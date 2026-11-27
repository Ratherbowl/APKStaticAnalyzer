#!/usr/bin/env python3
"""
Batch run FlowDroid against every APK in a directory (takes a while).

Outputs (in the -o folder):
  summary.csv   one row per APK: status, leak count, runtime, notes
  leaks.csv     one row per source -> sink leak, with data categories
  leaks_by_category.csv leak counts per app and category pair (compare to privacy policies)
  progress.csv    written as each APK finishes; used by --resume
  xml/, logs/   FlowDroid's raw report and full log per APK

Notes:
  - Runs FlowDroid through tools/flowdroid-multidex.jar so it reads every
    classes*.dex file, not just the first one.
  - Using FlowDroid 2.13, some apps error inside FlowDroid itself (see their logs).
  - FlowDroid can exit "successfully" after failing, so status comes from the log.
  - 0 leaks means no flow FlowDroid could prove, not that no data is collected.

Usage:
  python3 flow_droid_script.py apk_files -o results
  python3 flow_droid_script.py apk_files -o results -j 2 --timeout 3600 --resume

Standard library only. Needs Java on your PATH.
"""

from __future__ import annotations  # type hints on older Python 3 versions

import argparse
import csv
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# ---- configuration ----

PROJECT_DIR = Path(__file__).resolve().parent

FLOWDROID_JAR = PROJECT_DIR / "tools/flowdroid/soot-infoflow-cmd-2.13.0-jar-with-dependencies.jar"

# Multi-dex + lenient resource parsing. Without it most apps report
# "No sources found" or crash with "res1 is not zero".
WRAPPER_JAR = PROJECT_DIR / "tools/flowdroid/flowdroid-multidex.jar"
WRAPPER_MAIN = "FlowDroidMultiDex"  # its main class; launched via -cp, not -jar, so the wrapper runs first

# Android SDK "platforms" folder (path differs per operating system).
ANDROID_PLATFORMS = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/AppData/Local/Android/Sdk/platforms")

# Project sources/sinks list; its "% @category" headers label leaks in leaks.csv.
# FlowDroid's original default list: ~/tools/flowdroid/SourcesAndSinks.txt
SOURCES_SINKS = PROJECT_DIR / "aviation_sources_sinks.txt"

# Library summaries so taint flows through e.g. StringBuilder. None to skip.
TAINT_WRAPPER = PROJECT_DIR / "tools/flowdroid/EasyTaintWrapperSource.txt"

# Heap per run. (heap size) x (parallel jobs) must fit in RAM.
JAVA_HEAP = "8g"  # big apps need 4-8g; less tends to end in OutOfMemoryError


#running flowdroid

def build_command(apk: Path, out_xml: Path, fast_callgraph: bool, timeout: int) -> list[str]:
    """Build the java command line for one APK."""
    # FlowDroid's own phase limits (seconds). When one runs out FlowDroid keeps
    # what it has, so slow apps return partial results instead of being killed.
    callback_limit = max(60, int(timeout * 0.35))  # callback search is where big apps stall (ATC)
    dataflow_limit = max(60, int(timeout * 0.40))  # biggest share: the taint analysis itself
    result_limit = max(30, int(timeout * 0.10))  # ~15% left over for loading the APK before the hard kill
    classpath = os.pathsep.join([str(FLOWDROID_JAR), str(WRAPPER_JAR)])  # ":" on Mac/Linux, ";" on Windows
    cmd = [
        "java", f"-Xmx{JAVA_HEAP}", "-cp", classpath, WRAPPER_MAIN,
        "-a", str(apk),
        "-p", str(ANDROID_PLATFORMS),
        "-s", str(SOURCES_SINKS),
        "-o", str(out_xml),
        "-ct", str(callback_limit),
        "-dt", str(dataflow_limit),
        "-rt", str(result_limit),
    ]
    if TAINT_WRAPPER and Path(TAINT_WRAPPER).is_file():  # optional: run without it rather than fail
        cmd += ["-t", str(TAINT_WRAPPER)]
    if fast_callgraph:
        cmd += ["-cg", "CHA"]  # faster, less precise call graph (more false positives)
    return cmd


def run_one(apk: Path, out_dir: Path, timeout: int, retry_fast: bool) -> dict:
    """Analyze one APK (runs in a worker process). Returns its summary row plus leaks."""
    name = apk.stem
    out_xml = out_dir / "xml" / f"{name}.xml"
    log_file = out_dir / "logs" / f"{name}.log"  # named after the APK so reruns overwrite, not pile up

    # Precise call graph first; with --retry-fast, a timeout gets one CHA retry.
    attempts = [False, True] if retry_fast else [False]

    # Fresh log/XML so leftovers from older runs don't skew the checks.
    log_file.write_text("", encoding="utf-8")

    #Safer file deletion
    out_xml.unlink(missing_ok=True)

    status = "error"
    used_fast = False
    start = time.time()
    for fast in attempts:
        used_fast = fast
        cmd = build_command(apk, out_xml, fast, timeout)
        with open(log_file, "a", encoding="utf-8") as log:  # append: a CHA retry lands in the same log
            log.write(f"\n=== Command: {' '.join(cmd)}\n")
            log.flush()  # so the command line appears before Java's output
            try:
                proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT,  # one log, errors kept in order
                                      timeout=timeout)  # hard backstop if FlowDroid ignores its own limits
                status = "ok" if proc.returncode == 0 else f"error({proc.returncode})"
            except subprocess.TimeoutExpired:
                status = "timeout"
                log.write(f"\n=== Timed out after {timeout}s\n")
        if status != "timeout":
            break  # a crash would just crash again with CHA; only timeouts are retried

    # Exit code 0 isn't proof of success - confirm from log.
    notes = ""
    if status == "ok":
        status, notes = check_log(log_file)
    if status == "ok" and used_fast:
        status = "ok(CHA)"  # less precise result

    leaks = parse_leaks(out_xml, name) if out_xml.is_file() else []  # FlowDroid writes no XML when there are 0 leaks
    return {
        "apk": name,
        "status": status,
        "leaks_found": len(leaks),
        "seconds": round(time.time() - start),
        "notes": notes,
        "leaks": leaks,
    }




def check_log(log_file: Path) -> tuple[str, str]:
    """Return (status, notes) for a run that exited normally. "ok" requires a "Found N leaks" line."""
    text = log_file.read_text(encoding="utf-8", errors="ignore")
    notes = []

    #helper function to make the return statement cleaner
    def results_message(status: str, message: str = ""):
        return status, "; ".join(notes + [message])

    m = re.search(r"Source lookup done, found (\d+) sources and (\d+) sinks", text)
    if m:
        notes.append(f"{m.group(1)} sources, {m.group(2)} sinks in code")

    if "Multiple dex files detected, only processing" in text:
        notes.append("only classes.dex analyzed - check WRAPPER_JAR")
    if "OutOfMemoryError" in text:  # checked before "failed": an OOM also logs a failure message
        return results_message("out_of_memory", "raise JAVA_HEAP or lower -j")
    if "The data flow analysis has failed" in text:
        m = re.search(r"The data flow analysis has failed\. Error message: (.*)", text)
        #this one might throw an error, so keeping OG
        #return "error", "; ".join(notes + [m.group(1).strip()[:150] if m else "analysis failed"])
        return results_message("error", m.group(1).strip()[:150] if m else "analysis failed")  # trimmed for the CSV
    if "No sources found, aborting analysis" in text:
        return results_message("ok", "no sources reachable")# app never calls a listed source
    if not re.search(r"Found \d+ leaks", text):
        return results_message("incomplete", "no 'Found N leaks' line in log")
    return results_message("ok")


# ---- parsing results ----

def parse_leaks(xml_path: Path, apk_name: str) -> list[dict]:
    """
    One row per (source, sink) pair from a FlowDroid results XML:
      <Result> <Sink Statement=.. Method=../> <Sources><Source .../>...</Sources> </Result>
    """
    rows = []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return rows  #empty/truncated file (run killed or errored)

    for result in root.iter("Result"):
        sink = result.find("Sink")
        if sink is None:
            continue
        sink_stmt = sink.get("Statement", "")
        for source in result.iter("Source"):
            source_stmt = source.get("Statement", "")
            rows.append({
                "apk": apk_name,
                "source_category": category_of(source_stmt, "SOURCE"),
                "sink_category": category_of(sink_stmt, "SINK"),
                "source_api": called_api(source_stmt),
                "sink_api": called_api(sink_stmt),
                "source_method": source.get("Method", ""), # app method making the call
                "source_statement": source_stmt,
                "sink_method": sink.get("Method", ""),
                "sink_statement": sink_stmt,
            })
    return rows


_CATEGORIES: dict[str, str] | None = None  # cache: read the rules file once per worker, not once per leak
_SIG_RE = re.compile(r"<[^<>]+: [^<>]+ [^<>]+\([^<>]*\)>")  # Soot signature: <class: ret name(params)>

def load_categories() -> dict[str, str]:
    """Map "SOURCE <sig>" / "SINK <sig>" to the "% @category" header it sits under in SOURCES_SINKS."""
    global _CATEGORIES
    if _CATEGORIES is None:
        _CATEGORIES = {}
        current = {"SOURCE": "", "SINK": ""}  #tracked separately - source and sink headers alternate in the file
        for line in Path(SOURCES_SINKS).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            m = re.match(r"%\s*@category\s+(SOURCE|SINK)\s*:\s*(\S+)", line)
            if m:
                current[m.group(1)] = m.group(2)
            elif line.startswith("<"):
                kind = "SOURCE" if "_SOURCE_" in line else "SINK"
                sig = line[: line.index(")>") + 2]  # drop the permission and "-> _SINK_" tag
                _CATEGORIES[f"{kind} {sig}"] = current[kind] or "UNCATEGORIZED"
    return _CATEGORIES


def called_api(statement: str) -> str:
    """The called method's signature from a Jimple statement."""
    m = _SIG_RE.search(statement)
    return m.group(0) if m else ""


def category_of(statement: str, kind: str) -> str:
    """Category of the API called in a statement, or UNCATEGORIZED."""
    cats = load_categories()
    sig = called_api(statement)
    if f"{kind} {sig}" in cats:
        return cats[f"{kind} {sig}"]
    # FlowDroid also matches subclasses (BufferedWriter.write hits the Writer.write
    # sink), so fall back to matching method name + parameters.
    sub = sig.split(": ", 1)[-1]
    for key, cat in cats.items():
        if key.startswith(kind + " ") and key.endswith(": " + sub):
            return cat
    return "UNCATEGORIZED"

# main

def check_setup() -> None:
    """Exit early with a message if a required path is wrong."""
    problems = []
    if not FLOWDROID_JAR.is_file():
        problems.append(f"FlowDroid jar not found: {FLOWDROID_JAR}")
    if not WRAPPER_JAR.is_file():
        problems.append(f"Multi-dex wrapper not found: {WRAPPER_JAR}")
    if not ANDROID_PLATFORMS.is_dir():
        problems.append(f"Android platforms folder not found: {ANDROID_PLATFORMS}")
    if not SOURCES_SINKS.is_file():
        problems.append(f"Sources/sinks file not found: {SOURCES_SINKS}")
    if problems:
        sys.exit("Setup problem(s):\n  " + "\n  ".join(problems))

def find_apks(args):
    pattern = "**/*" if args.recursive else "*"
    apks = sorted(p for p in args.apk_dir.glob(pattern) if p.is_file() and p.suffix.lower() == ".apk")  #lower(): some downloads end in .APK
    return apks
        
def main() -> None:
    parser = argparse.ArgumentParser(description="Batch-run FlowDroid over a folder of APKs.")
    parser.add_argument("apk_dir", type=Path, help="Folder containing .apk files")
    parser.add_argument("-o", "--out", type=Path, default=Path("flowdroid_results"),
                        help="Output folder (default: flowdroid_results)")
    parser.add_argument("-j", "--jobs", type=int, default=1,  #1 by default: each job takes JAVA_HEAP of RAM
                        help="APKs to analyze at once (watch RAM; default 1)")
    parser.add_argument("--timeout", type=int, default=1800,
                        help="Seconds allowed per APK attempt (default 1800 = 30 min)")
    parser.add_argument("--retry-fast", action="store_true",
                        help="If an APK times out, retry once with the faster CHA call graph")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Also look for APKs in subfolders")
    parser.add_argument("--resume", action="store_true",
                        help="Skip APKs that already finished OK in this output folder")
    args = parser.parse_args()

    check_setup()  # before creating any folders, so a bad path leaves nothing behind

    apks = find_apks(args)

    #Following 3 lines could be moved to find_apks()
    if not apks:
        sys.exit(f"No APKs found in {args.apk_dir}")
    print(f"Found {len(apks)} APK(s). Running {args.jobs} at a time.\n") #when parsing parallel

    (args.out / "xml").mkdir(parents=True, exist_ok=True)
    (args.out / "logs").mkdir(parents=True, exist_ok=True)

    # progress.csv keeps finished apps if the run is stopped (Ctrl C, laptop sleep, etc).
    progress_path = args.out / "progress.csv"
    progress_fields = ["apk", "status", "leaks_found", "seconds", "notes"]
    results = []
    if args.resume and progress_path.is_file():
        with open(progress_path, newline="", encoding="utf-8") as f:
            finished = {row["apk"]: row for row in csv.DictReader(f)
                        if row["status"].startswith("ok")}  # errors/timeouts get another try
        for apk in [a for a in apks if a.stem in finished]:
            row = finished[apk.stem]
            xml_path = args.out / "xml" / f"{apk.stem}.xml"
            leaks = parse_leaks(xml_path, apk.stem) if xml_path.is_file() else []
            results.append({**row, "leaks_found": len(leaks), "leaks": leaks})
        apks = [a for a in apks if a.stem not in finished]
        print(f"Resuming: {len(finished)} already done, {len(apks)} to go.\n")
    else:
        with open(progress_path, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=progress_fields).writeheader()

    #Workers just wait on java; the real cost is Java's RAM.
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:  # processes: a worker crash can't take down the rest
        futures = {
            pool.submit(run_one, apk, args.out, args.timeout, args.retry_fast): apk
            for apk in apks
        }
        for i, fut in enumerate(as_completed(futures), 1):  # report each app as it finishes, not in list order
            apk = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:  # crash in the worker itself
                res = {"apk": apk.stem, "status": f"crash: {exc}",
                       "leaks_found": 0, "seconds": 0, "notes": "", "leaks": []}
            results.append(res)
            with open(progress_path, "a", newline="", encoding="utf-8") as f:  # reopened per row so it's on disk if the run dies
                csv.DictWriter(f, fieldnames=progress_fields).writerow(
                    {k: res[k] for k in progress_fields})
            print(f"[{i}/{len(apks)}] {res['apk']}: {res['status']}, "
                  f"{res['leaks_found']} leak(s), {res['seconds']}s"
                  + (f"  ({res['notes']})" if res["notes"] else ""))

    results.sort(key=lambda r: r["apk"])  #sorted so CSVs compare cleanly between runs

    summary_path = args.out / "summary.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["apk", "status", "leaks_found", "seconds", "notes"])
        w.writeheader()
        for r in results:
            w.writerow({k: r[k] for k in w.fieldnames})

    leaks_path = args.out / "leaks.csv"
    with open(leaks_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["apk", "source_category", "sink_category",
                                          "source_api", "sink_api",
                                          "source_method", "source_statement",
                                          "sink_method", "sink_statement"])
        w.writeheader()
        for r in results:
            w.writerows(r["leaks"])

    #"AppX, LOCATION_PRECISE, THIRD_PARTY_ANALYTICS, 3"
    counts: dict[tuple[str, str, str], int] = {}
    for r in results:
        for leak in r["leaks"]:
            key = (leak["apk"], leak["source_category"], leak["sink_category"])
            counts[key] = counts.get(key, 0) + 1
    by_cat_path = args.out / "leaks_by_category.csv"
    with open(by_cat_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["apk", "source_category", "sink_category", "leaks"])
        for (apk_name, src, snk), n in sorted(counts.items()):
            w.writerow([apk_name, src, snk, n])

    total = sum(r["leaks_found"] for r in results)
    failed = [r["apk"] for r in results if not r["status"].startswith("ok")]
    print(f"\nDone. {total} leak(s) across {len(results)} APK(s).")
    if failed:
        print(f"{len(failed)} APK(s) did not finish cleanly: {', '.join(failed)}")
        print(f"Check their logs in {args.out / 'logs'}")
    print(f"Summary: {summary_path}\nLeaks:   {leaks_path}\nBy category: {by_cat_path}")


if __name__ == "__main__":
    main()
