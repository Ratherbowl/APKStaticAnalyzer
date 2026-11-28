import datetime
import json
import csv
import os
import subprocess
import requests
import traceback
from pathlib import Path
import re
from collections import Counter
import flow_droid_script as fd

PROJECT_DIR = Path(__file__).resolve().parent

APK_INPUT_DIR = PROJECT_DIR / "AccountDeletionAnalyzer_Ubuntu" / "apks"
ARTIFACTS_DIR = PROJECT_DIR / "results"
ADF_DIR = PROJECT_DIR / "AccountDeletionAnalyzer_Ubuntu"
FLOWDROID_JAR = PROJECT_DIR / "tools" / "flowdroid" / "soot-infoflow-cmd-2.13.0-jar-with-dependencies.jar"
ANDROID_JARS = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/AppData/Local/Android/Sdk/platforms")

MOBSF_URL = "http://localhost:8000"
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY")
HEADERS = {"Authorization": MOBSF_API_KEY}

def get_all_apks():
    """Returns a list of all .apk files in the APK_INPUT_DIR."""
    return list(APK_INPUT_DIR.glob("*.apk"))

def _extractDotEvidence(dot_file: Path | None) -> list[str]:
    """Helper to extract unique node values from an ADF mapping_model_*.dot file."""
    evidence_items = []
    seen = set()
    if not dot_file or not dot_file.exists(): #switched to check if nonexistent first
            return []
    dot_content = dot_file.read_text(encoding="utf-8", errors="replace")

    # Matches only quoted "prefix::value" nodes;
    pattern = re.compile(r'"(adstr|nattr|lay|frag|act|img)::((?:\\.|[^"\\])*)"')

    for prefix, value in pattern.findall(dot_content):
        clean_val = (
            value.replace(r'\"', '"')
                    .replace(r'\/', '/')
                    .replace(r'\&', '&')
                    .replace(r'\\', '\\') 
                    .strip()
        )

        #Sets have O(1) Lookup time vs. List O(n)
        if clean_val and clean_val not in seen:
            evidence_items.append(clean_val)
            seen.add(clean_val)

    return evidence_items

def adfScan(app_id: str, apk_file: Path) -> dict[str, Path | None]:
    """Runs adf_delete.sh and adf_health.sh and copies the resulting .dot files to output_dir."""
    print(f"[*] Running ADF (deletion & health) for {app_id}...")
    scripts = {
        "deletion": (ADF_DIR / "adf_delete.sh", "mapping_model_deletion.dot"),
        "health": (ADF_DIR / "adf_health.sh", "mapping_model_health.dot"),
    }

    results = {"deletion": None, "health": None}
    target_apk = apk_file.resolve() #got rid of the Path cast since already Path
    apk_stem = target_apk.stem

    for key, (script_path, dot_filename) in scripts.items():
        if not script_path.exists():
            print(f"[!] ADF script {script_path} not found.")
            continue

        expected_dot = ADF_DIR / "output" / apk_stem / dot_filename
        expected_dot.unlink(missing_ok=True)

        print(f"  -> Executing {script_path.name}...")
        try:
            res = subprocess.run(
                ["bash", str(script_path), str(target_apk)],
                cwd=str(ADF_DIR),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=900
            )

            if expected_dot.exists():
                results[key] = expected_dot
                print(f"[*] Success! Found {dot_filename} at {expected_dot}")
            else:
                print(f"[!] {script_path.name} did not produce {expected_dot.name} (exit={res.returncode})")
                if res.stderr.strip():
                    print(f"    STDERR: {res.stderr.strip()[-500:]}")
        except subprocess.TimeoutExpired:
            print(f"[!] {script_path.name} timed out for {app_id}.")
        except Exception as e:
            print(f"[!] {script_path.name} execution failed for {app_id}: {e}")
            traceback.print_exc()

    return results

def adfParse(deletion_dot: Path | None, health_dot: Path | None = None) -> dict:
    """Parses both the deletion and health ADF .dot reports."""
    del_evidence = _extractDotEvidence(deletion_dot)
    health_evidence = _extractDotEvidence(health_dot)

    return {
        "delete_account_class_found": "Yes" if del_evidence else "No",
        "delete_account_string_evidence": ", ".join(del_evidence) if del_evidence else "None",
        "adf_health_detected": "Yes" if health_evidence else "No",
    }
    
def _parseExportedComponents(manifest_findings: list) -> dict:
    """Parses exported components findings from MobSF report."""
    # Loop through each finding and categorize exported components based on protection status
    for finding in manifest_findings:
        rule = finding.get("rule", "")
        title = str(finding.get("title", "")).lower()
        desc = str(finding.get("description", "")).lower()

        # Check for unprotected exported components based on rule and description
        if rule in ("explicitly_exported", "exported_intent_filter_exists"):
            if "not protected" in title or "not protected" in desc or "shared with other apps" in desc:
                return {"exported_components_unprotected": "Yes"}
            
    return {"exported_components_unprotected": "No"}

def _parseEncryption(code_findings: dict, sbom_versioned: list) -> dict:
    """Parses encryption findings from MobSF report."""
    enc_indicators = [
        "android_db_encryption", "android_sql_cipher", "android_sql_cipher_aes256", 
        "androidx.security.crypto", "androidx.datastore", "android.security.keystore", 
        "java.security", "javax.crypto", "javax.crypto.spec"
    ]
    search_corpus = [f.lower() for f in (list(code_findings.keys()) + sbom_versioned)]
   
    encryption_detected = "Yes" if any(indicator in item for item in search_corpus for indicator in enc_indicators) else "No"
    return {"encryption_at_rest": encryption_detected}

def _parseStorage(code_findings: dict) -> dict:
    """Parses storage findings from MobSF report."""
    insecure_storage_rules = [
        "android_hiddenui", "android_aes_ecb", "android_aws_ecb_default",
        "android_rsa_no_oaep", "android_world_writable", "android_world_readable",
        "android_world_read_write", "android_weak_ciphers", "cbc_padding_oracle",
        "android_sql_raw_query", "android_read_write_external",
    ]
    
    insecure_storage = "Yes" if any(rule in code_findings for rule in insecure_storage_rules) else "No"
    
    return {"insecure_data_storage_detected": insecure_storage}

def _parseCertificatePinning(code_findings: dict, net_findings: list) -> dict:
    """Parses certificate pinning findings from MobSF report."""
        # Check for the explicit MobSF rule OR any pinning in the network config
    if "android_ssl_pinning" in code_findings:
        return {"cert_pinning_detected": "Yes"}

    # Check for pinning in network security config findings
    for finding in net_findings:
        title = str(finding.get("title", "").lower())
        desc = str(finding.get("description", "").lower())
        severity = str(finding.get("severity", "")).lower()

        # Check if the finding is related to pinning and not a vulnerability (e.g., secure or info severity without "missing" in description)
        is_pin_config = "pin-set" in desc or "pin-set" in title or "pinning" in title
        is_not_vulnerability = severity in ("secure", "info") and "missing" not in desc

        if is_pin_config and is_not_vulnerability:
            return {"cert_pinning_detected": "Yes"}
    
    return {"cert_pinning_detected": "No"}

def _parseWebviewRisks(code_findings: dict) -> dict:
        # Check for any findings related to insecure WebView configurations

    insecure_webview = "Yes" if any(key.startswith("android_webview") for key in code_findings) else "No"
    return {"webview_insecure_config_detected": insecure_webview}

def _parseHealthFindings(permissions: dict, sbom_packages: list) -> dict:
    """Parses health findings from MobSF report."""
    health_permissions = {
        "android.permission.BODY_SENSORS", 
        "android.permission.BODY_SENSORS_BACKGROUND", 
        "android.permission.REQUEST_COMPANION_PROFILE_MEDICAL", 
        "android.permission.FOREGROUND_SERVICE_HEALTH"
    }

    health_packages = {
        "android.health.connect", "android.health.connect.changelog", 
        "android.health.connect.datatypes", "android.health.connect.datatypes.units", 
        "androidx.health.connect.client", "androidx.health.connect.client.aggregate", 
        "androidx.health.connect.client.changes", "androidx.health.connect.client.records",
        "androidx.health.connect.client.request", "androidx.health.connect.client.response",
        "androidx.health.connect.client.time", "androidx.health.connect.client.units",
        "androidx.health.services.client", "androidx.health.services.client.data",
        "com.google.android.gms.fitness", "com.google.android.gms.fitness.data",
        "com.google.android.gms.fitness.request", "com.google.android.gms.fitness.result",
        "com.google.android.gms.fitness.service"
    }

    if any(perm in permissions for perm in health_permissions):
        return {"health_related_findings": "Yes"}

    search_corpus = [f.lower() for f in sbom_packages]
    for item in search_corpus:
        if any(pkg in item for pkg in health_packages):
            return {"health_related_findings": "Yes"}

    return {"health_related_findings": "No"}

def mobsfParse(report_data: dict):
    """Parses MobSF JSON report and saves relevant findings to CSV."""
    if not report_data or "error" in report_data:
        return {"mobsf_status": "API Error"}

    # Centralized Data Extraction
    permissions = report_data.get("permissions", {})
    sbom = report_data.get("sbom", {})
    sbom_versioned = [str(x) for x in sbom.get("sbom_versioned", [])]
    sbom_packages = list(sbom.get("sbom_packages", [])) + sbom_versioned
    
    code_findings = report_data.get("code_analysis", {}).get("findings", {})
    net_findings = report_data.get("network_security", {}).get("network_findings", [])
    manifest_findings = report_data.get("manifest_analysis", {}).get("manifest_findings", [])
    libraries = report_data.get("libraries", [])
    secrets = report_data.get("secrets", [])

    dangerous_perms = [
        perm for perm, details in permissions.items()
        if details.get("status") == "dangerous"
    ]
    unique_sdks = set(sbom_versioned + libraries)
    cleartext_allowed = "Yes" if any(
        f.get("rule") == "clear_text_traffic" for f in manifest_findings
    ) else "No"

    # Call modular helper functions with pre-extracted data dictionaries
    exported_data = _parseExportedComponents(manifest_findings)
    encryption_data = _parseEncryption(code_findings, sbom_versioned)
    storage_data = _parseStorage(code_findings)
    pinning_data = _parseCertificatePinning(code_findings, net_findings)
    webview_data = _parseWebviewRisks(code_findings)
    health_data = _parseHealthFindings(permissions, sbom_packages)

    results = {
        "num_dangerous_permissions": len(dangerous_perms),
        "dangerous_permissions_list": ", ".join(dangerous_perms),
        "num_3rd_party_sdks": len(unique_sdks),
        "sdk_list": ", ".join(unique_sdks),
        "num_hardcoded_secrets": len(secrets),
        "cleartext_traffic_allowed": cleartext_allowed,
        "exported_components_unprotected": exported_data.get("exported_components_unprotected", "No"),
        "insecure_data_storage_detected": storage_data.get("insecure_data_storage_detected", "No"),
        "encryption_at_rest": encryption_data.get("encryption_at_rest", "No"),
        "webview_insecure_config_detected": webview_data.get("webview_insecure_config_detected", "No"),
        "health_related_findings": health_data.get("health_related_findings", "No"),
        "cert_pinning": pinning_data.get("cert_pinning_detected", "No"),
        "mobsf_status": "Success"
    }

    return results

def mobsfScan(app_id:str, apk_file: Path, output_dir: Path):
    """Uploads, scans, and retrieves JSON report from MobSF REST API."""
    print(f"[*] Submitting {apk_file.name} to MobSF Docker...")
    try:
        with open (apk_file, "rb") as f:
            files = {"file": (f"{app_id}.apk", f, "application/vnd.android.package-archive")}
            upload_res = requests.post(f"{MOBSF_URL}/api/v1/upload", headers=HEADERS, files=files, timeout=300)

        if upload_res.status_code != 200:
            print(f"[!] MobSF upload failed: {upload_res.text}")
            return None

        upload_data = upload_res.json()

        #Added a small bit of error checking
        if not upload_data.get("hash"):
            print(f"[!] MobSF upload response missing hash: {upload_data}")
            return None
        if not upload_data.get("file_name"):
            print(f"[!] MobSF upload response missing file_name: {upload_data}")
            return None

        scan_payload = {"scan_type": "apk", "file_name": upload_data.get("file_name"), "hash": upload_data.get("hash")}
        
        # 2. Trigger the scan. MobSF returns the FULL JSON report right here when it finishes.
        scan_res = requests.post(f"{MOBSF_URL}/api/v1/scan", headers=HEADERS, data=scan_payload, timeout=600)
        
        if scan_res.status_code != 200:
            print(f"[!] MobSF Scan Endpoint Failed (HTTP {scan_res.status_code}): {scan_res.text}")
            return None

        # 3. Grab the report directly from the scan response
        report_data = scan_res.json()

        # 4. Catch soft errors (where MobSF returns HTTP 200 but hands back an error JSON)
        if "error" in report_data:
            print(f"[!] MobSF API Error: {report_data['error']} | Payload sent: {scan_payload}")
            return report_data

        # 5. Save to file
        static_scan_dir = output_dir / "static_scan"
        static_scan_dir.mkdir(parents=True, exist_ok=True)
        report_file = static_scan_dir / "mobsf_report.json"
        
        with open(report_file, "w", encoding="utf-8") as out:
            json.dump(report_data, out, indent=4)

        print(f"[*] Success! Report saved to {report_file}")
        return report_data
    except Exception as e:
        print(f"[!] MobSF scan failed: {e}")
        traceback.print_exc()
        return None

CSV_HEADERS = [
    "app_id",
    "tool_used",
    "scan_date",
    "num_dangerous_permissions",
    "dangerous_permissions_list",
    "hardcoded_secret_found",
    "num_hardcoded_secrets",
    "num_3rd_party_sdks",
    "sdk_list",
    "cert_pinning_present",
    "encryption_at_rest_detected",
    "delete_account_class_found",
    "delete_account_string_evidence",
    "sensitive_dataflow_count",
    "sensitive_dataflow_examples",
    "raw_tool_output_path",
    "compliance_findings_mapped",
    "run_by",
    "notes",
    "cleartext_traffic_allowed",
    "insecure_data_storage_detected",
    "exported_components_unprotected",
    "webview_insecure_config_detected",
    "health_related_permission_or_sdk_detected",
    "mobsf_status",
    "adf_status",
    "flowdroid_status",
]

def _summarizeLeaks(leaks: list[dict], max_examples: int = 10) -> str:
    """Condense FlowDroid leak dicts into a concise CSV string like ''LOCATION -> NETWORK (3x)'."""
    if not leaks:
        return "None"

    pair_counts = Counter(
        (leak.get("source_category", "UNCATEGORIZED"), leak.get("sink_category", "UNCATEGORIZED"))
        for leak in leaks)

    top_pairs = pair_counts.most_common(max_examples)
    summary = "; ".join(f"{src} -> {snk} ({cnt}x)" for (src, snk), cnt in top_pairs)

    remaining = len(pair_counts) - len(top_pairs)

    if remaining > 0:
        summary += f"; (+{remaining} more category pairs)"

    return summary

def _isRowComplete(row: dict) -> bool:
    """Returns True only if MobSF, ADF, and FlowDroid all finished cleanly for this app."""
    return (
        row.get("mobsf_status") == "Success"
        and row.get("adf_status") == "Success"
        and str(row.get("flowdroid_status", "")).startswith("ok")
    )

def _prepareMasterCsv(csv_path: Path, fieldnames: list[str]) -> set[str]:
    """
    Loads an existing master CSV, keeps only cleanly completed apps (rewriting
    atomically so failed apps are removed before being re-run), and returns the
    set of completed app_ids to skip.
    """

    if not csv_path.exists() or csv_path.stat().st_size == 0:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=fieldnames).writeheader()
        return set()

    good_rows: dict[str, dict] = {}
    requeue_count = 0

    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            app_id = row.get("app_id", "").strip()
            if not app_id:
                continue
            if _isRowComplete(row):
                good_rows[app_id] = row
            else:
                requeue_count += 1

    tmp_path = csv_path.with_suffix(".tmp")
    with open(tmp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(good_rows.values())
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, csv_path)

    print(f"[*] Resume check: {len(good_rows)} complete (skipping), {requeue_count} failed (re-running).")
    return set(good_rows.keys())

def main(flowdroid_timeout: int = 1800, retry_fast: bool = True, run_by: str = "") -> None:
    """Orchestrates MobSF, ADF (deletion + health), and FlowDroid into one master CSV."""
    # Sync FlowDroid module paths with this script's constants and validate
    fd.FLOWDROID_JAR = FLOWDROID_JAR
    fd.ANDROID_PLATFORMS = ANDROID_JARS
    fd.check_setup()

    ## Ensure base output and FlowDroid subdirectories exist (fd.run_one expects xml/ and logs/)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    flowdroid_dir = ARTIFACTS_DIR / "flowdroid"
    (flowdroid_dir / "xml").mkdir(parents=True, exist_ok=True)
    (flowdroid_dir / "logs").mkdir(parents=True, exist_ok=True)

    # Discover APKs and filter out already succeeded apps
    all_apks = sorted(get_all_apks(), key=lambda p: p.stem.lower())
    if not all_apks:
        print(f"[!] No APKs found in {APK_INPUT_DIR}")
        return

    master_csv = ARTIFACTS_DIR / "static_findings.csv"

    completed_ids = _prepareMasterCsv(master_csv, CSV_HEADERS)
    pending_apks = [apk for apk in all_apks if apk.stem not in completed_ids]

    print(f"[*] Total APKs: {len(all_apks)} | Remaining to run: {len(pending_apks)}")
    if not pending_apks:
        print(f"[*] All APKs already completed cleanly. Master CSV: {master_csv}")
        return

    # run pipleline app by app, appending and flushing after each
    failed_apps = []
    with open(master_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, extrasaction="ignore")
        for idx, apk_path in enumerate(pending_apks, start=1):
            app_id = apk_path.stem
            app_out_dir = ARTIFACTS_DIR / app_id
            app_out_dir.mkdir(parents=True, exist_ok=True)

            print(f"\n{'=' * 60}\n[{idx}/{len(pending_apks)}] Processing: {apk_path.name} ({app_id})\n{'=' * 60}")

            # Baseline row so a single tool failure doesn't prevent recording other results
            row = {col: "Error" for col in CSV_HEADERS}
            row.update({
                "app_id": app_id,
                "tool_used": "MobSF + ADF + FlowDroid",
                "scan_date": datetime.date.today().isoformat(),
                "raw_tool_output_path": str(app_out_dir),
                "run_by": run_by,
                "notes": "",
                })

            notes_parts = []

            # MobSF Scan and Parse
            mobsf_health = "No"
            raw_mobsf = mobsfScan(app_id, apk_path, app_out_dir)
            if raw_mobsf and "error" not in raw_mobsf:
                mobsf_data = mobsfParse(raw_mobsf)
                num_secrets = mobsf_data.get("num_hardcoded_secrets", 0)
                mobsf_health = mobsf_data.get("health_related_findings", "No")

                row.update({
                    "num_dangerous_permissions": mobsf_data.get("num_dangerous_permissions", 0),
                    "dangerous_permissions_list": mobsf_data.get("dangerous_permissions_list") or "None",
                    "hardcoded_secret_found": "Yes" if num_secrets > 0 else "No",
                    "num_hardcoded_secrets": num_secrets,
                    "num_3rd_party_sdks": mobsf_data.get("num_3rd_party_sdks", 0),
                    "sdk_list": mobsf_data.get("sdk_list") or "None",
                    "cert_pinning_present": mobsf_data.get("cert_pinning", "No"),
                    "encryption_at_rest_detected": mobsf_data.get("encryption_at_rest", "No"),
                    "cleartext_traffic_allowed": mobsf_data.get("cleartext_traffic_allowed", "No"),
                    "insecure_data_storage_detected": mobsf_data.get("insecure_data_storage_detected", "No"),
                    "exported_components_unprotected": mobsf_data.get("exported_components_unprotected", "No"),
                    "webview_insecure_config_detected": mobsf_data.get("webview_insecure_config_detected", "No"),
                    "mobsf_status": mobsf_data.get("mobsf_status", "Success"),
                })
            else:
                row["mobsf_status"] = "API Error"
                notes_parts.append("MobSF scan failed or returned error.")

            # ADF Scan and Parse
            adf_dots = adfScan(app_id, apk_path)
            del_dot = adf_dots.get("deletion")
            health_dot = adf_dots.get("health")
            adf_data = adfParse(del_dot, health_dot)

            row["delete_account_class_found"] = adf_data["delete_account_class_found"]
            row["delete_account_string_evidence"] = adf_data["delete_account_string_evidence"]

            if del_dot and health_dot:
                row["adf_status"] = "Success"
            elif del_dot or health_dot:
                row["adf_status"] = "Partial Success"
                notes_parts.append("One ADF script did not produce a .dot file")
            else:
                row["adf_status"] = "Error"
                notes_parts.append("Both ADF scripts failed to produce .dot files")

            # Merge Health Findings from MobSF and ADF
            adf_health = adf_data.get("adf_health_detected", "No")
            row["health_related_permission_or_sdk_detected"] = ("Yes" if mobsf_health == "Yes" or adf_health == "Yes" else "No")

            # FlowDroid Scan and Parse
            print(f"[*] Running FlowDroid for {app_id}...")
            try:
                fd_res = fd.run_one(apk_path, flowdroid_dir, flowdroid_timeout, retry_fast)
                row["sensitive_dataflow_count"] = fd_res["leaks_found"]
                row["sensitive_dataflow_examples"] = _summarizeLeaks(fd_res["leaks"])
                row["flowdroid_status"] = fd_res["status"]
                if fd_res.get("notes"):
                    notes_parts.append(fd_res["notes"])
            except Exception as exc:
                row["sensitive_dataflow_count"] = "Error"
                row["sensitive_dataflow_examples"] = "Error"
                row["flowdroid_status"] = f"Error: {exc}"
                notes_parts.append(f"FlowDroid failed: {exc}")
                traceback.print_exc()

            row["notes"] = " | ".join(notes_parts)

            # Write and Flush Immediately
            writer.writerow(row)
            f.flush()
            os.fsync(f.fileno())

            if not _isRowComplete(row):
                failed_apps.append(app_id)

            print(
                f"[*] Saved {app_id} | MobSF: {row['mobsf_status']} | "
                f"ADF: {row['adf_status']} | FlowDroid: {row['flowdroid_status']}"
            )
        print(f"\n{'=' * 60}")
    print(f"[*] Batch run complete. Master CSV: {master_csv}")
    if failed_apps:
        print(f"[!] {len(failed_apps)} app(s) had errors and will be retried on next run: {', '.join(failed_apps)}")

if __name__ == "__main__":
    main()