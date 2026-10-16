import os
import glob
import fnmatch
import json
import csv
import subprocess
import requests
import zipfile
import shutil
import datetime
import traceback
from pathlib import Path
from apk_info import APK

APK_INPUT_DIR = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/Downloads/Test APK/APKs/")
ARTIFACTS_DIR = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/Downloads/Test APK/Output/")
ADF_DIR = Path.home() / "AccountDeletionAnalyzer"
FLOWDROID_JAR = Path.home() / "FlowDroid" / "soot-infoflow-cmd-jar-with-dependencies.jar"
ANDROID_JARS = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/AppData/Local/Android/Sdk/platforms")

MOBSF_URL = "http://localhost:8000"
MOBSF_API_KEY = "81cd67c1a301e2fe23f4c1fc59e51bde06d1beb0ea52ceb7e5766c8170fd90b7"
HEADERS = {"Authorization": MOBSF_API_KEY}


def getApkFiles():
    search_patterns = ["*.apk", "*.xapk", "*.apkm"]
    exclude_patterns = ["config.*", "split_config.*"]
    all_apks = []
    app_ids = []
    for pattern in search_patterns:
        all_apks.extend(str(f) for f in APK_INPUT_DIR.rglob(pattern) if f.is_file())
    # Filter out excluded patterns
    filtered_files = []
    for f in all_apks:
        filename = Path(f).name

        # Check if the file is an .xapk or .apkm file, extract the .apk file from it, and add it to the filtered_files list
        if filename.endswith((".xapk", ".apkm")):
            apk = APK(f)
            try:
                with zipfile.ZipFile(f, "r") as zip_ref:
                    zip_ref.extractall(ARTIFACTS_DIR / Path(f).stem)
                    filename = Path(f).stem
                    app_ids.append(str(Path(f).parent.name))
                    filtered_files.append(
                        str(ARTIFACTS_DIR / filename / (apk.get_package_name() + ".apk"))
                    )
            except zipfile.BadZipFile:
                print(f"Error: {f} is not a valid zip file.")
        else:
            if not any(fnmatch.fnmatch(filename, pattern) for pattern in exclude_patterns):
                app_ids.append(str(Path(f).parent.name))
                filtered_files.append(str(f))

    return filtered_files, app_ids

def mobsfScan(app_id:str, apk_file: Path, output_dir: Path):
    """Uploads, scans, and retrieves JSON report from MobSF REST API."""
    print(f"[*] Submitting {Path(apk_file).name} to MobSF Docker...")
    try:
        with open (apk_file, "rb") as f:
            files = {"file": (f"{app_id}.apk", f, "application/vnd.android.package-archive")}
            upload_res = requests.post(f"{MOBSF_URL}/api/v1/upload", headers=HEADERS, files=files, timeout=300)

        if upload_res.status_code != 200:
            print(f"[!] MobSF upload failed: {upload_res.text}")
            return None

        upload_data = upload_res.json()
        scan_hash = upload_data.get("hash")
        file_name = upload_data.get("file_name")

        scan_payload = {"scan_type": "apk", "file_name": upload_data.get("file_name"), "hash": scan_hash}
        
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


        
