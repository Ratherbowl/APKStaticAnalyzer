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
import re

APK_INPUT_DIR = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/Downloads/Test APK/APKs/")
ARTIFACTS_DIR = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/Downloads/Test APK/Output/")
ADF_DIR = Path.home() / "AccountDeletionAnalyzer"
FLOWDROID_JAR = Path.home() / "FlowDroid" / "soot-infoflow-cmd-jar-with-dependencies.jar"
ANDROID_JARS = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/AppData/Local/Android/Sdk/platforms")

MOBSF_URL = "http://localhost:8000"
MOBSF_API_KEY = "81cd67c1a301e2fe23f4c1fc59e51bde06d1beb0ea52ceb7e5766c8170fd90b7"
HEADERS = {"Authorization": MOBSF_API_KEY}

def getApkFiles():
    '''Performs a recursive search for APK files in the APK_INPUT_DIR, including .apk, .xapk, and .apkm files. Extracts .apk files from .xapk and .apkm archives and filters out excluded patterns. Returns a list of filtered APK file paths and their corresponding app IDs.'''
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
                # Extract the .apk file from the .xapk or .apkm archive, finds base file, and add it to the filtered_files list
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
            # If the file is a regular .apk file, check if it matches any exclude patterns
            if not any(fnmatch.fnmatch(filename, pattern) for pattern in exclude_patterns):
                app_ids.append(str(Path(f).parent.name))
                filtered_files.append(str(f))

    return filtered_files, app_ids

def adfParse(dot_file: Path | None) -> dict:
    """Parses the ADF report and returns a dictionary of relevant findings."""
    class_found = "No"
    evidence_items = []

    if dot_file and Path(dot_file).exists():
        dot_content = Path(dot_file).read_text(encoding="utf-8", errors="replace")

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

            if clean_val and clean_val not in evidence_items:
                evidence_items.append(clean_val)
    
    return {
        "delete_account_class_found": "Yes" if evidence_items else "No",
        "delete_account_string_evidence": ", ".join(evidence_items) if evidence_items else "None"
    }

            
    
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

        scan_payload = {"scan_type": "apk", "file_name": file_name, "hash": scan_hash}
        
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

def _parseExportedComponents(manifest_findings: list) -> dict:
    """Parses exported components findings from MobSF report."""
    # Loop through each finding and categorize exported components based on protection status
    for finding in manifest_findings:
        rule = finding.get("rule", "")
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()

        # Check for unprotected exported components based on rule and description
        if rule in ("explicitly_exported", "exported_intent_filter_exists"):
            if "not protected" in title or "not protected" in desc or "shared with other apps" in desc:
                return {"exported_components_unprotected": "Yes"}
            
    return {"exported_components_unprotected": "No"}

def _parseEncryptionAndStorage(report_data: dict) -> dict:
    '''Parses encryption and storage findings from MobSF report.'''
    enc_indicators = ["android_db_encryption", "android_sql_cipher",
                      "android_sql_cipher_aes256", "androidx.security.crypto",
                      "androidx.datastore", "android.security.keystore", "java.security", 
                      "javax.crypto", "javax.crypto.spec"]
    insecure_storage = [
    "android_hiddenui",
    "android_aes_ecb",
    "android_aws_ecb_default",
    "android_rsa_no_oaep",
    "android_world_writable",
    "android_world_readable",
    "android_world_read_write",
    "android_weak_ciphers",
    "cbc_padding_oracle",
    "android_sql_raw_query",
    "android_read_write_external",
    ]

    code_findings = report_data.get("code_analysis", {}).get("findings", {})
    sbom = report_data.get("sbom", {})

    sbom_versioned = [str(x) for x in sbom.get("sbom_versioned", [])]

    search_corpus = [f.lower() for f in (list(code_findings.keys()) + sbom_versioned)]

    encryption_detected = "No"

    for item in search_corpus:
            if any(indicator in item for indicator in enc_indicators):
                encryption_detected = "Yes"
                break

    insecure_storage = "Yes" if any(rule in code_findings for rule in insecure_storage) else "No"
    
    return {"encryption_at_rest": encryption_detected, "insecure_data_storage_detected": insecure_storage}

def _parseCertificatePinning(report_data: dict) -> dict:
    '''Parses certificate pinning findings from MobSF report.'''
    code_findings = report_data.get("code_analysis", {}).get("findings", {})
    net_findings = report_data.get("network_security", {}).get("network_findings", [])

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

def _parseWebviewRisks(report_data: dict) -> dict:
    code_findings = report_data.get("code_analysis", {}).get("findings", {})
    
    # Check for any findings related to insecure WebView configurations
    insecure_webview = "Yes" if any(key.startswith("android_webview") for key in code_findings) else "No"
    
    return {"webview_insecure_config_detected": insecure_webview}

def _parseHealthFindings(report_data: dict) -> dict:
    '''Parses health findings from MobSF report.'''
    health_permissions = {
        "android.permission.BODY_SENSORS", 
        "android.permission.BODY_SENSORS_BACKGROUND", 
        "android.permission.REQUEST_COMPANION_PROFILE_MEDICAL", 
        "android.permission.FOREGROUND_SERVICE_HEALTH", 
        "android.permission.ACTIVITY_RECOGNITION"
    }

    health_packages = {
        "android.health.connect", 
        "android.health.connect.changelog", 
        "android.health.connect.datatypes", 
        "android.health.connect.datatypes.units", 
        "androidx.health.connect.client",
        "androidx.health.connect.client.aggregate", 
        "androidx.health.connect.client.changes",
        "androidx.health.connect.client.records",
        "androidx.health.connect.client.request",
        "androidx.health.connect.client.response",
        "androidx.health.connect.client.time",
        "androidx.health.connect.client.units",
        "androidx.health.services.client",
        "androidx.health.services.client.data",
        "com.google.android.gms.fitness",
        "com.google.android.gms.fitness.data",
        "com.google.android.gms.fitness.request",
        "com.google.android.gms.fitness.result",
        "com.google.android.gms.fitness.service"
    }

    permissions = set(report_data.get("permissions", {}).keys())
    sbom = report_data.get("sbom", {})
    sbom_packages = sbom.get("sbom_packages", []) + [str(x) for x in sbom.get("sbom_versioned", [])]
    search_corpus = [f.lower() for f in sbom_packages]

    health_detected = "No"

    if any(perm in permissions for perm in health_permissions):
        health_detected = "Yes"
    else:
        for item in search_corpus:
            if any(pkg in item for pkg in health_packages):
                health_detected = "Yes"
                break

    return {"health_related_findings": health_detected}


def mobsfParse(report_data: dict):
    """Parses MobSF JSON report and saves relevant findings to CSV."""
    if not report_data or "error" in report_data:
        return {"mobsf_status": "API Error"}

    permissions = report_data.get("permissions", {})
    dangerous_perms = [
        perm for perm, details in permissions.items()
        if details.get("status") == "dangerous"
    ]

    sbom = report_data.get("sbom", {})
    sbom_versioned = [str(x) for x in sbom.get("sbom_versioned", [])]
    libraries = report_data.get("libraries", [])
    
    unique_sdks = set(sbom_versioned + libraries)
 
    secrets = report_data.get("secrets", [])

    manifest_findings = report_data.get("manifest_analysis", {}).get("manifest_findings", [])
    cleartext_allowed = "Yes" if any(
        f.get("rule") == "clear_text_traffic" for f in manifest_findings
    ) else "No"

    exported_data = _parseExportedComponents(manifest_findings)
    storage_data = _parseEncryptionAndStorage(report_data)
    pinning_data = _parseCertificatePinning(report_data)
    webview_data = _parseWebviewRisks(report_data)
    health_data = _parseHealthFindings(report_data)

    results = {
        "num_dangerous_permissions": len(dangerous_perms),
        "dangerous_permissions_list": ", ".join(dangerous_perms),
        "num_3rd_party_sdks": len(unique_sdks),
        "sdk_list": ", ".join(unique_sdks),
        "num_hardcoded_secrets": len(secrets),
        "cleartext_traffic_allowed": cleartext_allowed,
        "exported_components_unprotected": exported_data.get("exported_components_unprotected", "No"),
        "insecure_data_storage_detected": storage_data.get("insecure_data_storage_detected", "No"),
        "encryption_at_rest": storage_data.get("encryption_at_rest", "No"),
        "webview_insecure_config_detected": webview_data.get("webview_insecure_config_detected", "No"),
        "health_related_findings": health_data.get("health_related_findings", "No"),
        "cert_pinning": pinning_data.get("cert_pinning_detected", "No"),
        "mobsf_status": "Success"
    }

    return results

