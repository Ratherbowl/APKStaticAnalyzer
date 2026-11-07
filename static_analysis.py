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
import re

APK_INPUT_DIR = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/Downloads/Test APK/APKs/")
ARTIFACTS_DIR = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/Downloads/Test APK/Output/")
ADF_DIR = Path(__file__).resolve().parent.parent / "AccountDeletionAnalyzer_Ubuntu"
FLOWDROID_JAR = Path.home() / "FlowDroid" / "soot-infoflow-cmd-jar-with-dependencies.jar"
ANDROID_JARS = Path("/mnt/c/Users/darda.LAPTOP-P9KGA7VP/AppData/Local/Android/Sdk/platforms")

MOBSF_URL = "http://localhost:8000"
MOBSF_API_KEY = "81cd67c1a301e2fe23f4c1fc59e51bde06d1beb0ea52ceb7e5766c8170fd90b7"
HEADERS = {"Authorization": MOBSF_API_KEY}

def get_all_apks():
    """Returns a list of all .apk files in the APK_INPUT_DIR."""
    return list(APK_INPUT_DIR.glob("*.apk"))

def _extractDotEvidence(dot_file: Path | None) -> list[str]:
    """Helper to extract unique node values from an ADF mapping_model_*.dot file."""
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

    return evidence_items

def adfScan(app_id: str, apk_file: Path) -> dict[str, Path | None]:
    """Runs adf_delete.sh and adf_health.sh and copies the resulting .dot files to output_dir."""
    print(f"[*] Running ADF (deletion & health) for {app_id}...")
    scripts = {
        "deletion": (ADF_DIR / "adf_delete.sh", "mapping_model_deletion.dot"),
        "health": (ADF_DIR / "adf_health.sh", "mapping_model_health.dot"),
    }

    results = {"deletion": None, "health": None}
    target_apk = Path(apk_file).resolve()
    apk_stem = target_apk.stem

    try:
        # Loop unpacks each script key and its tuple pair (script path, output filename)
        for key, (script_path, dot_filename) in scripts.items():
            if not script_path.exists():
                print(f"[!] ADF script {script_path} not found.")
                continue

            expected_dot = ADF_DIR / "output" / apk_stem / dot_filename
            if expected_dot.exists():
                expected_dot.unlink()  # Remove old .dot file to prevent data collision between runs
            
            subprocess.run(
                ["bash", str(script_path), str(target_apk)],
                cwd=str(ADF_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=900
            )

            if expected_dot.exists():
                results[key] = expected_dot
                print(f"[*] Success! Found {dot_filename} at {expected_dot}")
            else:
                print(f"[!] {script_path.name} did not produce {expected_dot.name}")

    except subprocess.TimeoutExpired:
        print(f"[!] ADF script timed out for {app_id}.")
    except Exception as e:
        print(f"[!] ADF execution failed for {app_id}: {e}")
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
        title = str(finding.get("title", "")).lower()
        desc = str(finding.get("description", "")).lower()

        # Check for unprotected exported components based on rule and description
        if rule in ("explicitly_exported", "exported_intent_filter_exists"):
            if "not protected" in title or "not protected" in desc or "shared with other apps" in desc:
                return {"exported_components_unprotected": "Yes"}
            
    return {"exported_components_unprotected": "No"}

def _parseEncryptionAndStorage(code_findings: dict, sbom_versioned: list) -> dict:
    """Parses encryption and storage findings from MobSF report."""
    enc_indicators = [
        "android_db_encryption", "android_sql_cipher", "android_sql_cipher_aes256", 
        "androidx.security.crypto", "androidx.datastore", "android.security.keystore", 
        "java.security", "javax.crypto", "javax.crypto.spec"
    ]
    insecure_storage_rules = [
        "android_hiddenui", "android_aes_ecb", "android_aws_ecb_default",
        "android_rsa_no_oaep", "android_world_writable", "android_world_readable",
        "android_world_read_write", "android_weak_ciphers", "cbc_padding_oracle",
        "android_sql_raw_query", "android_read_write_external",
    ]

    search_corpus = [f.lower() for f in (list(code_findings.keys()) + sbom_versioned)]
    
    encryption_detected = "No"
    for item in search_corpus:
        if any(indicator in item for indicator in enc_indicators):
            encryption_detected = "Yes"
            break

    insecure_storage = "Yes" if any(rule in code_findings for rule in insecure_storage_rules) else "No"
    
    return {"encryption_at_rest": encryption_detected, "insecure_data_storage_detected": insecure_storage}

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
    sbom_packages = sbom.get("sbom_packages", []) + sbom_versioned
    
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
    storage_data = _parseEncryptionAndStorage(code_findings, sbom_versioned)
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
        "encryption_at_rest": storage_data.get("encryption_at_rest", "No"),
        "webview_insecure_config_detected": webview_data.get("webview_insecure_config_detected", "No"),
        "health_related_findings": health_data.get("health_related_findings", "No"),
        "cert_pinning": pinning_data.get("cert_pinning_detected", "No"),
        "mobsf_status": "Success"
    }

    return results
