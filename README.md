# APKStaticAnalyzer

**Affiliation:** Embry-Riddle Aeronautical University — Aviation Application Research Project

## Overview

**APKStaticAnalyzer** is an automated static analysis pipeline built to evaluate the privacy, security, and regulatory compliance of mobile Android applications (`.apk` files) used across airlines, airports, flight training, and drone/UAS operations. 

Designed to process a corpus of 200 aviation applications, this codebase automates the extraction of machine-measured static evidence for **Tab 3 (Static Findings)** of the research tracker. It integrates the **Mobile Security Framework (MobSF)** REST API with customized **AccountDeletionAnalyzer (ADF)** scripts to detect security vulnerabilities, third-party SDK usage, account deletion workflows, and health-data handling.

> **Project Status:** Active Development. This repository currently provides the core scanning and parsing modules (`static_analysis.py`, `adf_delete.sh`, and `adf_health.sh`). Batch orchestration and automated CSV export are under active development.

---

## Repository Components

* **`static_analysis.py`**: Core Python module that discovers input APKs, executes the external ADF scripts, interacts with the local MobSF Docker REST API, and parses both Graphviz `.dot` models and MobSF JSON reports into structured Python dictionaries.
* **`adf_delete.sh`**: Custom Bash script for `AccountDeletionAnalyzer` that decompiles an APK, runs OCR on embedded images, validates account-deletion strings via `semantics.py`, maps UI strings to Android layouts, fragments, and activities, and outputs `mapping_model_deletion.dot` (and `.svg`).
* **`adf_health.sh`**: Custom Bash script following the same mapping pipeline as `adf_delete.sh`, tailored with regular expressions to detect health, medical, and COVID-19 document/certificate upload or verification workflows (`mapping_model_health.dot` and `.svg`).

---

## Prerequisites & Dependencies

On Windows, all command-line utilities and scripts must be executed inside **WSL (Windows Subsystem for Linux - Ubuntu)**, while Docker Desktop runs on the host OS. On macOS, tools can be run natively via Terminal.

### 1. System & CLI Tools
* **Java (JDK 17+)**: Required by Apktool and MobSF components.
* **Python 3.10+**: Required for `static_analysis.py` (requires `requests`) and `semantics.py`.
* **Docker Desktop**: Required to host the MobSF container.
* **Apktool**: Decompiles `.apk` binaries into smali code, manifest, and XML resources.
* **Tesseract OCR**: Extracts text from app image resources during ADF scans.
* **Graphviz (`dot`)**: Renders `.dot` mapping models into `.svg` visualizations.
* **Unix Utilities**: `grep` (or `ggrep` on macOS), `gawk`, `sed`, `find`, `xargs`, and `timeout` (or `gtimeout` on macOS).

**Ubuntu / WSL Installation:**
```bash
sudo apt update
sudo apt install openjdk-17-jdk python3 python3-pip apktool tesseract-ocr graphviz findutils gawk grep sed -y
pip3 install requests
```

**macOS Installation (via Homebrew):**
```bash
brew update
brew install openjdk python apktool tesseract graphviz findutils gawk grep gnu-sed coreutils
pip3 install requests
```

### 2. MobSF Docker Container
Pull and run the official MobSF image on port `8000`:
```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

### 3. External Requirement: `AccountDeletionAnalyzer_Ubuntu`
This project relies on the `AccountDeletionAnalyzer` toolset (distributed separately from this repository). 
* By default, `static_analysis.py` expects the `AccountDeletionAnalyzer_Ubuntu` folder to reside in the parent directory alongside this repository.
* **Important:** You must move or copy `adf_delete.sh` and `adf_health.sh` from this repository directly into your `AccountDeletionAnalyzer_Ubuntu` directory so they sit alongside `toplevel.sh` and the `pyStatParser/` directory.

---

## Directory Structure

For default relative path resolution to work properly, arrange your workspace as follows:

```text
workspace/
├── APKStaticAnalyzer/
│   ├── static_analysis.py
│   └── README.md
└── AccountDeletionAnalyzer_Ubuntu/       # Distributed separately
    ├── adf_delete.sh                     # Copied from APKStaticAnalyzer
    ├── adf_health.sh                     # Copied from APKStaticAnalyzer
    ├── toplevel.sh
    ├── pyStatParser/
    │   └── pyStatParser/
    │       └── semantics.py
    └── output/                           # Generated automatically during ADF runs
```

---

## Configuration (Required Before Running)

Every operator must update hardcoded file paths and API credentials in both `static_analysis.py` and the two `adf_*.sh` scripts to match their local environment.

### 1. Configure `static_analysis.py`
Open `static_analysis.py` and update the global configuration variables at the top of the file:

```python
# Directory containing the target .apk files to analyze
APK_INPUT_DIR = Path("/path/to/your/input/APKs/")

# Directory where per-app scan artifacts (e.g., mobsf_report.json) will be saved
ARTIFACTS_DIR = Path("/path/to/your/Output/")

# Path to the external AccountDeletionAnalyzer_Ubuntu directory
ADF_DIR = Path(__file__).resolve().parent.parent / "AccountDeletionAnalyzer_Ubuntu"

# MobSF connection settings (retrieve your API key from http://localhost:8000/api_docs)
MOBSF_URL = "http://localhost:8000"
MOBSF_API_KEY = "YOUR_MOBSF_REST_API_KEY_HERE"
```

### 2. Configure `adf_delete.sh` and `adf_health.sh`
Open **both** `adf_delete.sh` and `adf_health.sh` inside your `AccountDeletionAnalyzer_Ubuntu/` directory and update the `SEMANTICS` variable (Line 28 in `adf_health.sh`, Line 26 in `adf_delete.sh`) to point to your local `semantics.py` file:

```bash
# EDIT THIS to match your local AccountDeletionAnalyzer_Ubuntu path:
SEMANTICS="/path/to/your/AccountDeletionAnalyzer_Ubuntu/pyStatParser/pyStatParser/semantics.py"
```

Ensure both scripts and `toplevel.sh` have executable permissions:
```bash
cd /path/to/your/AccountDeletionAnalyzer_Ubuntu
chmod +x adf_delete.sh adf_health.sh toplevel.sh
```

---

## Current Functionality & Architecture

Currently, `static_analysis.py` functions as an importable library providing five primary operations:

### 1. APK Discovery
* **`get_all_apks()`**: Scans `APK_INPUT_DIR` and returns a list of `Path` objects for all `.apk` files found.

### 2. Account & Health Feature Mapping (ADF)
* **`adfScan(app_id: str, apk_file: Path) -> dict[str, Path | None]`**:
  * Invokes `adf_delete.sh` and `adf_health.sh` inside `ADF_DIR` with a 900-second timeout per script.
  * Automatically removes any pre-existing `.dot` files before execution to prevent data collisions across runs.
  * Returns a dictionary containing the paths to `mapping_model_deletion.dot` and `mapping_model_health.dot`.
* **`adfParse(deletion_dot: Path | None, health_dot: Path | None) -> dict`**:
  * Uses `_extractDotEvidence()` to parse Graphviz nodes matching `adstr::`, `nattr::`, `lay::`, `frag::`, `act::`, and `img::` prefixes.
  * Returns structured indicators for account deletion and health-document workflows.

### 3. MobSF Static Security & Privacy Analysis
* **`mobsfScan(app_id: str, apk_file: Path, output_dir: Path) -> dict | None`**:
  * Uploads the `.apk` binary to the running MobSF container via `POST /api/v1/upload`.
  * Triggers the static scan via `POST /api/v1/scan` (600-second timeout).
  * Saves the complete raw JSON response to `<output_dir>/static_scan/mobsf_report.json` and returns the parsed JSON dictionary.
* **`mobsfParse(report_data: dict) -> dict`**:
  * Evaluates the MobSF JSON report using dedicated helper functions (`_parseExportedComponents`, `_parseEncryptionAndStorage`, `_parseCertificatePinning`, `_parseWebviewRisks`, and `_parseHealthFindings`).
  * Returns a flattened dictionary of security, cryptography, permission, SDK, and health-related metrics.

### Quick Usage Example
*In Progress*

## Extracted Output Schema

The parsers generate the following fields to support **Tab 3 (Static Findings)**:

| Field Name | Source | Type / Values | Description |
| :--- | :--- | :--- | :--- |
| `delete_account_class_found` | `adfParse` | `"Yes"` / `"No"` | Whether valid account deletion nodes were mapped in `mapping_model_deletion.dot`. |
| `delete_account_string_evidence` | `adfParse` | `str` (`"None"` or CSV list) | Unique strings, resource attributes, layouts, fragments, activities, or OCR image names linked to account deletion. |
| `adf_health_detected` | `adfParse` | `"Yes"` / `"No"` | Whether health/medical document upload or verification nodes were mapped in `mapping_model_health.dot`. |
| `num_dangerous_permissions` | `mobsfParse` | `int` | Count of Android permissions flagged as `"dangerous"` by MobSF. |
| `dangerous_permissions_list` | `mobsfParse` | `str` (CSV list) | Comma-separated list of dangerous permissions requested by the app. |
| `num_3rd_party_sdks` | `mobsfParse` | `int` | Count of unique versioned SBOM packages and native libraries detected. |
| `sdk_list` | `mobsfParse` | `str` (CSV list) | Comma-separated list of identified third-party SDKs and libraries. |
| `num_hardcoded_secrets` | `mobsfParse` | `int` | Count of hardcoded API keys, tokens, or secrets identified in the package. |
| `cleartext_traffic_allowed` | `mobsfParse` | `"Yes"` / `"No"` | Whether `clear_text_traffic` is permitted in the Android Manifest. |
| `exported_components_unprotected` | `mobsfParse` | `"Yes"` / `"No"` | Whether activities, services, receivers, or providers are exported without permission protection. |
| `insecure_data_storage_detected` | `mobsfParse` | `"Yes"` / `"No"` | Detects weak ciphers (ECB, CBC padding oracle, RSA without OAEP), world-readable/writable files, external storage writes, or raw SQL queries. |
| `encryption_at_rest` | `mobsfParse` | `"Yes"` / `"No"` | Detects usage of SQLCipher, `androidx.security.crypto`, Android Keystore, `javax.crypto`, or `androidx.datastore`. |
| `webview_insecure_config_detected`| `mobsfParse` | `"Yes"` / `"No"` | Detects any `android_webview*` code analysis vulnerabilities. |
| `health_related_findings` | `mobsfParse` | `"Yes"` / `"No"` | Detects health/medical permissions (`BODY_SENSORS`, `FOREGROUND_SERVICE_HEALTH`, etc.) or Health Connect / Google Fit SDK packages. |
| `cert_pinning` | `mobsfParse` | `"Yes"` / `"No"` | Detects `android_ssl_pinning` rules or valid `pin-set` declarations in the network security configuration. |
| `mobsf_status` | `mobsfParse` | `"Success"` / `"API Error"` | Indicates whether the MobSF scan and JSON extraction completed cleanly. |

---

## Roadmap & Future Functionality

The following features are planned for upcoming releases of `APKStaticAnalyzer` to complete the automated pipeline:

1. **Automated Batch Execution Loop**: A CLI entry point (`main()`) to iterate across all 200 aviation APKs in `APK_INPUT_DIR` with error recovery, logging, and progress tracking.
2. **Metadata & Tab 3 Compliance Integration**: Merging static scan outputs with application inventory metadata (such as `app_id`, functional category, and applicable aviation/cybersecurity standards) to generate automated compliance mappings.
3. **Automated CSV Export**: Writing the unified dictionary outputs from `adfParse()`, `mobsfParse()`, and app metadata directly into a master CSV formatted for **Tab 3 (Static Findings)** and downstream machine learning classification.