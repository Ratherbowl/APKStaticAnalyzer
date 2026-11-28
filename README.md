# APKStaticAnalyzer

**Affiliation:** Embry-Riddle Aeronautical University — Aviation Application Research Project

## Overview

**APKStaticAnalyzer** is an automated static analysis pipeline built to evaluate the privacy, security, and regulatory compliance of mobile Android applications (`.apk` files) used across airlines, airports, flight training, and drone/UAS operations.

Designed to process a corpus of ~200 aviation applications, this codebase automates the extraction of machine-measured static evidence for **Tab 3 (Static Findings)** of the research tracker. It orchestrates three analysis engines into a single resumable batch workflow:

1. **Mobile Security Framework (MobSF)** via its local Docker REST API for permissions, third-party SDKs, hardcoded secrets, cryptography, storage, certificate pinning, WebView risks, and health SDK/permission detection.
2. **AccountDeletionAnalyzer (ADF)** using customized shell scripts (`adf_delete.sh`, `adf_health.sh`, and `toplevel.sh`) to map account-deletion and health/medical document workflows from UI strings and OCR'd images to Android layouts, fragments, and activities.
3. **FlowDroid (v2.13.0)** via a multi-dex wrapper (`flowdroid-multidex.jar`) and an aviation-tailored sources/sinks list (`aviation_sources_sinks.txt`) to detect and categorize sensitive source-to-sink taint dataflows.

> **Project Status:** Active Development. End-to-end batch execution (`static_analysis.py`), standalone FlowDroid batching (`flow_droid_script.py`), crash-safe resume logic, and master CSV export (`results/static_findings.csv`) are operational. Automated regulatory compliance mapping (`compliance_findings_mapped`) and CLI flags for `static_analysis.py` are under active development.

## Repository Components

* **`static_analysis.py`**: Main pipeline orchestrator and importable library. Discovers `.apk` files in `AccountDeletionAnalyzer_Ubuntu/apks/`, runs MobSF, ADF (deletion & health), and FlowDroid sequentially per app, handles crash-safe resume/retry, and exports unified results to `results/static_findings.csv`.
* **`flow_droid_script.py`**: FlowDroid execution and XML parsing module. Used both by `static_analysis.py` (via `run_one()` and `check_setup()`) and as a standalone parallel CLI runner. Launches FlowDroid 2.13 through `FlowDroidMultiDex`, parses source-to-sink leaks, categorizes them using `% @category` headers in `aviation_sources_sinks.txt`, and supports automatic SPARK-to-CHA call graph fallback on timeouts or SPARK crashes.
* **`aviation_sources_sinks.txt`**: Project-specific FlowDroid sources and sinks definition annotated with `% @category SOURCE/SINK` headers for automated leak categorization.
* **`adf_delete.sh`**: Tracked custom Bash script (must be copied into `AccountDeletionAnalyzer_Ubuntu/`, replacing any existing copy). Decompiles an APK with Apktool, runs Tesseract OCR on embedded images, validates account-deletion strings via `semantics.py`, resolves layout hierarchies via `toplevel.sh`, and generates `mapping_model_deletion.dot` and `.svg`.
* **`adf_health.sh`**: Tracked custom Bash script (must be copied into `AccountDeletionAnalyzer_Ubuntu/`, replacing any existing copy). Follows the same pipeline as `adf_delete.sh` with regex patterns targeting health, medical, and COVID-19 document/certificate upload and verification workflows (`mapping_model_health.dot` and `.svg`).
* **`toplevel.sh`**: Tracked reconstructed helper script (must be copied into `AccountDeletionAnalyzer_Ubuntu/`, replacing the original copy). Recursively walks `@layout/<name>` XML inclusions to identify top-level/screen-level layouts for `adf_delete.sh` and `adf_health.sh`.
* **`requirements.txt`**: Python package dependencies for the project (including `requests`).
* **`tools/flowdroid/`**: Contains FlowDroid runtime dependencies (`soot-infoflow-cmd-2.13.0-jar-with-dependencies.jar`, `flowdroid-multidex.jar`, and `EasyTaintWrapperSource.txt`).
* **`AccountDeletionAnalyzer_Ubuntu/`**: Nested directory inside the project root containing the separately distributed `AccountDeletionAnalyzer` toolset (`pyStatParser/`, `adf.sh`, `parallel.sh`), the input `apks/` folder, generated `output/` artifacts, and the replaced copies of `adf_delete.sh`, `adf_health.sh`, and `toplevel.sh`.
* **`results/`**: Auto-generated output directory storing `static_findings.csv`, per-app MobSF JSON reports (`results/<app_id>/static_scan/mobsf_report.json`), and FlowDroid XML reports and logs (`results/flowdroid/{xml,logs}`).
* **`.gitignore`**: Excludes the separately distributed `AccountDeletionAnalyzer_Ubuntu/` toolset and generated outputs so third-party binaries and scan artifacts remain untracked by Git.

## Prerequisites & Dependencies

On Windows, execute all command-line utilities, shell scripts, and Python scripts inside **WSL (Windows Subsystem for Linux — Ubuntu)**, while **Docker Desktop** and **Android Studio** run on the Windows host. On macOS, run tools natively via Terminal.

### 1. System & CLI Tools

* **Java (JDK 17+)**: Required by Apktool, FlowDroid, and MobSF components. FlowDroid defaults to `8g` heap (`JAVA_HEAP = "8g"`), so ensure sufficient system RAM.
* **Python 3.10+**: Required for `static_analysis.py`, `flow_droid_script.py`, and `semantics.py`.
* **Docker Desktop**: Required to run the MobSF container.
* **Android Studio / Android SDK Platforms**: Required by FlowDroid (`platforms/` directory containing `android-*.jar` files).
* **Apktool**: Decompiles `.apk` binaries into smali code, manifest, and XML resources.
* **Tesseract OCR**: Extracts text from image resources during ADF scans.
* **Graphviz (`dot`)**: Renders `.dot` mapping models into styled `.svg` visualizations.
* **Unix Utilities**: `grep` (or `ggrep` on macOS), `gawk`, `sed`, `find`, `xargs`, and `timeout` (or `gtimeout` on macOS).

**Ubuntu / WSL Installation:**

```bash
sudo apt update
sudo apt install openjdk-17-jdk python3 python3-pip apktool tesseract-ocr graphviz findutils gawk grep sed -y
pip3 install -r requirements.txt
```

**macOS Installation (via Homebrew):**

```bash
brew update
brew install openjdk python apktool tesseract graphviz findutils gawk grep gnu-sed coreutils
pip3 install -r requirements.txt
```

### 2. MobSF Docker Container

Pull and start the official MobSF container on port `8000`:

```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Retrieve your REST API key from `http://localhost:8000/api_docs` (or the container startup logs).

### 3. FlowDroid Assets (`tools/flowdroid/`)

The required FlowDroid runtime assets are bundled in `APKStaticAnalyzer/tools/flowdroid/`:

* `soot-infoflow-cmd-2.13.0-jar-with-dependencies.jar` — FlowDroid 2.13.0 command-line JAR.
* `flowdroid-multidex.jar` — Multi-dex and lenient resource-parsing wrapper (`FlowDroidMultiDex`). Required so FlowDroid analyzes all `classes*.dex` files instead of stopping at the first dex or failing on resource errors.
* `EasyTaintWrapperSource.txt` — Library taint summary rules (optional, used automatically when present).

### 4. External Requirement: `AccountDeletionAnalyzer_Ubuntu` Setup

This project relies on the separately distributed `AccountDeletionAnalyzer_Ubuntu` toolset:

1. **Place `AccountDeletionAnalyzer_Ubuntu/` directly inside the project root** (`APKStaticAnalyzer/AccountDeletionAnalyzer_Ubuntu/`).
2. **Replace the ADF scripts inside `AccountDeletionAnalyzer_Ubuntu/`** with the version-controlled scripts from the project root (`adf_delete.sh`, `adf_health.sh`, and `toplevel.sh`):

   ```bash
   cd /path/to/APKStaticAnalyzer
   cp adf_delete.sh adf_health.sh toplevel.sh AccountDeletionAnalyzer_Ubuntu/
   chmod +x AccountDeletionAnalyzer_Ubuntu/adf_delete.sh \
            AccountDeletionAnalyzer_Ubuntu/adf_health.sh \
            AccountDeletionAnalyzer_Ubuntu/toplevel.sh
   ```

   > **Important:** Whenever you pull updates to `adf_delete.sh`, `adf_health.sh`, or `toplevel.sh` in the repository root, re-run the `cp` command above so the copies inside `AccountDeletionAnalyzer_Ubuntu/` stay up to date. Both `adf_delete.sh` and `adf_health.sh` resolve `SCRIPT_DIR` dynamically at runtime, so no hardcoded path edits are needed inside them once placed in `AccountDeletionAnalyzer_Ubuntu/`.

3. **Place target `.apk` files inside `AccountDeletionAnalyzer_Ubuntu/apks/`** (the default `APK_INPUT_DIR`).
4. If `semantics.py` reports missing Python packages, install `AccountDeletionAnalyzer_Ubuntu/requirements.txt` into your active Python environment.

## Directory Structure

Arrange your local workspace as follows:

```text
APKStaticAnalyzer/
├── .gitignore
├── README.md
├── requirements.txt
├── static_analysis.py                     # Main pipeline orchestrator (MobSF + ADF + FlowDroid)
├── flow_droid_script.py                   # FlowDroid batch runner, log validator, & XML parser
├── aviation_sources_sinks.txt             # Categorized FlowDroid sources & sinks for aviation apps
├── adf_delete.sh                          # Source script -> copy/replace into AccountDeletionAnalyzer_Ubuntu/
├── adf_health.sh                          # Source script -> copy/replace into AccountDeletionAnalyzer_Ubuntu/
├── toplevel.sh                            # Source script -> copy/replace into AccountDeletionAnalyzer_Ubuntu/
├── AccountDeletionAnalyzer_Ubuntu/        # Separately distributed toolset (nested in project root, ignored by Git)
│   ├── adf_delete.sh                      # Replaced from project root
│   ├── adf_health.sh                      # Replaced from project root
│   ├── toplevel.sh                        # Replaced from project root
│   ├── adf.sh                             # Original toolset script
│   ├── parallel.sh                        # Original toolset script
│   ├── requirements.txt
│   ├── apks/                              # Input corpus of .apk files (default APK_INPUT_DIR)
│   │   └── *.apk
│   ├── pyStatParser/
│   │   └── pyStatParser/
│   │       └── semantics.py
│   ├── output/                            # Auto-generated: decompiled APKs, OCR text, mapping_model_*.dot/.svg
│   ├── logs/
│   ├── temp/
│   └── venv/
├── tools/
│   └── flowdroid/
│       ├── soot-infoflow-cmd-2.13.0-jar-with-dependencies.jar
│       ├── flowdroid-multidex.jar
│       └── EasyTaintWrapperSource.txt
├── results/                               # Auto-generated by static_analysis.py
│   ├── static_findings.csv                # Master output CSV (Tab 3: Static Findings)
│   ├── <app_id>/
│   │   └── static_scan/
│   │       └── mobsf_report.json          # Raw MobSF JSON report per app
│   └── flowdroid/
│       ├── xml/                           # Raw FlowDroid leak XML reports (<app_id>.xml)
│       └── logs/                          # Full FlowDroid execution logs (<app_id>.log)
└── sootOutput/                            # Auto-generated Soot/FlowDroid scratch output
```

## Configuration (Required Before Running)

### 1. Export `MOBSF_API_KEY`

`static_analysis.py` reads the MobSF REST API key from the `MOBSF_API_KEY` environment variable:

```bash
export MOBSF_API_KEY="YOUR_MOBSF_REST_API_KEY_HERE"
```

Add this line to `~/.bashrc` (Ubuntu/WSL) or `~/.zshrc` (macOS) to persist it across terminal sessions.

### 2. Update the Android SDK `platforms` Path

Update the Android SDK `platforms` directory path to match your local machine:

* **In `static_analysis.py`** (used by the unified pipeline, which automatically syncs `flow_droid_script.ANDROID_PLATFORMS`):

  ```python
  # WSL example:
  ANDROID_JARS = Path("/mnt/c/Users/<username>/AppData/Local/Android/Sdk/platforms")
  # macOS example:
  # ANDROID_JARS = Path.home() / "Library/Android/sdk/platforms"
  ```

* **In `flow_droid_script.py`** (required if running `flow_droid_script.py` standalone):

  ```python
  ANDROID_PLATFORMS = Path("/mnt/c/Users/<username>/AppData/Local/Android/Sdk/platforms")
  ```

### 3. Optional Pipeline & Memory Settings

* **Input / Output Paths (`static_analysis.py`)**:
  * `APK_INPUT_DIR` defaults to `PROJECT_DIR / "AccountDeletionAnalyzer_Ubuntu" / "apks"` (switch to `PROJECT_DIR / "test"` for test runs).
  * `ARTIFACTS_DIR` defaults to `PROJECT_DIR / "results"`.
  * `ADF_DIR` defaults to `PROJECT_DIR / "AccountDeletionAnalyzer_Ubuntu"`.
  * `MOBSF_URL` defaults to `"http://localhost:8000"`.
* **JVM Heap Size (`flow_droid_script.py`)**:
  * `JAVA_HEAP` defaults to `"8g"`. Large apps typically require `4g`–`8g`; when running FlowDroid standalone with `-j`, ensure `JAVA_HEAP × jobs` fits in available RAM.

## Usage

### 1. Run the Full Automated Pipeline (`static_analysis.py`)

With the MobSF Docker container running and `MOBSF_API_KEY` exported:

```bash
python3 static_analysis.py
```

Running `static_analysis.py` executes `main(flowdroid_timeout=1800, retry_fast=True, run_by="")`, which:

1. Syncs `flow_droid_script.py` paths (`FLOWDROID_JAR`, `ANDROID_PLATFORMS`) and validates setup via `fd.check_setup()`.
2. Creates `results/` and `results/flowdroid/{xml,logs}`.
3. Discovers all `.apk` files in `APK_INPUT_DIR` (sorted case-insensitively).
4. **Crash-safe resume (`_prepareMasterCsv`)**: If `results/static_findings.csv` already exists, retains only rows where MobSF (`Success`), ADF (`Success`), and FlowDroid (`ok` / `ok(CHA)`) all finished cleanly, atomically rewrites the CSV to drop incomplete/failed rows, and skips already-completed APKs.
5. Processes each pending APK through MobSF, ADF (deletion & health), and FlowDroid, flushing (`flush()` + `os.fsync()`) each row to `results/static_findings.csv` immediately so progress is preserved if interrupted.

To customize `flowdroid_timeout`, `retry_fast`, or the `run_by` operator tag, call `main()` from Python:

```python
import static_analysis as sa

sa.main(flowdroid_timeout=1800, retry_fast=True, run_by="YourName")
```

### 2. Run FlowDroid Standalone (`flow_droid_script.py`)

`flow_droid_script.py` can also be invoked independently for parallel FlowDroid-only batch scans (uses Python's standard library only):

```bash
python3 flow_droid_script.py AccountDeletionAnalyzer_Ubuntu/apks -o flowdroid_results -j 2 --timeout 3600 --retry-fast --resume
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `apk_dir` | *(required)* | Folder containing `.apk` files to analyze. |
| `-o`, `--out` | `flowdroid_results` | Output directory for CSVs, `xml/`, and `logs/`. |
| `-j`, `--jobs` | `1` | Number of APKs to analyze in parallel (watch RAM: `JAVA_HEAP × jobs`). |
| `--timeout` | `1800` | Hard timeout in seconds per APK attempt (phase budgets: 35% callbacks, 40% dataflow, 10% results). |
| `--retry-fast` | `False` | On timeout or SPARK callgraph crash, retry once using the faster `CHA` call graph (`ok(CHA)`). |
| `-r`, `--recursive` | `False` | Recursively search subfolders for `.apk` files. |
| `--resume` | `False` | Skip APKs that already completed with `ok*` status in `progress.csv`; re-run failures/timeouts. |

**Standalone FlowDroid Outputs (inside `-o`):**

* `summary.csv`: One row per APK (`apk`, `status`, `leaks_found`, `seconds`, `notes`).
* `leaks.csv`: One row per detected `(source, sink)` leak with categories, called APIs, methods, and Jimple statements.
* `leaks_by_category.csv`: Aggregated leak counts per `(apk, source_category, sink_category)` pair.
* `progress.csv`: Incremental per-APK checkpoint log used by `--resume`.
* `xml/` and `logs/`: Raw FlowDroid XML reports and full execution logs per APK.

## Pipeline Architecture & Modules

### 1. APK Discovery & Resume Management (`static_analysis.py`)

* **`get_all_apks()`**: Returns all `.apk` `Path` objects inside `APK_INPUT_DIR`.
* **`_isRowComplete(row)`**: Checks that `mobsf_status == "Success"`, `adf_status == "Success"`, and `flowdroid_status` starts with `"ok"`.
* **`_prepareMasterCsv(csv_path, fieldnames)`**: Initializes or atomically compacts `static_findings.csv` on startup so cleanly finished apps are skipped and partial/failed apps are automatically retried.

### 2. MobSF Static Security & Privacy Analysis (`static_analysis.py`)

* **`mobsfScan(app_id, apk_file, output_dir)`**: Uploads the APK via `POST /api/v1/upload`, triggers static analysis via `POST /api/v1/scan` (600s timeout), checks for soft API errors, and saves raw JSON to `<output_dir>/static_scan/mobsf_report.json`.
* **`mobsfParse(report_data)`**: Extracts metrics using modular helpers:
  * `_parseExportedComponents()` — Detects unprotected exported components.
  * `_parseEncryption()` — Detects encryption-at-rest indicators (SQLCipher, `androidx.security.crypto`, Android Keystore, `javax.crypto`, `androidx.datastore`).
  * `_parseStorage()` — Detects weak ciphers (ECB, CBC padding oracle, RSA without OAEP), world-readable/writable files, external storage reads/writes, and raw SQL queries.
  * `_parseCertificatePinning()` — Detects `android_ssl_pinning` rules or non-vulnerability `pin-set` network security configs.
  * `_parseWebviewRisks()` — Detects `android_webview*` code analysis vulnerabilities.
  * `_parseHealthFindings()` — Detects health/medical permissions (`BODY_SENSORS`, `FOREGROUND_SERVICE_HEALTH`, etc.) and Health Connect / Google Fit SDKs.

### 3. Account & Health Feature Mapping (`static_analysis.py` + ADF Scripts)

* **`adfScan(app_id, apk_file)`**: Runs `adf_delete.sh` and `adf_health.sh` inside `AccountDeletionAnalyzer_Ubuntu/` (900s timeout each), clearing stale `.dot` files beforehand and returning paths to `mapping_model_deletion.dot` and `mapping_model_health.dot`.
* **`adfParse(deletion_dot, health_dot)`**: Calls `_extractDotEvidence()` to extract unique nodes matching `adstr::`, `nattr::`, `lay::`, `frag::`, `act::`, and `img::` prefixes.
* **`toplevel.sh`**: Called by both ADF scripts to trace included XML layouts upward to top-level screen layouts before matching `R$layout` references in `.smali` files.

### 4. FlowDroid Taint Analysis (`flow_droid_script.py` + `static_analysis.py`)

* **`build_command()` & `run_one()`**: Invokes `java -Xmx8g -cp <FLOWDROID_JAR>:<WRAPPER_JAR> FlowDroidMultiDex` with phase time limits (`-ct`, `-dt`, `-rt`), optional taint wrapper (`-t`), and optional SPARK-to-CHA fallback (`-cg CHA`).
* **`check_log()`**: Validates actual run status from FlowDroid's log rather than relying solely on exit code `0` (distinguishing `ok`, `ok(CHA)`, `out_of_memory`, `timeout`, `incomplete`, and `error`).
* **`parse_leaks()` & `load_categories()`**: Parses FlowDroid XML results and maps Soot signatures (with subclass fallback) to `% @category` labels from `aviation_sources_sinks.txt`.
* **`_summarizeLeaks()`** (`static_analysis.py`): Condenses per-app leaks into a concise CSV string (e.g., `LOCATION -> NETWORK (3x); DEVICE_ID -> ANALYTICS (2x)`), capped at the top 10 category pairs.

## Master CSV Output Schema (`results/static_findings.csv`)

`static_analysis.py` writes the following 27 columns to support **Tab 3 (Static Findings)**:

| Column Name | Source | Type / Values | Description |
| :--- | :--- | :--- | :--- |
| `app_id` | Pipeline | `str` | APK filename stem (`apk_path.stem`). |
| `tool_used` | Pipeline | `str` | Fixed value `"MobSF + ADF + FlowDroid"`. |
| `scan_date` | Pipeline | `YYYY-MM-DD` | ISO date when the scan executed. |
| `num_dangerous_permissions` | `mobsfParse` | `int` | Count of Android permissions flagged as `"dangerous"` by MobSF. |
| `dangerous_permissions_list` | `mobsfParse` | `str` | Comma-separated list of dangerous permissions (or `"None"`). |
| `hardcoded_secret_found` | `mobsfParse` | `"Yes"` / `"No"` | `"Yes"` if `num_hardcoded_secrets > 0`, otherwise `"No"`. |
| `num_hardcoded_secrets` | `mobsfParse` | `int` | Count of hardcoded API keys, tokens, or secrets detected by MobSF. |
| `num_3rd_party_sdks` | `mobsfParse` | `int` | Count of unique versioned SBOM packages and native libraries detected. |
| `sdk_list` | `mobsfParse` | `str` | Comma-separated list of detected third-party SDKs and libraries (or `"None"`). |
| `cert_pinning_present` | `mobsfParse` | `"Yes"` / `"No"` | Whether SSL/certificate pinning rules or valid `pin-set` configs were detected. |
| `encryption_at_rest_detected` | `mobsfParse` | `"Yes"` / `"No"` | Whether encryption-at-rest libraries or APIs (SQLCipher, Keystore, `javax.crypto`, etc.) were detected. |
| `delete_account_class_found` | `adfParse` | `"Yes"` / `"No"` | Whether valid account-deletion nodes were mapped in `mapping_model_deletion.dot`. |
| `delete_account_string_evidence` | `adfParse` | `str` | Comma-separated unique strings, attributes, layouts, fragments, activities, or OCR images linked to account deletion (or `"None"`). |
| `sensitive_dataflow_count` | `flow_droid_script` | `int` | Total number of `(source, sink)` taint leaks reported by FlowDroid. |
| `sensitive_dataflow_examples` | `_summarizeLeaks` | `str` | Top 10 source-to-sink category pairs with counts (e.g., `LOCATION -> NETWORK (3x)`), or `"None"`. |
| `raw_tool_output_path` | Pipeline | `str` | Path to the app's raw artifact directory (`results/<app_id>`). |
| `compliance_findings_mapped` | Pipeline | `str` | Placeholder column reserved for the upcoming Compliance Mapping Engine (defaults to `"Error"` until populated). |
| `run_by` | Pipeline | `str` | Operator name/initials passed to `main(run_by=...)`. |
| `notes` | Pipeline | `str` | Pipe-separated (`\|`) operational notes, FlowDroid source/sink counts, or error details. |
| `cleartext_traffic_allowed` | `mobsfParse` | `"Yes"` / `"No"` | Whether `clear_text_traffic` is allowed in the Android Manifest. |
| `insecure_data_storage_detected` | `mobsfParse` | `"Yes"` / `"No"` | Whether weak ciphers, world-accessible files, external storage writes, or raw SQL queries were detected. |
| `exported_components_unprotected` | `mobsfParse` | `"Yes"` / `"No"` | Whether exported components lack permission protection. |
| `webview_insecure_config_detected` | `mobsfParse` | `"Yes"` / `"No"` | Whether any `android_webview*` vulnerabilities were detected. |
| `health_related_permission_or_sdk_detected` | `mobsfParse` + `adfParse` | `"Yes"` / `"No"` | `"Yes"` if either MobSF detected health permissions/SDKs **or** `adf_health.sh` mapped health-document workflows. |
| `mobsf_status` | `mobsfParse` | `"Success"` / `"API Error"` | Outcome of the MobSF scan and report parsing. |
| `adf_status` | `adfScan` | `"Success"` / `"Partial Success"` / `"Error"` | `"Success"` when both deletion and health `.dot` models were generated. |
| `flowdroid_status` | `flow_droid_script` | `"ok"` / `"ok(CHA)"` / error string | Log-verified FlowDroid outcome (`timeout`, `out_of_memory`, `incomplete`, `error(...)`, etc.). |

## Roadmap & Future Functionality

1. **CLI Arguments for `static_analysis.py`**: Add `argparse` flags (`--apk-dir`, `--out`, `--timeout`, `--no-retry-fast`, `--run-by`) so operators do not need to edit constants or wrap `main()` in Python.
2. **Compliance Mapping Engine**: Populate `compliance_findings_mapped` by mapping extracted MobSF, ADF, and FlowDroid findings to applicable aviation and security standards (FAA AC 120-76D/E, OWASP MASVS/ASVS, NIST SP 800-53, HIPAA).
3. **Research Tracker & ML Integration**: Merge `results/static_findings.csv` with Tab 1 (App Inventory), Tab 2 (Manual Review), and Tab 4 (LLM Judgments) to support rule-based baselines and compliance classifier training.