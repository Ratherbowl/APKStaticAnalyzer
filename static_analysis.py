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

raw_path = Path("C:/Users/darda.LAPTOP-P9KGA7VP/OneDrive - Embry-Riddle Aeronautical University/Santhanam, Preethi's files - First Grant Aviation Research/APK_files")
APK_INPUT_DIR = Path(f"\\\\?\\{raw_path}")
ARTIFACTS_DIR = Path("C:/Users/darda.LAPTOP-P9KGA7VP/OneDrive - Embry-Riddle Aeronautical University/Santhanam, Preethi's files - First Grant Aviation Research/test")
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
    for pattern in search_patterns:
        all_apks.extend(str(f) for f in APK_INPUT_DIR.rglob(pattern) if f.is_file())
    # Filter out excluded patterns
    filtered_files = []
    for f in all_apks:
        filename = Path(f).name

        if filename.endswith((".xapk", ".apkm")):
            apk = APK(f)
            try:
                with zipfile.ZipFile(f, "r") as zip_ref:
                    zip_ref.extractall(ARTIFACTS_DIR / Path(f).stem)
                    filename = Path(f).stem
                    filtered_files.append(str(ARTIFACTS_DIR / filename / (apk.get_package_name() + ".apk")))
            except zipfile.BadZipFile:
                print(f"Error: {f} is not a valid zip file.")
        else:
            if not any(fnmatch.fnmatch(filename, pattern) for pattern in exclude_patterns):
                filtered_files.append(str(f))

    return filtered_files


