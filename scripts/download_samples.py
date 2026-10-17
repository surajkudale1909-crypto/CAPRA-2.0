"""Sample APK Downloader Utility.

Downloads curated open-source benign and test APKs into data/apks/
for benchmarking and mid-semester evaluations.
"""

import os
import sys
import urllib.request

SAMPLES = {
    "fossify_calculator.apk": {
        "name": "Fossify Calculator (Benign Baseline)",
        "url": "https://github.com/FossifyOrg/Calculator/releases/download/1.4.0/calculator-10-foss-release.apk",
        "category": "Calculator",
    },
}

DATA_APKS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "apks"))


def download_all():
    os.makedirs(DATA_APKS_DIR, exist_ok=True)
    print(f"Target directory: {DATA_APKS_DIR}\n")

    for filename, info in SAMPLES.items():
        dest = os.path.join(DATA_APKS_DIR, filename)
        print(f"[*] Fetching: {info['name']}")
        print(f"    URL: {info['url']}")
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            print(f"    [SKIP] Already exists: {dest} ({os.path.getsize(dest)} bytes)\n")
            continue

        try:
            req = urllib.request.Request(info["url"], headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as f:
                content = resp.read()
                f.write(content)
            print(f"    [OK] Saved to: {dest} ({len(content)} bytes)\n")
        except Exception as e:
            print(f"    [ERROR] Download failed: {e}\n", file=sys.stderr)


if __name__ == "__main__":
    download_all()
