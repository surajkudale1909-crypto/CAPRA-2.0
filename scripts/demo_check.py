#!/usr/bin/env python
"""CAPRA Demo-Day Smoke Check.

Runs every demo path end-to-end and prints a PASS/FAIL checklist.
Run this BEFORE any live presentation:

    python scripts/demo_check.py

Exit code 0 = everything is demo-ready. Non-zero = fix before going on stage.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

SKIP = "SKIP"
RESULTS = []


def check(name):
    """Decorator registering a demo check."""

    def _wrap(func):
        RESULTS.append((name, func))
        return func

    return _wrap


@check("1. All modules import cleanly")
def c_imports():
    import main  # noqa: F401
    import src.category_detector  # noqa: F401
    import src.config  # noqa: F401
    import src.context_engine  # noqa: F401
    import src.extractor  # noqa: F401
    import src.fusion_engine  # noqa: F401
    import src.history_manager  # noqa: F401
    import src.ml_pipeline  # noqa: F401
    import src.network_detector  # noqa: F401
    import src.pipeline  # noqa: F401
    import src.reachability  # noqa: F401
    import src.report_generator  # noqa: F401
    import src.security_analyzer  # noqa: F401
    import src.threat_intel  # noqa: F401
    import src.tracker_detector  # noqa: F401


@check("2. Manifest extraction (Fossify Calculator sample APK)")
def c_manifest():
    from src.extractor import extract_manifest_info

    apk = os.path.join(ROOT_DIR, "data", "apks", "calculator_sample.apk")
    if not os.path.exists(apk):
        return SKIP
    data = extract_manifest_info(apk)
    assert data["package_name"] == "org.fossify.math", data["package_name"]
    assert data["total_permissions_count"] >= 1


@check("3. Full APK scan -> Safe verdict (sample calculator)")
def c_full_scan():
    from src.pipeline import analyze_apk

    apk = os.path.join(ROOT_DIR, "data", "apks", "calculator_sample.apk")
    if not os.path.exists(apk):
        return SKIP
    res = analyze_apk(apk, options={"skip_history": True})
    assert res["fusion"]["verdict"] == "Safe", res["fusion"]["verdict"]
    assert res["fusion"]["score"] <= 30, res["fusion"]["score"]
    assert res["category"] == "Calculator", res["category"]


@check("4. Demo: benign calculator -> Safe")
def c_demo_calc():
    from src.pipeline import run_synthetic_demo

    r = run_synthetic_demo("benign_calculator", category="Calculator")
    assert r["fusion"]["verdict"] == "Safe", r["fusion"]["verdict"]


@check("5. Demo: spyware flashlight -> Critical (exfil combos + threat override)")
def c_demo_flashlight():
    from src.pipeline import run_synthetic_demo

    r = run_synthetic_demo("malicious_flashlight", category="Flashlight")
    assert r["fusion"]["verdict"] == "Critical", r["fusion"]["verdict"]
    assert r["fusion"]["score"] >= 90, r["fusion"]["score"]
    combo_ids = {c["id"] for c in r["context"]["triggered_combinations"]}
    assert "COMB_STORAGE_EXFILTRATION" in combo_ids, combo_ids


@check("6. Demo: navigation (contextual location exemption)")
def c_demo_nav():
    from src.pipeline import run_synthetic_demo

    r = run_synthetic_demo("benign_navigation", category="Navigation")
    combo_ids = {c["id"] for c in r["context"]["triggered_combinations"]}
    assert "COMB_LOCATION_TRACKING" not in combo_ids, combo_ids
    assert r["fusion"]["score"] <= 15, r["fusion"]["score"]


@check("7. Report export (Markdown + JSON)")
def c_reports():
    from src.pipeline import run_synthetic_demo
    from src.report_generator import export_json_report, generate_markdown_report

    r = run_synthetic_demo("malicious_flashlight", category="Flashlight")
    tmp = tempfile.mkdtemp()
    try:
        md_path = generate_markdown_report(r, output_path=os.path.join(tmp, "report.md"))
        js_path = export_json_report(r, output_path=os.path.join(tmp, "report.json"))
        md = open(md_path, encoding="utf-8").read()
        js = json.load(open(js_path, encoding="utf-8"))
        assert "Privacy" in md or "privacy" in md.lower(), "markdown report missing content"
        assert js["fusion"]["verdict"] == "Critical"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("8. Audit history: save, list, and diff two scans")
def c_history():
    from src.pipeline import PrivacyAnalysisPipeline

    tmp = tempfile.mkdtemp()
    try:
        pipeline = PrivacyAnalysisPipeline(history_db_path=os.path.join(tmp, "history.db"))
        from src.pipeline import run_synthetic_demo

        r = run_synthetic_demo("benign_calculator", category="Calculator")
        id1 = pipeline.history_manager.save_analysis(r)
        r2 = run_synthetic_demo("malicious_flashlight", category="Flashlight")
        id2 = pipeline.history_manager.save_analysis(r2)
        records = pipeline.get_history(limit=10)
        assert len(records) >= 2, f"expected >=2 history records, got {len(records)}"
        diff = pipeline.compare_scans(id1, id2)
        assert diff is not None and len(str(diff)) > 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("9. ML model separates malware-like from benign profiles")
def c_ml():
    import logging

    from src.ml_pipeline import PermissionMLPipeline

    logging.disable(logging.INFO)
    p = PermissionMLPipeline()
    malware_like = [
        "android.permission." + x
        for x in [
            "READ_SMS",
            "SEND_SMS",
            "RECEIVE_SMS",
            "READ_CONTACTS",
            "CALL_PHONE",
            "READ_CALL_LOG",
            "SYSTEM_ALERT_WINDOW",
            "INTERNET",
        ]
    ]
    benign_like = ["android.permission." + x for x in ["VIBRATE", "WAKE_LOCK"]]
    hi = p.predict_risk(malware_like)["risk_percentage"]
    lo = p.predict_risk(benign_like)["risk_percentage"]
    assert hi > lo, f"malware-like {hi}% should exceed benign-like {lo}%"


@check("10. Hardening: zip bomb rejected safely")
def c_hardening():
    from src.extractor import APKSecurityError, validate_apk_archive

    tmp = tempfile.mkdtemp()
    try:
        bomb = os.path.join(tmp, "bomb.apk")
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("classes.dex", b"\x00" * (20 * 1024 * 1024))
        try:
            validate_apk_archive(bomb)
        except APKSecurityError:
            return  # correctly rejected
        raise AssertionError("zip bomb was NOT rejected")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("11. CLI end-to-end (subprocess smoke)")
def c_cli():
    proc = subprocess.run(
        [sys.executable, "main.py", "--demo", "benign_calculator", "--json", "--no-history"],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"CLI exit {proc.returncode}: {proc.stderr[-500:]}"
    payload = json.loads(proc.stdout)
    assert payload["fusion"]["verdict"] == "Safe", payload["fusion"]["verdict"]


@check("12. Desktop GUI modules load")
def c_gui():
    try:
        import tkinter  # noqa: F401
    except Exception:
        return SKIP
    try:
        import src.gui  # noqa: F401
    except Exception as e:
        raise AssertionError(f"GUI module failed to import: {e}") from e


@check("13. Web dashboard boots (headless)")
def c_web():
    try:
        from fastapi.testclient import TestClient
    except Exception:
        return SKIP
    from src.webapp import create_app

    client = TestClient(create_app())
    r = client.get("/health")
    assert r.status_code == 200 and r.json().get("status") == "ok", "health check failed"
    r = client.get("/")
    assert r.status_code == 200 and "CAPRA" in r.text, "home page failed"


def main() -> int:
    print("=" * 78)
    print("  CAPRA 2.0 — DEMO-DAY SMOKE CHECK")
    print("=" * 78)

    failed = 0
    skipped = 0
    for name, func in RESULTS:
        try:
            result = func()
            status = SKIP if result == SKIP else "PASS"
            if status == SKIP:
                skipped += 1
        except Exception as e:
            status = f"FAIL  ({type(e).__name__}: {e})"
            failed += 1
        print(f"  [{status:>4}]  {name}")

    print("-" * 78)
    total = len(RESULTS)
    print(
        f"  {total - failed - skipped} passed, {failed} failed, {skipped} skipped / {total} checks"
    )
    if failed:
        print("\n  *** NOT DEMO-READY — fix the failures above before presenting ***")
        return 1
    print("\n  ALL SYSTEMS GO — good luck with the demo! 🚀")
    return 0


if __name__ == "__main__":
    sys.exit(main())
