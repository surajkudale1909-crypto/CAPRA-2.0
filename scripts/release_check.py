#!/usr/bin/env python
"""CAPRA Release Check — fresh-machine install verification.

Simulates a brand-new machine: clean virtualenv, installs from requirements.txt
plus the packaged project (`pip install .[dev]`), then verifies the INSTALLED
artifacts from an unrelated working directory:

  1. fresh virtualenv created
  2. dependencies install from requirements.txt
  3. project installs (wheel) with data files + console script
  4. `capra --help` console entry point works
  5. `capra --demo benign_calculator --json` runs from an unrelated cwd
     (proves models/rules/trackers ship inside the package)
  6. web dashboard boots headlessly
  7. GUI toolkit availability (WARN only — python3-tk is a system package)
  8. full test suite in the fresh environment
  9. demo-day smoke check (scripts/demo_check.py)

Usage:
    python scripts/release_check.py            # full check (downloads deps)
    python scripts/release_check.py --quick    # skip the full pytest run
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

RESULTS = []


def check(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn

    return deco


SKIP = "SKIP"


def run(cmd, cwd, timeout=2400, env=None):
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    )


@check("1. Fresh virtualenv created")
def c_venv(ctx):
    proc = run([sys.executable, "-m", "venv", ctx["venv"]], cwd=ROOT_DIR)
    assert proc.returncode == 0, f"venv creation failed: {proc.stderr[-400:]}"


@check("2. Dependencies install from requirements.txt")
def c_deps(ctx):
    proc = run([ctx["pip"], "install", "-q", "-r", "requirements.txt"], cwd=ROOT_DIR)
    assert proc.returncode == 0, f"pip install -r failed:\n{proc.stderr[-1200:]}"


@check("3. Project installs (wheel + data files + console script)")
def c_install(ctx):
    proc = run([ctx["pip"], "install", "-q", ".[dev]"], cwd=ROOT_DIR)
    assert proc.returncode == 0, f"pip install . failed:\n{proc.stderr[-1200:]}"


@check("4. `capra --help` console entry point works")
def c_entrypoint(ctx):
    proc = run([ctx["capra"], "--help"], cwd=ctx["scratch"])
    assert proc.returncode == 0, f"capra --help failed:\n{proc.stderr[-500:]}"
    assert "--web" in proc.stdout and "--demo" in proc.stdout, "expected flags missing"


@check("5. Demo runs from an unrelated cwd (packaged data files)")
def c_demo_unrelated_cwd(ctx):
    proc = run(
        [ctx["capra"], "--demo", "benign_calculator", "--json", "--no-history"],
        cwd=ctx["scratch"],
    )
    assert proc.returncode == 0, f"demo failed:\n{proc.stderr[-800:]}"
    payload = json.loads(proc.stdout)
    assert payload["fusion"]["score"] <= 10, f"unexpected score {payload['fusion']['score']}"
    assert payload["fusion"]["verdict"] == "Safe"


@check("6. Web dashboard boots headlessly")
def c_web(ctx):
    code = (
        "from fastapi.testclient import TestClient\n"
        "from src.webapp import create_app\n"
        "c = TestClient(create_app())\n"
        "assert c.get('/health').json()['status'] == 'ok'\n"
        "print('WEB_OK')\n"
    )
    proc = run([ctx["python"], "-c", code], cwd=ctx["scratch"])
    assert proc.returncode == 0 and "WEB_OK" in proc.stdout, (
        f"web boot failed:\n{proc.stderr[-600:]}"
    )


@check("7. GUI toolkit availability (python3-tk system package)")
def c_gui(ctx):
    proc = run([ctx["python"], "-c", "import tkinter"], cwd=ctx["scratch"])
    if proc.returncode != 0:
        print(
            "      note: tkinter unavailable — install the OS package "
            "(e.g. `sudo apt install python3-tk`) for the desktop GUI. "
            "CLI/Web/tests are unaffected."
        )
        return SKIP


@check("8. Full test suite in the fresh environment")
def c_tests(ctx):
    if ctx["quick"]:
        return SKIP
    proc = run([ctx["python"], "-m", "pytest", "tests/", "-q"], cwd=ROOT_DIR, timeout=3000)
    tail = "\n".join(proc.stdout.splitlines()[-4:])
    assert proc.returncode == 0, f"pytest failed:\n{tail}\n{proc.stderr[-400:]}"


@check("9. Demo-day smoke check (demo_check.py)")
def c_demo_check(ctx):
    if ctx["quick"]:
        return SKIP
    proc = run([ctx["python"], "scripts/demo_check.py"], cwd=ROOT_DIR, timeout=1200)
    tail = "\n".join(proc.stdout.splitlines()[-6:])
    assert proc.returncode == 0, f"demo_check failed:\n{tail}"


def main() -> int:
    parser = argparse.ArgumentParser(description="CAPRA fresh-machine release check")
    parser.add_argument("--quick", action="store_true", help="skip full pytest + demo_check")
    args = parser.parse_args()

    tmp = tempfile.mkdtemp(prefix="capra_release_")
    ctx = {
        "venv": os.path.join(tmp, "venv"),
        "scratch": os.path.join(tmp, "scratch"),
        "quick": args.quick,
    }
    os.makedirs(ctx["scratch"], exist_ok=True)
    bin_dir = os.path.join(ctx["venv"], "bin")
    ctx["python"] = os.path.join(bin_dir, "python")
    ctx["pip"] = os.path.join(bin_dir, "pip")
    ctx["capra"] = os.path.join(bin_dir, "capra")

    print("=" * 78)
    print("  CAPRA 2.0 — FRESH-MACHINE RELEASE CHECK")
    print(f"  scratch dir: {tmp}")
    print("=" * 78)

    failed = 0
    skipped = 0
    try:
        for name, func in RESULTS:
            try:
                result = func(ctx)
                status = SKIP if result == SKIP else "PASS"
                if status == SKIP:
                    skipped += 1
            except Exception as e:
                status = f"FAIL  ({type(e).__name__}: {e})"
                failed += 1
            print(f"  [{status:>4}]  {name}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("-" * 78)
    total = len(RESULTS)
    print(
        f"  {total - failed - skipped} passed, {failed} failed, {skipped} skipped / {total} checks"
    )
    if failed:
        print("\n  RELEASE CHECK FAILED — fix before tagging.")
        return 1
    print("\n  FRESH-MACHINE INSTALL VERIFIED — ready for release. 🚀")
    return 0


if __name__ == "__main__":
    sys.exit(main())
