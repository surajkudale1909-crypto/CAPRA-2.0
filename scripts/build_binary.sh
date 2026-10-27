#!/usr/bin/env bash
# =============================================================================
# CAPRA 2.0 — one-file demo binary build (PyInstaller)
#
# Produces dist/capra — a self-contained executable for demo-day machines that
# should not need a Python environment.
#
# Prerequisites (one-time, needs root):
#   - Debian/Ubuntu:  sudo apt install libpython3.11   # or libpython3.XX for
#                       the exact Python version used to build (PyInstaller
#                       needs the shared library, not just the interpreter)
#   - pip install pyinstaller
#
# Known gotchas (already handled in capra.spec):
#   - androguard's `pentest` subpackage calls exit() at import time and breaks
#     PyInstaller collection -> excluded explicitly in capra.spec.
#   - sklearn/numpy/joblib pickles need their estimators traced -> they are
#     imported statically via src.ml_pipeline, normally detected; if a target
#     machine errors on unpickling, add --collect-all sklearn.
#
# Smoke-test the result before the demo:
#   ./dist/capra --help
#   ./dist/capra --demo malicious_flashlight --no-history
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c "import sys, sysconfig, os; p = sysconfig.get_config_var('LIBDIR'); n = sysconfig.get_config_var('INSTSONAME'); ok = p and n and os.path.exists(os.path.join(p, n)); sys.exit(0 if ok else 1)"; then
    echo "ERROR: Python shared library not found for '$PYTHON'."
    echo "PyInstaller needs it to freeze the interpreter. On Debian/Ubuntu:"
    echo "    sudo apt install libpython3.11      # match your Python minor version"
    echo "Then re-run this script."
    exit 1
fi

if ! "$PYTHON" -c "import PyInstaller" 2>/dev/null; then
    echo "Installing PyInstaller (build-time only, not a runtime dependency)..."
    "$PYTHON" -m pip install -q pyinstaller
fi

echo "Building one-file binary (this takes a few minutes)..."
# capra.spec is the checked-in build config (onefile, androguard.pentest excluded)
"$PYTHON" -m PyInstaller capra.spec --clean --noconfirm

echo
echo "Smoke-testing dist/capra ..."
./dist/capra --help >/dev/null
./dist/capra --demo benign_calculator --json --no-history | "$PYTHON" -c "import json,sys; d=json.load(sys.stdin); assert d['fusion']['verdict']=='Safe', d['fusion']; print('demo smoke: Safe', d['fusion']['score'], '/100')"
echo
ls -lh dist/capra
echo
echo "Binary ready: dist/capra  (do NOT commit it — attach to a GitHub Release)"
