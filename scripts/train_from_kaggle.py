#!/usr/bin/env python
"""Train CAPRA's ML model on real Kaggle datasets (e.g. Android_Malware_Benign.csv).

This is the standard training entry point for real-world datasets such as:
  * Android_Malware_Benign.csv   (malware + benign apps with permission columns)
  * Android_Permission.csv       (Kaggle Android permissions datasets)
  * Drebin / CIC-AndMal extracts converted to CSV

Expected schema (all handled automatically):
  * One row per app
  * Permission columns in short form (READ_SMS) or full form (android.permission.READ_SMS)
  * A label column such as class / label / malware / type with values like
    malware|benign, 1|0, M|B, malicious|benign
  * Metadata columns (pkgname, 'App categore', Downloads, ...) are ignored

Usage:
    python scripts/train_from_kaggle.py                     # auto-scan data/datasets/*.csv
    python scripts/train_from_kaggle.py path/to/file.csv    # explicit file(s)
    python scripts/train_from_kaggle.py --scan-only         # inspect schemas without training
"""

from __future__ import annotations

import argparse
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import pandas as pd

from src.ml_pipeline import (
    DEFAULT_DATASETS_DIR,
    PermissionMLPipeline,
    detect_label_column,
    normalize_permission_column,
)


def report_schema(path: str) -> bool:
    """Print a schema report for one CSV. Returns True if the file is labelled."""
    print(f"\n{'-' * 78}")
    print(f"FILE: {os.path.basename(path)}")
    try:
        df = pd.read_csv(path)
    except Exception as e:
        print(f"  [ERROR] Could not parse CSV: {e}")
        return False

    print(f"  Rows: {len(df)}   Columns: {len(df.columns)}")

    label_col = detect_label_column(df)
    perm_cols = [c for c in df.columns if normalize_permission_column(c) is not None]
    meta_cols = [
        c for c in df.columns
        if normalize_permission_column(c) is None and c != label_col
    ]

    print(f"  Permission features detected: {len(perm_cols)}")
    if meta_cols:
        print(f"  Ignored metadata/intent/aggregate columns: {len(meta_cols)} "
              f"(e.g. {', '.join(str(c).strip() for c in meta_cols[:4])}...)")

    if label_col is None:
        print("  Label column: [NOT FOUND]  -> file will be SKIPPED for training.")
        print("    Tip: supervised training needs a 'class'/'label' column with")
        print("    malware/benign (or 1/0) values. This file looks like an")
        print("    unlabelled permission dump (useful for context baselines, not training).")
        return False

    counts = df[label_col].astype(str).str.strip().str.lower().value_counts().to_dict()
    print(f"  Label column: '{str(label_col).strip()}'  values: {counts}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train CAPRA's ML model on real Kaggle/Drebin/CIC CSV datasets.",
    )
    parser.add_argument(
        "datasets",
        nargs="*",
        default=None,
        help="CSV file(s) to train on. Defaults to scanning data/datasets/*.csv.",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Only report each file's schema and label detection; do not train.",
    )
    args = parser.parse_args()

    if args.datasets:
        files = args.datasets
    else:
        files = sorted(
            os.path.join(DEFAULT_DATASETS_DIR, f)
            for f in os.listdir(DEFAULT_DATASETS_DIR)
            if f.lower().endswith(".csv")
        ) if os.path.isdir(DEFAULT_DATASETS_DIR) else []

    if not files:
        print(f"No CSV datasets found. Place your Kaggle CSVs in '{DEFAULT_DATASETS_DIR}/' "
              f"or pass explicit paths.")
        sys.exit(1)

    print("CAPRA - Real Dataset Schema Report")
    print(f"Scanning {len(files)} CSV file(s)...")

    labelled = [f for f in files if report_schema(f)]

    print(f"\n{'=' * 78}")
    if not labelled:
        print("RESULT: no labelled dataset found - nothing to train on.")
        print("The classifier needs at least one CSV with a malware/benign label column.")
        print("Example: unzip Android_Malware_Benign.csv.zip and copy the CSV here:")
        print(f"    {DEFAULT_DATASETS_DIR}/")
        sys.exit(1)

    print(f"RESULT: {len(labelled)} labelled dataset(s) ready for training.")
    if args.scan_only:
        print("(--scan-only: training skipped)")
        return

    print("\nTraining... (Random Forest vs Gradient Boosting, 5-fold stratified CV)")
    pipeline = PermissionMLPipeline(dataset_path=files, force_retrain=True)
    import joblib
    saved = joblib.load(pipeline.model_path)
    metrics = saved.get("metrics", {}) if isinstance(saved, dict) else {}

    print(f"\n{'=' * 78}")
    print("TRAINING COMPLETE")
    print(f"  Winning model : {pipeline.model_name}")
    print(f"  Data source   : {pipeline.data_source}")
    print(f"  Features      : {len(pipeline.features)} permission columns")
    for name, m in metrics.get("models", {}).items():
        print(f"  {name}: acc={m.get('accuracy_mean', 0):.4f}  "
              f"f1={m.get('f1_mean', 0):.4f}  auc={m.get('roc_auc_mean', 0):.4f}")
    print(f"\n  Model saved to  : {pipeline.model_path}")
    print(f"                  : data/models/best_model.joblib")
    print("  Eval report     : reports/evaluation_metrics.md, reports/model_comparison.json")
    print("  Charts          : reports/confusion_matrix.png, reports/roc_curve.png, "
          "reports/feature_importance.png")
    if saved.get("is_synthetic"):
        print("\n  [!] WARNING: model was trained on SYNTHETIC fallback data.")
    elif len(saved.get("features", [])) and saved.get("n_samples", 0) < 200:
        print("\n  [!] NOTE: small sample size - treat metrics as illustrative.")


if __name__ == "__main__":
    main()
