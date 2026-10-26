"""Machine Learning Permission Risk Pipeline.

Ishan's Module (EDAI Group 8 - CAPRA v2).
Trains Scikit-Learn classifiers (Random Forest and Gradient Boosting) on Android
permission feature vectors, evaluates them using Stratified K-Fold Cross Validation,
computes risk probabilities (0.0 to 1.0), and provides per-prediction local feature
explainability. Supports real labelled datasets (Drebin / CIC-AndMal / Kaggle formats)
with explicit SYNTHETIC fallback indicators.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib

# Ensure Matplotlib operates headlessly
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold

from src.config import settings

logger = logging.getLogger("capra.ml")

# Standard vocabulary of 32 sensitive & common Android permissions
FEATURE_PERMISSIONS: List[str] = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BODY_SENSORS",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.NFC",
]

DEFAULT_MODEL_DIR = str(settings.models_dir)
DEFAULT_MODEL_FILE = str(settings.model_path)
DEFAULT_DATASETS_DIR = os.path.join(str(settings.data_dir), "datasets")
DEFAULT_REPORTS_DIR = str(settings.reports_dir)


def generate_synthetic_training_dataset(
    n_samples: int = 1200,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """Generate a realistic synthetic dataset modeling benign vs. malicious permission patterns.

    Grounding:
    - Benign apps typically request 1-5 functional permissions without exfiltration combinations.
    - Malicious apps heavily over-request dangerous combinations:
      (INTERNET + SMS, INTERNET + CONTACTS, INTERNET + AUDIO, INTERNET + STORAGE, BOOT_COMPLETED).
    """
    rng = np.random.RandomState(random_state)
    n_features = len(FEATURE_PERMISSIONS)
    X = np.zeros((n_samples, n_features), dtype=np.int32)
    y = np.zeros(n_samples, dtype=np.int32)

    perm_idx = {p: i for i, p in enumerate(FEATURE_PERMISSIONS)}
    half = n_samples // 2

    # 1. Synthesize Benign Samples (Class 0)
    for i in range(half):
        archetype = rng.choice(["calc", "torch", "nav", "offline_utility", "simple_game"])
        if archetype == "calc":
            active = ["android.permission.VIBRATE"]
        elif archetype == "torch":
            active = ["android.permission.CAMERA", "android.permission.WAKE_LOCK"]
        elif archetype == "nav":
            active = [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
            ]
        elif archetype == "offline_utility":
            active = ["android.permission.VIBRATE", "android.permission.WAKE_LOCK"]
        else:
            active = [
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.VIBRATE",
            ]

        for p in active:
            if p in perm_idx:
                X[i, perm_idx[p]] = 1

        if rng.rand() < 0.15:
            rand_p = rng.choice(
                ["android.permission.ACCESS_WIFI_STATE", "android.permission.BLUETOOTH"]
            )
            X[i, perm_idx[rand_p]] = 1

        y[i] = 0

    # 2. Synthesize Malicious / High-Risk Samples (Class 1)
    for i in range(half, n_samples):
        malware_type = rng.choice(["banking_trojan", "spyware", "adware_fraud", "ransomware"])
        if malware_type == "banking_trojan":
            active = [
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.READ_PHONE_STATE",
            ]
        elif malware_type == "spyware":
            active = [
                "android.permission.INTERNET",
                "android.permission.READ_CONTACTS",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.CAMERA",
                "android.permission.READ_EXTERNAL_STORAGE",
            ]
        elif malware_type == "adware_fraud":
            active = [
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.READ_PHONE_STATE",
                "android.permission.ACCESS_FINE_LOCATION",
            ]
        else:
            active = [
                "android.permission.INTERNET",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
            ]

        for p in active:
            if p in perm_idx:
                X[i, perm_idx[p]] = 1

        if rng.rand() < 0.3:
            rand_extra = rng.choice(FEATURE_PERMISSIONS)
            X[i, perm_idx[rand_extra]] = 1

        y[i] = 1

    return X, y


# ---------------------------------------------------------------------------
# Dataset schema handling (real Kaggle / Drebin / CIC-AndMal style CSVs)
# ---------------------------------------------------------------------------

#: Columns that describe the app, not its permission footprint
METADATA_COLUMNS = {
    "pkgname",
    "package",
    "package name",
    "package_name",
    "app name",
    "app_name",
    "app",
    "name",
    "downloads",
    "app categore",
    "app category",
    "app_category",
    "category",
    "index",
    "unnamed: 0",
    "id",
    "md5",
    "sha1",
    "sha256",
}

#: Aggregate Android permission-group columns (derived summaries, not real permissions)
AGGREGATE_GROUP_COLUMNS = {
    "CALENDAR",
    "CONTACTS",
    "LOCATION",
    "MICROPHONE",
    "PHONE",
    "SENSORS",
    "SMS",
    "STORAGE",
}

#: Known label column names (case-insensitive, first match wins)
LABEL_COLUMN_CANDIDATES = (
    "class",
    "label",
    "result",
    "malware",
    "is_malicious",
    "type",
    "verdict",
    "target",
    "y",
)

#: Canonical label values accepted for the positive (malware) class
LABEL_ONE_VALUES = {
    "1",
    "malware",
    "malicious",
    "m",
    "s",
    "suspect",
    "suspicious",
    "true",
    "yes",
    "bad",
    "dangerous",
    "trojan",
    "adware",
    "riskware",
    "pua",
}

#: Canonical label values accepted for the negative (benign) class
LABEL_ZERO_VALUES = {"0", "benign", "b", "good", "false", "no", "clean", "normal"}

#: Word-style label values (used to distinguish real labels from plain 0/1 feature columns)
WORD_LABEL_VALUES = (LABEL_ONE_VALUES | LABEL_ZERO_VALUES) - {"0", "1"}

#: The bundled toy dataset is ignored automatically when real labelled data exists
TOY_DATASET_NAME = "sample_android_malware_dataset.csv"


def normalize_permission_column(col: str) -> Optional[str]:
    """Map a raw CSV column name to canonical ``android.permission.*`` form.

    Handles both short (``READ_SMS``) and full (``android.permission.READ_SMS``)
    styles used across Kaggle/Drebin/CIC datasets. Returns None for metadata,
    intent-action, provider, and aggregate permission-group columns.
    """
    c = str(col).strip()
    if c.lower() in METADATA_COLUMNS:
        return None
    if c.startswith("android.permission."):
        return c
    if "." in c:
        # Intent actions (android.intent.action.*), providers, and pandas-deduped
        # aggregate columns such as 'CAMERA.1' are not manifest permissions.
        return None
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", c) and c not in AGGREGATE_GROUP_COLUMNS:
        return "android.permission." + c
    return None


def normalize_permission_name(perm: str) -> str:
    """Normalize any permission string to canonical ``android.permission.*`` form."""
    p = str(perm).strip()
    if p.startswith("android.permission."):
        return p
    if "." not in p:
        return "android.permission." + p
    return p


def detect_label_column(df: pd.DataFrame) -> Optional[str]:
    """Locate the malware/benign label column of a dataset, if one exists."""
    stripped = {str(c).strip().lower(): c for c in df.columns}
    for cand in LABEL_COLUMN_CANDIDATES:
        if cand in stripped:
            return stripped[cand]
    # Heuristic fallback: a small-cardinality column whose values are label words.
    # Feature-like columns (permissions, intents, aggregate groups, plain 0/1 flags)
    # are excluded so binary feature columns are never mistaken for the label.
    for col in df.columns:
        if normalize_permission_column(col) is not None:
            continue
        col_str = str(col).strip()
        if (
            col_str in AGGREGATE_GROUP_COLUMNS
            or "." in col_str
            or col_str.lower().startswith("android.")
        ):
            continue
        values = {str(v).strip().lower() for v in df[col].dropna().unique()}
        if (
            2 <= len(values) <= 6
            and values <= (LABEL_ONE_VALUES | LABEL_ZERO_VALUES)
            and (values & WORD_LABEL_VALUES)  # must contain a word-style label, not just 0/1
        ):
            return col
    return None


def _encode_labels(raw_labels: Any, source: str) -> np.ndarray:
    """Map raw label values to a binary 0/1 numpy array with strict validation."""
    y = np.zeros(len(raw_labels), dtype=np.int32)
    unknown = 0
    for i, val in enumerate(raw_labels):
        v = str(val).strip().lower()
        if v in LABEL_ONE_VALUES:
            y[i] = 1
        elif v in LABEL_ZERO_VALUES:
            y[i] = 0
        else:
            unknown += 1
            y[i] = 0
    if unknown:
        msg = (
            f"{unknown}/{len(raw_labels)} unrecognised label value(s) in {source} "
            f"were treated as benign (0)."
        )
        if unknown / max(1, len(raw_labels)) > 0.1:
            raise ValueError(msg + " Refusing to train on ambiguous labels.")
        logger.warning(msg)
    return y


def _resolve_dataset_files(custom_dataset_path: Optional[Union[str, List[str]]]) -> List[str]:
    """Resolve the candidate CSV file list from a path, list, directory, or default."""
    if custom_dataset_path is None:
        if os.path.isdir(DEFAULT_DATASETS_DIR):
            return [
                os.path.join(DEFAULT_DATASETS_DIR, f)
                for f in sorted(os.listdir(DEFAULT_DATASETS_DIR))
                if f.lower().endswith(".csv")
            ]
        return []
    if isinstance(custom_dataset_path, (list, tuple)):
        return [str(p) for p in custom_dataset_path]
    if os.path.isdir(custom_dataset_path):
        return [
            os.path.join(custom_dataset_path, f)
            for f in sorted(os.listdir(custom_dataset_path))
            if f.lower().endswith(".csv")
        ]
    return [str(custom_dataset_path)]


def load_dataset(
    custom_dataset_path: Optional[Union[str, List[str]]] = None,
) -> Tuple[np.ndarray, np.ndarray, str, str, List[str]]:
    """Load real labelled dataset(s) or return clearly marked synthetic fallback data.

    Accepts real-world Kaggle/Drebin/CIC style CSVs:
      * short (``READ_SMS``) or full (``android.permission.READ_SMS``) permission names
      * metadata columns (``pkgname``, ``App categore``, ``Downloads``, ...) are ignored
      * the label column is auto-detected (class / label / malware / type / ...)
      * all labelled CSVs found are concatenated over the union of their permissions
      * CSVs without a label column are skipped with an explanatory warning

    Returns:
        (X, y, data_source_type, source_description, feature_names) where
        feature_names are canonical full permission names aligned to X's columns.
    """
    files = _resolve_dataset_files(custom_dataset_path)

    frames: List[pd.DataFrame] = []
    label_cols: List[str] = []
    used_files: List[str] = []
    skipped: List[str] = []

    for path in files:
        if not os.path.isfile(path):
            logger.warning("Dataset file not found: %s. Skipping.", path)
            skipped.append(path)
            continue
        try:
            df = pd.read_csv(path)
        except Exception as e:
            logger.warning("Could not parse %s (%s). Skipping.", path, e)
            skipped.append(path)
            continue
        label_col = detect_label_column(df)
        if label_col is None:
            logger.warning(
                "Skipping %s: no malware/benign label column detected. "
                "Supervised training needs a class/label column (e.g. 'class' with "
                "malware/benign values).",
                os.path.basename(path),
            )
            skipped.append(path)
            continue
        frames.append(df)
        label_cols.append(label_col)
        used_files.append(path)

    # Ignore the bundled toy sample when real labelled datasets are present
    if len(used_files) > 1:
        kept = [
            (f, d, lbl)
            for f, d, lbl in zip(used_files, frames, label_cols)
            if os.path.basename(f) != TOY_DATASET_NAME
        ]
        if kept and len(kept) < len(used_files):
            logger.info(
                "Ignoring bundled toy dataset %s in favour of real labelled data.",
                TOY_DATASET_NAME,
            )
            used_files = [k[0] for k in kept]
            frames = [k[1] for k in kept]
            label_cols = [k[2] for k in kept]

    if frames:
        # Union of canonical permission columns across all labelled files.
        # Real-world datasets often contain BOTH short and full names of the same
        # permission as separate columns (e.g. ACCESS_NETWORK_STATE and
        # android.permission.ACCESS_NETWORK_STATE) - these are OR-combined.
        feature_names: List[str] = []
        seen: set = set()
        per_file_perms: List[Dict[str, List[str]]] = []
        for df in frames:
            perms: Dict[str, List[str]] = {}
            for col in df.columns:
                norm = normalize_permission_column(col)
                if norm is not None:
                    perms.setdefault(norm, []).append(col)
                    if norm not in seen:
                        seen.add(norm)
                        feature_names.append(norm)
            per_file_perms.append(perms)
        feature_names = sorted(feature_names)
        feat_index = {p: i for i, p in enumerate(feature_names)}

        blocks: List[np.ndarray] = []
        y_blocks: List[np.ndarray] = []
        for path, df, label_col, perms in zip(used_files, frames, label_cols, per_file_perms):
            Xb = np.zeros((len(df), len(feature_names)), dtype=np.int32)
            for norm, cols in perms.items():
                combined = np.zeros(len(df), dtype=np.int32)
                for col in cols:
                    combined |= (
                        (pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int) > 0)
                        .astype(np.int32)
                        .values
                    )
                Xb[:, feat_index[norm]] = combined
            blocks.append(Xb)
            y_blocks.append(_encode_labels(df[label_col].values, os.path.basename(path)))

        X = np.vstack(blocks)
        y = np.concatenate(y_blocks)

        names = ", ".join(os.path.basename(f) for f in used_files)
        source_name = f"EMPIRICAL ({names}, {len(feature_names)} features)"
        n_mal = int(sum(y == 1))
        n_ben = int(sum(y == 0))
        if len(X) < 200:
            source_name += f" [SMALL SAMPLE n={len(X)} - ILLUSTRATIVE ONLY]"
            logger.warning(
                "Dataset only has %d samples (%d malware, %d benign). Metrics on such a small "
                "sample are illustrative, NOT representative of in-the-wild accuracy. Provide a "
                "full Drebin / CIC-AndMal / Kaggle dataset for meaningful evaluation.",
                len(X),
                n_mal,
                n_ben,
            )
        logger.info(
            "Dataset successfully loaded: %d samples (%d malware, %d benign), %d permission features [%s]",
            len(X),
            n_mal,
            n_ben,
            len(feature_names),
            names,
        )
        return X, y, "EMPIRICAL", source_name, feature_names

    if skipped:
        logger.warning(
            "No labelled datasets found (files without a label column: %s).",
            ", ".join(os.path.basename(s) for s in skipped),
        )

    # Synthetic fallback (strictly labeled)
    logger.info(
        "[DATA SOURCE: SYNTHETIC (FALLBACK)] No empirical dataset loaded. Generating synthetic benchmark."
    )
    X, y = generate_synthetic_training_dataset(n_samples=1200, random_state=42)
    return X, y, "SYNTHETIC", "SYNTHETIC (Fallback Generator)", list(FEATURE_PERMISSIONS)


def compare_and_evaluate_models(
    X: np.ndarray,
    y: np.ndarray,
    data_source_label: str = "SYNTHETIC",
    reports_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Train and compare Random Forest vs Gradient Boosting with Stratified K-Fold CV.

    Exports comparison metrics, confusion matrices, ROC curves, and feature importance to reports/.
    """
    out_dir = reports_dir or DEFAULT_REPORTS_DIR
    os.makedirs(out_dir, exist_ok=True)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    rf_model = RandomForestClassifier(
        n_estimators=100, max_depth=8, random_state=42, class_weight="balanced"
    )
    gb_model = GradientBoostingClassifier(
        n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42
    )

    metrics: Dict[str, Dict[str, List[float]]] = {
        "RandomForest": {"accuracy": [], "precision": [], "recall": [], "f1": [], "roc_auc": []},
        "GradientBoosting": {
            "accuracy": [],
            "precision": [],
            "recall": [],
            "f1": [],
            "roc_auc": [],
        },
    }

    # Tracking predictions for ROC & Confusion Matrix from representative test fold
    rf_best_preds: Optional[np.ndarray] = None
    rf_best_probs: Optional[np.ndarray] = None
    gb_best_preds: Optional[np.ndarray] = None
    gb_best_probs: Optional[np.ndarray] = None
    y_test_rep: Optional[np.ndarray] = None

    for train_idx, test_idx in skf.split(X, y):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        # 1. Random Forest
        rf_model.fit(X_train, y_train)
        rf_preds = rf_model.predict(X_test)
        rf_probs = rf_model.predict_proba(X_test)[:, 1]

        metrics["RandomForest"]["accuracy"].append(float(accuracy_score(y_test, rf_preds)))
        metrics["RandomForest"]["precision"].append(
            float(precision_score(y_test, rf_preds, zero_division=0))
        )
        metrics["RandomForest"]["recall"].append(
            float(recall_score(y_test, rf_preds, zero_division=0))
        )
        metrics["RandomForest"]["f1"].append(float(f1_score(y_test, rf_preds, zero_division=0)))
        metrics["RandomForest"]["roc_auc"].append(float(roc_auc_score(y_test, rf_probs)))

        # 2. Gradient Boosting
        gb_model.fit(X_train, y_train)
        gb_preds = gb_model.predict(X_test)
        gb_probs = gb_model.predict_proba(X_test)[:, 1]

        metrics["GradientBoosting"]["accuracy"].append(float(accuracy_score(y_test, gb_preds)))
        metrics["GradientBoosting"]["precision"].append(
            float(precision_score(y_test, gb_preds, zero_division=0))
        )
        metrics["GradientBoosting"]["recall"].append(
            float(recall_score(y_test, gb_preds, zero_division=0))
        )
        metrics["GradientBoosting"]["f1"].append(float(f1_score(y_test, gb_preds, zero_division=0)))
        metrics["GradientBoosting"]["roc_auc"].append(float(roc_auc_score(y_test, gb_probs)))

        if y_test_rep is None:
            y_test_rep = y_test
            rf_best_preds = rf_preds
            rf_best_probs = rf_probs
            gb_best_preds = gb_preds
            gb_best_probs = gb_probs

    summary = {
        "data_source": data_source_label,
        "is_synthetic": "SYNTHETIC" in data_source_label,
        "n_samples": len(X),
        "cv_folds": 5,
        "models": {
            "RandomForest": {
                "accuracy_mean": round(float(np.mean(metrics["RandomForest"]["accuracy"])), 4),
                "accuracy_std": round(float(np.std(metrics["RandomForest"]["accuracy"])), 4),
                "precision_mean": round(float(np.mean(metrics["RandomForest"]["precision"])), 4),
                "recall_mean": round(float(np.mean(metrics["RandomForest"]["recall"])), 4),
                "f1_mean": round(float(np.mean(metrics["RandomForest"]["f1"])), 4),
                "roc_auc_mean": round(float(np.mean(metrics["RandomForest"]["roc_auc"])), 4),
            },
            "GradientBoosting": {
                "accuracy_mean": round(float(np.mean(metrics["GradientBoosting"]["accuracy"])), 4),
                "accuracy_std": round(float(np.std(metrics["GradientBoosting"]["accuracy"])), 4),
                "precision_mean": round(
                    float(np.mean(metrics["GradientBoosting"]["precision"])), 4
                ),
                "recall_mean": round(float(np.mean(metrics["GradientBoosting"]["recall"])), 4),
                "f1_mean": round(float(np.mean(metrics["GradientBoosting"]["f1"])), 4),
                "roc_auc_mean": round(float(np.mean(metrics["GradientBoosting"]["roc_auc"])), 4),
            },
        },
    }

    # Determine winner by F1 score
    rf_f1 = summary["models"]["RandomForest"]["f1_mean"]
    gb_f1 = summary["models"]["GradientBoosting"]["f1_mean"]
    winner = "RandomForest" if rf_f1 >= gb_f1 else "GradientBoosting"
    summary["selected_winner"] = winner

    # Export model_comparison.json
    comp_json_path = os.path.join(out_dir, "model_comparison.json")
    with open(comp_json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Export evaluation_metrics.md
    md_path = os.path.join(out_dir, "evaluation_metrics.md")
    rf_m = summary["models"]["RandomForest"]
    gb_m = summary["models"]["GradientBoosting"]
    badge = (
        "**[DATA SOURCE: SYNTHETIC (FALLBACK)]**"
        if summary["is_synthetic"]
        else f"**[DATA SOURCE: {data_source_label}]**"
    )

    md_content = f"""# CAPRA Machine Learning Evaluation Report (Phase 3)

{badge}

## Model Comparison (Stratified 5-Fold Cross Validation)

| Metric | Random Forest (RF) | Gradient Boosting (GB) | Delta |
| :--- | :---: | :---: | :---: |
| **Accuracy** | {rf_m["accuracy_mean"]:.4f} ± {rf_m["accuracy_std"]:.4f} | {gb_m["accuracy_mean"]:.4f} ± {gb_m["accuracy_std"]:.4f} | {gb_m["accuracy_mean"] - rf_m["accuracy_mean"]:+.4f} |
| **Precision** | {rf_m["precision_mean"]:.4f} | {gb_m["precision_mean"]:.4f} | {gb_m["precision_mean"] - rf_m["precision_mean"]:+.4f} |
| **Recall** | {rf_m["recall_mean"]:.4f} | {gb_m["recall_mean"]:.4f} | {gb_m["recall_mean"] - rf_m["recall_mean"]:+.4f} |
| **F1-Score** | **{rf_m["f1_mean"]:.4f}** | {gb_m["f1_mean"]:.4f} | {gb_m["f1_mean"] - rf_m["f1_mean"]:+.4f} |
| **ROC-AUC** | **{rf_m["roc_auc_mean"]:.4f}** | {gb_m["roc_auc_mean"]:.4f} | {gb_m["roc_auc_mean"] - rf_m["roc_auc_mean"]:+.4f} |

**Selected Model**: `{winner}` (Saved to `data/models/best_model.joblib`)

> Note on Validity: If trained on synthetic fallback, results reflect the rule generator rather than empirical malware distribution. Small hand-built datasets (< 200 rows) are marked ILLUSTRATIVE ONLY - cross-validation metrics on them do NOT represent in-the-wild accuracy. Place a full real Drebin or CIC-AndMal CSV in `data/datasets/` to evaluate true in-the-wild accuracy.
"""
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    # Plot Confusion Matrix
    if y_test_rep is not None and rf_best_preds is not None and gb_best_preds is not None:
        fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))
        for ax, preds, title in zip(
            axes, [rf_best_preds, gb_best_preds], ["Random Forest", "Gradient Boosting"]
        ):
            cm = confusion_matrix(y_test_rep, preds)
            im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
            ax.set_title(f"{title} Confusion Matrix", fontsize=11, fontweight="bold")
            fig.colorbar(im, ax=ax)
            classes = ["Benign", "Malware"]
            tick_marks = np.arange(len(classes))
            ax.set_xticks(tick_marks)
            ax.set_yticks(tick_marks)
            ax.set_xticklabels(classes)
            ax.set_yticklabels(classes)
            for i in range(cm.shape[0]):
                for j in range(cm.shape[1]):
                    ax.text(
                        j,
                        i,
                        format(cm[i, j], "d"),
                        ha="center",
                        va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black",
                    )
            ax.set_ylabel("True Label")
            ax.set_xlabel("Predicted Label")
        plt.tight_layout()
        cm_path = os.path.join(out_dir, "confusion_matrix.png")
        plt.savefig(cm_path, dpi=200)
        plt.close(fig)

        # Plot ROC Curve
        fig, ax = plt.subplots(figsize=(7, 5))
        rf_fpr, rf_tpr, _ = roc_curve(y_test_rep, rf_best_probs)
        gb_fpr, gb_tpr, _ = roc_curve(y_test_rep, gb_best_probs)
        ax.plot(
            rf_fpr,
            rf_tpr,
            color="#1f77b4",
            lw=2,
            label=f"Random Forest (AUC = {rf_m['roc_auc_mean']:.3f})",
        )
        ax.plot(
            gb_fpr,
            gb_tpr,
            color="#ff7f0e",
            lw=2,
            label=f"Gradient Boosting (AUC = {gb_m['roc_auc_mean']:.3f})",
        )
        ax.plot([0, 1], [0, 1], color="grey", lw=1.5, linestyle="--")
        ax.set_xlabel("False Positive Rate (1 - Specificity)")
        ax.set_ylabel("True Positive Rate (Recall)")
        ax.set_title("Receiver Operating Characteristic (ROC) Comparison", fontweight="bold")
        ax.legend(loc="lower right")
        ax.grid(alpha=0.3)
        plt.tight_layout()
        roc_path = os.path.join(out_dir, "roc_curve.png")
        plt.savefig(roc_path, dpi=200)
        plt.close(fig)

    logger.info(f"Evaluation report and comparison assets written to: {out_dir}")
    return summary


class PermissionMLPipeline:
    """Classifies Android permission vectors with explainability and model comparison."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        force_retrain: bool = False,
        dataset_path: Optional[Union[str, List[str]]] = None,
    ):
        """Initialize the ML pipeline and load or train the model."""
        self.model_path = model_path or DEFAULT_MODEL_FILE
        self.features = list(FEATURE_PERMISSIONS)
        self.perm_to_idx: Dict[str, int] = {}
        self._rebuild_index()
        self.model: Optional[Any] = None
        self.model_name: str = "RandomForest"
        self.data_source: str = "SYNTHETIC"
        self.is_synthetic: bool = True

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        if os.path.exists(self.model_path) and not force_retrain:
            self._load_model()
        else:
            self.train_and_save(dataset_path=dataset_path)

    def _rebuild_index(self) -> None:
        """Rebuild the permission->column index from the active feature vocabulary."""
        self.perm_to_idx = {normalize_permission_name(f): i for i, f in enumerate(self.features)}

    def _load_model(self) -> None:
        """Load trained model and metadata from disk."""
        try:
            saved_data = joblib.load(self.model_path)
            if isinstance(saved_data, dict):
                self.model = saved_data.get("model")
                self.features = saved_data.get("features", self.features)
                self.model_name = saved_data.get("model_name", "RandomForest")
                self.data_source = saved_data.get("data_source", "SYNTHETIC")
                self.is_synthetic = saved_data.get("is_synthetic", True)
            else:
                self.model = saved_data
                self.model_name = "RandomForest"
                self.data_source = "SYNTHETIC"
                self.is_synthetic = True
            self._rebuild_index()
            logger.info(
                f"Loaded ML model ({self.model_name}) from {self.model_path} [Source: {self.data_source}]"
            )
        except Exception as e:
            logger.warning(f"Failed to load model from {self.model_path} ({e}). Retraining...")
            self.train_and_save()

    def train_and_save(
        self, dataset_path: Optional[Union[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Train and evaluate models on real or synthetic data, saving the winner."""
        logger.info("Initializing ML training and model comparison...")
        X, y, source_type, source_desc, feature_names = load_dataset(dataset_path)

        # Adopt the dataset's permission vocabulary (dynamic for real-world schemas)
        self.features = list(feature_names)
        self._rebuild_index()

        self.data_source = source_desc
        self.is_synthetic = source_type == "SYNTHETIC"

        # Compare Random Forest vs Gradient Boosting with 5-fold CV
        eval_summary = compare_and_evaluate_models(X, y, data_source_label=source_desc)

        winner = eval_summary.get("selected_winner", "RandomForest")
        self.model_name = winner

        if winner == "GradientBoosting":
            self.model = GradientBoostingClassifier(
                n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42
            )
        else:
            self.model = RandomForestClassifier(
                n_estimators=100, max_depth=8, random_state=42, class_weight="balanced"
            )

        self.model.fit(X, y)

        model_payload = {
            "model": self.model,
            "features": self.features,
            "model_name": self.model_name,
            "data_source": self.data_source,
            "is_synthetic": self.is_synthetic,
            "metrics": eval_summary,
            "n_samples": int(len(X)),
            "class_balance": {"malware": int(sum(y == 1)), "benign": int(sum(y == 0))},
        }

        # Save primary model file and best_model.joblib
        joblib.dump(model_payload, self.model_path)
        best_path = os.path.join(os.path.dirname(self.model_path), "best_model.joblib")
        joblib.dump(model_payload, best_path)

        # Export feature importance plot
        self.export_feature_importance_plot()

        logger.info(f"Winning model ({winner}) saved to {self.model_path} and {best_path}")
        return eval_summary

    def vectorize(self, permissions: List[str]) -> np.ndarray:
        """Convert a list of requested permissions into a binary feature vector.

        Accepts full (``android.permission.X``) or short (``X``) names; unknown
        permissions are ignored (they have no trained feature column).
        """
        vec = np.zeros((1, len(self.features)), dtype=np.int32)
        for p in permissions:
            key = normalize_permission_name(p)
            idx = self.perm_to_idx.get(key, self.perm_to_idx.get(p))
            if idx is not None:
                vec[0, idx] = 1
        return vec

    def predict_risk(self, requested_permissions: List[str]) -> Dict[str, Any]:
        """Perform risk inference with per-prediction feature contributions."""
        if self.model is None:
            raise RuntimeError("Model is not loaded or trained.")

        vec = self.vectorize(requested_permissions)
        proba = self.model.predict_proba(vec)[0]
        # Locate the malicious/positive class robustly (do not assume label ordering)
        classes = list(getattr(self.model, "classes_", [0, 1]))
        if 1 in classes:
            positive_idx = classes.index(1)
        else:
            positive_idx = len(classes) - 1
        malicious_prob = float(proba[positive_idx]) if len(proba) > 1 else float(proba[0])
        pred_label = int(self.model.predict(vec)[0])

        active_perms = []
        seen_cols: set = set()
        for p in requested_permissions:
            key = normalize_permission_name(p)
            idx = self.perm_to_idx.get(key, self.perm_to_idx.get(p))
            if idx is not None and idx not in seen_cols:
                active_perms.append(key)
                seen_cols.add(idx)
        importances = getattr(
            self.model, "feature_importances_", np.ones(len(self.features)) / len(self.features)
        )

        # Per-prediction local explainability: directional risk contribution
        ranked_active = []
        for p in active_perms:
            idx = self.perm_to_idx[p]
            short_name = p.replace("android.permission.", "")
            imp = float(importances[idx])
            # Directional weight: active dangerous permissions increment risk probability
            contrib_pct = round(imp * malicious_prob * 100, 2)
            ranked_active.append(
                {
                    "permission": p,
                    "short_name": short_name,
                    "importance_score": round(imp, 4),
                    "risk_contribution_pct": contrib_pct,
                    "influence": "INCREASES_RISK" if malicious_prob >= 0.40 else "BENIGN_PROFILE",
                }
            )
        ranked_active.sort(key=lambda x: x["importance_score"], reverse=True)

        verdict_str = "High Risk / Anomaly" if malicious_prob >= 0.50 else "Benign Profile"

        return {
            "risk_probability": round(malicious_prob, 4),
            "risk_percentage": round(malicious_prob * 100, 1),
            "predicted_class": pred_label,
            "ml_verdict": verdict_str,
            "model_type": self.model_name,
            "data_source": self.data_source,
            "is_synthetic": self.is_synthetic,
            "active_feature_count": len(active_perms),
            "top_contributing_permissions": ranked_active[:5],
        }

    def export_feature_importance_plot(
        self,
        output_path: Optional[str] = None,
        top_n: int = 10,
    ) -> str:
        """Generate and save horizontal bar chart of top decision features."""
        if self.model is None:
            raise RuntimeError("Model is not initialized.")

        if output_path is None:
            output_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "data", "feature_importance.png")
            )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        importances = getattr(self.model, "feature_importances_", None)
        if importances is None:
            return output_path

        indices = np.argsort(importances)[::-1][:top_n]
        top_names = [self.features[i].replace("android.permission.", "") for i in indices]
        top_scores = [float(importances[i]) for i in indices]

        top_names.reverse()
        top_scores.reverse()

        fig, ax = plt.subplots(figsize=(9, 5.5))
        bars = ax.barh(top_names, top_scores, color="#2b5c8f", edgecolor="#1a365d")

        for i in range(max(0, len(bars) - 3), len(bars)):
            bars[i].set_color("#d9534f")

        ax.set_xlabel(
            "Relative Feature Importance (Gini / Split Gain)", fontsize=11, fontweight="bold"
        )
        badge = "[SYNTHETIC FALLBACK]" if self.is_synthetic else f"[{self.data_source}]"
        ax.set_title(
            f"{self.model_name} Top {top_n} Decision Features\n{badge}",
            fontsize=12,
            fontweight="bold",
            pad=15,
        )
        ax.grid(axis="x", linestyle="--", alpha=0.6)

        for bar in bars:
            width = bar.get_width()
            ax.text(
                width + 0.005,
                bar.get_y() + bar.get_height() / 2,
                f"{width:.3f}",
                ha="left",
                va="center",
                fontsize=9,
            )

        plt.tight_layout()
        plt.savefig(output_path, dpi=200)

        # Also copy to reports/feature_importance.png
        reports_copy = os.path.join(DEFAULT_REPORTS_DIR, "feature_importance.png")
        os.makedirs(DEFAULT_REPORTS_DIR, exist_ok=True)
        plt.savefig(reports_copy, dpi=200)

        plt.close(fig)
        logger.info(f"Feature importance plot exported to: {output_path} and {reports_copy}")
        return output_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CAPRA Machine Learning Pipeline")
    parser.add_argument(
        "--train", action="store_true", help="Train models and perform Stratified CV"
    )
    parser.add_argument("--dataset", type=str, default=None, help="Path to real CSV dataset")
    parser.add_argument("--plot", action="store_true", help="Generate feature importance plot")
    args = parser.parse_args()

    pipeline = PermissionMLPipeline(force_retrain=args.train, dataset_path=args.dataset)
    if args.plot:
        pipeline.export_feature_importance_plot()

    # Demo inference
    test_perms = [
        "android.permission.INTERNET",
        "android.permission.READ_CONTACTS",
        "android.permission.RECORD_AUDIO",
    ]
    res = pipeline.predict_risk(test_perms)
    print("\nSample Inference Result:")
    print(json.dumps(res, indent=2))
