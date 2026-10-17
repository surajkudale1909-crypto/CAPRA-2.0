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
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

# Ensure Matplotlib operates headlessly
import matplotlib
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
            rand_p = rng.choice(["android.permission.ACCESS_WIFI_STATE", "android.permission.BLUETOOTH"])
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


def load_dataset(
    custom_dataset_path: Optional[str] = None,
) -> Tuple[np.ndarray, np.ndarray, str, str]:
    """Load real labelled dataset or return clearly marked synthetic fallback data.

    Returns:
        (X, y, data_source_type, source_description)
    """
    candidate_path = custom_dataset_path

    # If no custom path provided, check data/datasets for any .csv
    if not candidate_path and os.path.isdir(DEFAULT_DATASETS_DIR):
        csv_files = [
            os.path.join(DEFAULT_DATASETS_DIR, f)
            for f in os.listdir(DEFAULT_DATASETS_DIR)
            if f.lower().endswith(".csv")
        ]
        if csv_files:
            candidate_path = sorted(csv_files)[0]

    # Try loading real CSV
    if candidate_path and os.path.isfile(candidate_path):
        try:
            logger.info(f"Loading real empirical dataset from: {candidate_path}")
            df = pd.read_csv(candidate_path)

            # Locate label column
            label_col = None
            for col in ["class", "label", "Result", "malware", "is_malicious", "type"]:
                if col in df.columns:
                    label_col = col
                    break

            if label_col is None:
                raise ValueError(f"Could not find a valid label column in {candidate_path}")

            # Normalize labels to binary 0 / 1
            raw_labels = df[label_col].values
            y = np.zeros(len(raw_labels), dtype=np.int32)
            for i, val in enumerate(raw_labels):
                if str(val).strip().lower() in ("1", "malware", "s", "malicious", "true"):
                    y[i] = 1
                else:
                    y[i] = 0

            # Build feature matrix for FEATURE_PERMISSIONS
            n_features = len(FEATURE_PERMISSIONS)
            X = np.zeros((len(df), n_features), dtype=np.int32)

            for feat_idx, perm in enumerate(FEATURE_PERMISSIONS):
                short_perm = perm.replace("android.permission.", "")
                matched_col = None
                if perm in df.columns:
                    matched_col = perm
                elif short_perm in df.columns:
                    matched_col = short_perm

                if matched_col:
                    X[:, feat_idx] = pd.to_numeric(df[matched_col], errors="coerce").fillna(0).astype(int)

            source_name = f"EMPIRICAL ({os.path.basename(candidate_path)})"
            logger.info(f"Dataset successfully loaded: {len(X)} samples ({sum(y == 1)} malware, {sum(y == 0)} benign)")
            return X, y, "EMPIRICAL", source_name

        except Exception as e:
            logger.warning(f"Failed to load dataset at {candidate_path} ({e}). Falling back to synthetic.")

    # Synthetic fallback (strictly labeled)
    logger.info("[DATA SOURCE: SYNTHETIC (FALLBACK)] No empirical dataset loaded. Generating synthetic benchmark.")
    X, y = generate_synthetic_training_dataset(n_samples=1200, random_state=42)
    return X, y, "SYNTHETIC", "SYNTHETIC (Fallback Generator)"


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

    rf_model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight="balanced")
    gb_model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42)

    metrics: Dict[str, Dict[str, List[float]]] = {
        "RandomForest": {"accuracy": [], "precision": [], "recall": [], "f1": [], "roc_auc": []},
        "GradientBoosting": {"accuracy": [], "precision": [], "recall": [], "f1": [], "roc_auc": []},
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
        metrics["RandomForest"]["precision"].append(float(precision_score(y_test, rf_preds, zero_division=0)))
        metrics["RandomForest"]["recall"].append(float(recall_score(y_test, rf_preds, zero_division=0)))
        metrics["RandomForest"]["f1"].append(float(f1_score(y_test, rf_preds, zero_division=0)))
        metrics["RandomForest"]["roc_auc"].append(float(roc_auc_score(y_test, rf_probs)))

        # 2. Gradient Boosting
        gb_model.fit(X_train, y_train)
        gb_preds = gb_model.predict(X_test)
        gb_probs = gb_model.predict_proba(X_test)[:, 1]

        metrics["GradientBoosting"]["accuracy"].append(float(accuracy_score(y_test, gb_preds)))
        metrics["GradientBoosting"]["precision"].append(float(precision_score(y_test, gb_preds, zero_division=0)))
        metrics["GradientBoosting"]["recall"].append(float(recall_score(y_test, gb_preds, zero_division=0)))
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
                "precision_mean": round(float(np.mean(metrics["GradientBoosting"]["precision"])), 4),
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
    badge = "**[DATA SOURCE: SYNTHETIC (FALLBACK)]**" if summary["is_synthetic"] else f"**[DATA SOURCE: {data_source_label}]**"

    md_content = f"""# CAPRA Machine Learning Evaluation Report (Phase 3)

{badge}

## Model Comparison (Stratified 5-Fold Cross Validation)

| Metric | Random Forest (RF) | Gradient Boosting (GB) | Delta |
| :--- | :---: | :---: | :---: |
| **Accuracy** | {rf_m['accuracy_mean']:.4f} ± {rf_m['accuracy_std']:.4f} | {gb_m['accuracy_mean']:.4f} ± {gb_m['accuracy_std']:.4f} | {gb_m['accuracy_mean'] - rf_m['accuracy_mean']:+.4f} |
| **Precision** | {rf_m['precision_mean']:.4f} | {gb_m['precision_mean']:.4f} | {gb_m['precision_mean'] - rf_m['precision_mean']:+.4f} |
| **Recall** | {rf_m['recall_mean']:.4f} | {gb_m['recall_mean']:.4f} | {gb_m['recall_mean'] - rf_m['recall_mean']:+.4f} |
| **F1-Score** | **{rf_m['f1_mean']:.4f}** | {gb_m['f1_mean']:.4f} | {gb_m['f1_mean'] - rf_m['f1_mean']:+.4f} |
| **ROC-AUC** | **{rf_m['roc_auc_mean']:.4f}** | {gb_m['roc_auc_mean']:.4f} | {gb_m['roc_auc_mean'] - rf_m['roc_auc_mean']:+.4f} |

**Selected Model**: `{winner}` (Saved to `data/models/best_model.joblib`)

> Note on Validity: If trained on synthetic fallback, results reflect the rule generator rather than empirical malware distribution. Place real Drebin or CIC-AndMal CSV files in `data/datasets/` to evaluate true in-the-wild accuracy.
"""
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    # Plot Confusion Matrix
    if y_test_rep is not None and rf_best_preds is not None and gb_best_preds is not None:
        fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))
        for ax, preds, title in zip(axes, [rf_best_preds, gb_best_preds], ["Random Forest", "Gradient Boosting"]):
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
                    ax.text(j, i, format(cm[i, j], "d"), ha="center", va="center",
                            color="white" if cm[i, j] > cm.max() / 2 else "black")
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
        ax.plot(rf_fpr, rf_tpr, color="#1f77b4", lw=2, label=f"Random Forest (AUC = {rf_m['roc_auc_mean']:.3f})")
        ax.plot(gb_fpr, gb_tpr, color="#ff7f0e", lw=2, label=f"Gradient Boosting (AUC = {gb_m['roc_auc_mean']:.3f})")
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
        dataset_path: Optional[str] = None,
    ):
        """Initialize the ML pipeline and load or train the model."""
        self.model_path = model_path or DEFAULT_MODEL_FILE
        self.features = list(FEATURE_PERMISSIONS)
        self.perm_to_idx = {p: i for i, p in enumerate(self.features)}
        self.model: Optional[Any] = None
        self.model_name: str = "RandomForest"
        self.data_source: str = "SYNTHETIC"
        self.is_synthetic: bool = True

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        if os.path.exists(self.model_path) and not force_retrain:
            self._load_model()
        else:
            self.train_and_save(dataset_path=dataset_path)

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
            logger.info(f"Loaded ML model ({self.model_name}) from {self.model_path} [Source: {self.data_source}]")
        except Exception as e:
            logger.warning(f"Failed to load model from {self.model_path} ({e}). Retraining...")
            self.train_and_save()

    def train_and_save(self, dataset_path: Optional[str] = None) -> Dict[str, Any]:
        """Train and evaluate models on real or synthetic data, saving the winner."""
        logger.info("Initializing ML training and model comparison...")
        X, y, source_type, source_desc = load_dataset(dataset_path)

        self.data_source = source_desc
        self.is_synthetic = (source_type == "SYNTHETIC")

        # Compare Random Forest vs Gradient Boosting with 5-fold CV
        eval_summary = compare_and_evaluate_models(
            X, y, data_source_label=source_desc
        )

        winner = eval_summary.get("selected_winner", "RandomForest")
        self.model_name = winner

        if winner == "GradientBoosting":
            self.model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42)
        else:
            self.model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight="balanced")

        self.model.fit(X, y)

        model_payload = {
            "model": self.model,
            "features": self.features,
            "model_name": self.model_name,
            "data_source": self.data_source,
            "is_synthetic": self.is_synthetic,
            "metrics": eval_summary,
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
        """Convert a list of requested permissions into a binary feature vector."""
        vec = np.zeros((1, len(self.features)), dtype=np.int32)
        for p in permissions:
            if p in self.perm_to_idx:
                vec[0, self.perm_to_idx[p]] = 1
        return vec

    def predict_risk(self, requested_permissions: List[str]) -> Dict[str, Any]:
        """Perform risk inference with per-prediction feature contributions."""
        if self.model is None:
            raise RuntimeError("Model is not loaded or trained.")

        vec = self.vectorize(requested_permissions)
        proba = self.model.predict_proba(vec)[0]
        malicious_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        pred_label = int(self.model.predict(vec)[0])

        active_perms = [p for p in requested_permissions if p in self.perm_to_idx]
        importances = getattr(self.model, "feature_importances_", np.ones(len(self.features)) / len(self.features))

        # Per-prediction local explainability: directional risk contribution
        ranked_active = []
        for p in active_perms:
            idx = self.perm_to_idx[p]
            short_name = p.replace("android.permission.", "")
            imp = float(importances[idx])
            # Directional weight: active dangerous permissions increment risk probability
            contrib_pct = round(imp * malicious_prob * 100, 2)
            ranked_active.append({
                "permission": p,
                "short_name": short_name,
                "importance_score": round(imp, 4),
                "risk_contribution_pct": contrib_pct,
                "influence": "INCREASES_RISK" if malicious_prob >= 0.40 else "BENIGN_PROFILE",
            })
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

        ax.set_xlabel("Relative Feature Importance (Gini / Split Gain)", fontsize=11, fontweight="bold")
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
    parser.add_argument("--train", action="store_true", help="Train models and perform Stratified CV")
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
