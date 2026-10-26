# CAPRA Machine Learning Evaluation Report (Phase 3)

**[DATA SOURCE: EMPIRICAL (sample_android_malware_dataset.csv) [SMALL SAMPLE n=60 - ILLUSTRATIVE ONLY]]**

## Model Comparison (Stratified 5-Fold Cross Validation)

| Metric | Random Forest (RF) | Gradient Boosting (GB) | Delta |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 0.9833 ± 0.0333 | 1.0000 ± 0.0000 | +0.0167 |
| **Precision** | 1.0000 | 1.0000 | +0.0000 |
| **Recall** | 0.9667 | 1.0000 | +0.0333 |
| **F1-Score** | **0.9818** | 1.0000 | +0.0182 |
| **ROC-AUC** | **1.0000** | 1.0000 | +0.0000 |

**Selected Model**: `GradientBoosting` (Saved to `data/models/best_model.joblib`)

> Note on Validity: If trained on synthetic fallback, results reflect the rule generator rather than empirical malware distribution. Small hand-built datasets (< 200 rows) are marked ILLUSTRATIVE ONLY - cross-validation metrics on them do NOT represent in-the-wild accuracy. Place a full real Drebin or CIC-AndMal CSV in `data/datasets/` to evaluate true in-the-wild accuracy.
