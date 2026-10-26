# CAPRA Machine Learning Evaluation Report (Phase 3)

**[DATA SOURCE: EMPIRICAL (Android_Malware_Benign.csv, 213 features)]**

## Model Comparison (Stratified 5-Fold Cross Validation)

| Metric | Random Forest (RF) | Gradient Boosting (GB) | Delta |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 0.8577 ± 0.0084 | 0.8752 ± 0.0103 | +0.0175 |
| **Precision** | 0.8931 | 0.8818 | -0.0113 |
| **Recall** | 0.8516 | 0.9013 | +0.0497 |
| **F1-Score** | **0.8717** | 0.8913 | +0.0196 |
| **ROC-AUC** | **0.9379** | 0.9542 | +0.0163 |

**Selected Model**: `GradientBoosting` (Saved to `data/models/best_model.joblib`)

> Note on Validity: If trained on synthetic fallback, results reflect the rule generator rather than empirical malware distribution. Small hand-built datasets (< 200 rows) are marked ILLUSTRATIVE ONLY - cross-validation metrics on them do NOT represent in-the-wild accuracy. Place a full real Drebin or CIC-AndMal CSV in `data/datasets/` to evaluate true in-the-wild accuracy.
