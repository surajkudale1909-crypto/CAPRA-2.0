# CAPRA Machine Learning Datasets Directory

This directory stores labelled Android malware and benign application permission datasets for training and evaluating CAPRA's Machine Learning models.

## Supported Dataset Formats

The loader in `src/ml_pipeline.py` supports standard CSV formats from academic benchmarks:
1. **Drebin Dataset**: Binary indicator columns for Android permissions and an output label column (`class`, `label`, `Result`, or `malware`).
2. **CIC-AndMal2017 / CIC-InvesAndMal2019**: Permission and API call matrices.
3. **Kaggle Android Malware Permission Datasets**: CSV containing permission columns (either fully qualified e.g. `android.permission.SEND_SMS` or short name e.g. `SEND_SMS`) with binary flags (0 or 1).

### Expected CSV Structure:
```csv
package_name,android.permission.INTERNET,android.permission.SEND_SMS,android.permission.READ_CONTACTS,...,class
com.example.benign,1,0,0,...,0
com.example.trojan,1,1,1,...,1
```

## How to Train on Your Real Dataset
1. Place your CSV file in this directory (e.g., `data/datasets/drebin_data.csv` or `data/datasets/android_malware.csv`).
2. Run model training and evaluation:
   ```bash
   python -m src.ml_pipeline --train --dataset data/datasets/drebin_data.csv
   ```
3. The pipeline will automatically:
   - Perform Stratified 5-Fold Cross Validation.
   - Compare **Random Forest** vs. **Gradient Boosting**.
   - Output metric tables and plots (`reports/model_comparison.json`, `reports/roc_curve.png`, `reports/confusion_matrix.png`, `reports/feature_importance.png`).
   - Save the best-performing model to `data/models/best_model.joblib`.

> **Note on Synthetic Fallback**:
> If no CSV dataset file is present in `data/datasets/`, CAPRA transparently falls back to a deterministic synthetic dataset. In that event, all logs, UI elements, and exported reports are explicitly marked with **`[DATA SOURCE: SYNTHETIC (FALLBACK)]`**. Synthetic results are NEVER presented as empirical accuracy.
