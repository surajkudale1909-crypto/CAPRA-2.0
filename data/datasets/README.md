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

Kaggle-style schemas are handled automatically:
* **Short or full names** — `SEND_SMS` and `android.permission.SEND_SMS` are both accepted and normalized.
* **Metadata columns are ignored** — `pkgname`, `App categore`, `Downloads`, etc. never become features.
* **Aggregate group columns are ignored** — `SMS`, `STORAGE`, `LOCATION`, `CAMERA.1`, ... are derived summaries, not real permissions.
* **Intent/broadcast columns are ignored** — `android.intent.action.*` columns are excluded (CAPRA's classifier is permission-based).
* **Label column is auto-detected** — `class`, `label`, `malware`, `type`, `verdict`, `target`, `y`, ... (case-insensitive), with values like `malware|benign`, `1|0`, `M|B`.
* **CSVs without a label column are skipped** with an explanatory warning (e.g. unlabelled permission dumps like `Extracted_permssion_updated.csv`).
* **Multiple labelled CSVs are concatenated** over the union of their permission columns. The bundled toy `sample_android_malware_dataset.csv` is automatically ignored once real labelled data is present.

## How to Train on Your Real Dataset
1. Place your CSV file(s) in this directory (e.g. `data/datasets/Android_Malware_Benign.csv`).
2. Check what the loader sees (recommended first step):
   ```bash
   python scripts/train_from_kaggle.py --scan-only
   ```
3. Train and evaluate:
   ```bash
   python scripts/train_from_kaggle.py
   # or equivalently:
   python -m src.ml_pipeline --train --dataset data/datasets/Android_Malware_Benign.csv
   ```
4. The pipeline will automatically:
   - Perform Stratified 5-Fold Cross Validation.
   - Compare **Random Forest** vs. **Gradient Boosting**.
   - Output metric tables and plots (`reports/model_comparison.json`, `reports/roc_curve.png`, `reports/confusion_matrix.png`, `reports/feature_importance.png`).
   - Save the best-performing model to `data/models/permission_model.joblib` and `data/models/best_model.joblib`, including the dataset's feature vocabulary and class balance.

> **Note on Synthetic Fallback**:
> If no CSV dataset file is present in `data/datasets/`, CAPRA transparently falls back to a deterministic synthetic dataset. In that event, all logs, UI elements, and exported reports are explicitly marked with **`[DATA SOURCE: SYNTHETIC (FALLBACK)]`**. Synthetic results are NEVER presented as empirical accuracy.
