"""Tests for the ML permission-risk pipeline and real-dataset schema handling."""

import os
import shutil
import tempfile
import unittest


class TestMLPipeline(unittest.TestCase):
    """Tests for Random Forest permission risk estimation (Ishan's Module)."""

    def setUp(self):
        from src.ml_pipeline import PermissionMLPipeline

        self.pipeline = PermissionMLPipeline()
        # The feature vocabulary is dataset-driven (real-world schemas vary);
        # always compare against the active vocabulary of the loaded model.
        self.features = self.pipeline.features

    def test_vectorization_dimensions(self):
        """Vector shape must strictly equal (1, num_features)."""
        vec = self.pipeline.vectorize(["android.permission.INTERNET", "android.permission.VIBRATE"])
        self.assertEqual(vec.shape, (1, len(self.features)))

    def test_benign_profile_low_risk(self):
        """Benign utility permissions should yield a low risk probability (< 0.50)."""
        benign_perms = ["android.permission.VIBRATE"]
        res = self.pipeline.predict_risk(benign_perms)
        self.assertLess(res["risk_probability"], 0.50)
        self.assertEqual(res["predicted_class"], 0)
        self.assertEqual(res["ml_verdict"], "Benign Profile")

    def test_trojan_profile_high_risk(self):
        """High-risk exfiltration permissions should yield high risk probability (>= 0.50)."""
        malicious_perms = [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_PHONE_STATE",
        ]
        res = self.pipeline.predict_risk(malicious_perms)
        self.assertGreaterEqual(res["risk_probability"], 0.50)
        self.assertEqual(res["predicted_class"], 1)
        self.assertEqual(res["ml_verdict"], "High Risk / Anomaly")

    def test_feature_importance_export(self):
        """Ensure feature importance bar plot renders and saves to disk."""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            temp_png = f.name

        try:
            out = self.pipeline.export_feature_importance_plot(temp_png)
            self.assertTrue(os.path.exists(out))
            self.assertGreater(os.path.getsize(out), 1000)
        finally:
            if os.path.exists(temp_png):
                os.remove(temp_png)


class TestMLEvaluationAndExplainability(unittest.TestCase):
    """Tests for dataset loader, model comparison, and local explainability (Phase 3)."""

    def test_empirical_dataset_loader(self):
        from src.ml_pipeline import load_dataset

        csv_path = os.path.join("data", "datasets", "sample_android_malware_dataset.csv")
        X, y, source_type, source_desc, features = load_dataset(csv_path)
        self.assertEqual(source_type, "EMPIRICAL")
        self.assertIn("sample_android_malware_dataset.csv", source_desc)
        self.assertGreater(len(X), 20)
        self.assertEqual(len(X), len(y))
        self.assertEqual(X.shape[1], len(features))

    def test_synthetic_fallback_loader(self):
        from src.ml_pipeline import load_dataset

        X, y, source_type, source_desc, features = load_dataset("non_existent_dataset.csv")
        self.assertEqual(source_type, "SYNTHETIC")
        self.assertIn("SYNTHETIC", source_desc)
        self.assertGreater(len(features), 0)


class TestKaggleSchemaLoader(unittest.TestCase):
    """Tests for real-world Kaggle/Drebin/CIC dataset schema handling."""

    def _write_csv(self, name, rows, header):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(",".join(header) + "\n")
            for r in rows:
                f.write(",".join(str(v) for v in r) + "\n")
        return path

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_short_names_metadata_and_aggregates(self):
        """Kaggle-style CSV: short perm names + metadata + aggregate cols + 'class' label."""
        from src.ml_pipeline import load_dataset

        header = [
            "pkgname",
            "App categore  ",
            "Downloads",
            "INTERNET",
            "READ_SMS",
            "SMS",
            "CALENDAR",
            "android.intent.action.BOOT_COMPLETED",
            "class",
        ]
        rows = [
            ["com.evil.app", "Tools", "10 M", 1, 1, 1, 1, 1, "malware"],
            ["com.good.app", "Tools", "10 M", 1, 0, 0, 0, 1, "benign"],
            ["com.evil2.app", "Games", "1 M", 1, 1, 1, 0, 0, "1"],
            ["com.good2.app", "Games", "1 M", 0, 0, 0, 0, 0, "0"],
        ]
        path = self._write_csv("kaggle_style.csv", rows, header)
        X, y, source_type, source_desc, features = load_dataset(path)
        self.assertEqual(source_type, "EMPIRICAL")
        # Only real permissions become features: aggregates, metadata and intents excluded
        self.assertEqual(
            sorted(features),
            ["android.permission.INTERNET", "android.permission.READ_SMS"],
        )
        self.assertEqual(list(y), [1, 0, 1, 0])
        self.assertEqual(X.shape, (4, 2))
        # Column order follows sorted features: INTERNET, READ_SMS
        self.assertEqual(X[0].tolist(), [1, 1])
        self.assertEqual(X[1].tolist(), [1, 0])
        self.assertIn("SMALL SAMPLE", source_desc)

    def test_label_column_case_insensitive_and_m_b_values(self):
        """Label column found case-insensitively; M/B label values mapped correctly."""
        from src.ml_pipeline import load_dataset

        header = ["name", "INTERNET", "CAMERA", "Label"]
        rows = [
            ["a", 1, 1, "M"],
            ["b", 1, 0, "B"],
            ["c", 0, 0, "M"],
        ]
        path = self._write_csv("mb_labels.csv", rows, header)
        X, y, source_type, source_desc, features = load_dataset(path)
        self.assertEqual(source_type, "EMPIRICAL")
        self.assertEqual(list(y), [1, 0, 1])
        self.assertEqual(
            sorted(features), ["android.permission.CAMERA", "android.permission.INTERNET"]
        )

    def test_unlabelled_csv_is_skipped_and_falls_back(self):
        """A CSV without any label column cannot train a supervised model."""
        from src.ml_pipeline import load_dataset

        header = ["pkgname", "App categore  ", "Downloads", "INTERNET", "READ_SMS"]
        rows = [["com.x", "Tools", "10 M", 1, 1]]
        path = self._write_csv("unlabelled.csv", rows, header)
        X, y, source_type, source_desc, features = load_dataset(path)
        self.assertEqual(source_type, "SYNTHETIC")
        self.assertIn("SYNTHETIC", source_desc)

    def test_multiple_labelled_csvs_concatenated(self):
        """Two labelled CSVs are stacked over the union of their permission columns."""
        from src.ml_pipeline import load_dataset

        p1 = self._write_csv(
            "set_a.csv",
            [["com.a", 1, "malware"], ["com.b", 0, "benign"]],
            ["pkgname", "INTERNET", "class"],
        )
        p2 = self._write_csv(
            "set_b.csv",
            [["com.c", 1, 1, 1], ["com.d", 0, 0, 0]],
            ["pkgname", "READ_SMS", "CAMERA", "malware"],
        )
        X, y, source_type, source_desc, features = load_dataset([p1, p2])
        self.assertEqual(source_type, "EMPIRICAL")
        self.assertEqual(len(X), 4)
        self.assertEqual(
            sorted(features),
            [
                "android.permission.CAMERA",
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
            ],
        )
        self.assertEqual(list(y), [1, 0, 1, 0])
        # Missing columns in each file are zero-filled
        self.assertEqual(X[0].tolist(), [0, 1, 0])  # com.a: INTERNET only
        self.assertEqual(X[2].tolist(), [1, 0, 1])  # com.d? no - com.c: READ_SMS+CAMERA

    def test_vectorize_normalizes_short_and_full_names(self):
        """vectorize() accepts both short and full permission names."""
        from src.ml_pipeline import PermissionMLPipeline, normalize_permission_name

        pipeline = PermissionMLPipeline()
        vec = pipeline.vectorize(["android.permission.INTERNET", "READ_SMS"])
        self.assertEqual(vec.shape, (1, len(pipeline.features)))
        self.assertEqual(
            vec[0, pipeline.perm_to_idx[normalize_permission_name("INTERNET")]],
            1,
        )
        self.assertEqual(
            vec[0, pipeline.perm_to_idx[normalize_permission_name("android.permission.READ_SMS")]],
            1,
        )

    def test_normalize_permission_column_rules(self):
        from src.ml_pipeline import normalize_permission_column as npc

        self.assertEqual(npc("READ_SMS"), "android.permission.READ_SMS")
        self.assertEqual(npc("android.permission.CAMERA"), "android.permission.CAMERA")
        self.assertIsNone(npc("pkgname"))
        self.assertIsNone(npc("App categore  "))
        self.assertIsNone(npc("Downloads"))
        self.assertIsNone(npc("SMS"))  # aggregate group column
        self.assertIsNone(npc("STORAGE"))  # aggregate group column
        self.assertIsNone(npc("android.intent.action.BOOT_COMPLETED"))
        self.assertIsNone(npc("CAMERA.1"))  # pandas-deduped aggregate

    def test_short_and_full_name_duplicates_are_combined(self):
        """When a CSV has both short and full name columns of a permission, OR them."""
        from src.ml_pipeline import load_dataset

        header = [
            "pkgname",
            "ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_NETWORK_STATE",
            "class",
        ]
        rows = [
            ["com.a", 1, 0, "malware"],  # short column set
            ["com.b", 0, 1, "benign"],  # full column set
            ["com.c", 0, 0, "benign"],  # neither
        ]
        path = self._write_csv("dup_names.csv", rows, header)
        X, y, source_type, source_desc, features = load_dataset(path)
        self.assertEqual(features, ["android.permission.ACCESS_NETWORK_STATE"])
        self.assertEqual(X[:, 0].tolist(), [1, 1, 0])

    def test_binary_feature_columns_are_not_labels(self):
        """Regression: a 0/1 intent/feature column must never be detected as the label."""
        import pandas as pd

        from src.ml_pipeline import detect_label_column

        df = pd.DataFrame(
            {
                "pkgname": ["a", "b", "c"],
                "INTERNET": [1, 1, 0],
                "android.intent.action.MEDIA_BAD_REMOVAL": [0, 0, 1],
                "SMS": [1, 0, 1],
            }
        )
        self.assertIsNone(detect_label_column(df))
        # ...but a word-style label column is still found even among binary features
        df["Target"] = ["Malware", "Benign", "Malware"]
        self.assertEqual(detect_label_column(df), "Target")

    def test_per_prediction_explainability(self):
        from src.ml_pipeline import PermissionMLPipeline

        pipeline = PermissionMLPipeline()
        perms = [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ]
        res = pipeline.predict_risk(perms)
        self.assertIn("top_contributing_permissions", res)
        self.assertIn("model_type", res)
        self.assertIn("data_source", res)
        self.assertGreater(len(res["top_contributing_permissions"]), 0)
        top = res["top_contributing_permissions"][0]
        self.assertIn("importance_score", top)
        self.assertIn("risk_contribution_pct", top)

    def test_reports_generated(self):
        self.assertTrue(os.path.exists(os.path.join("reports", "model_comparison.json")))
        self.assertTrue(os.path.exists(os.path.join("reports", "evaluation_metrics.md")))
        self.assertTrue(os.path.exists(os.path.join("reports", "confusion_matrix.png")))
        self.assertTrue(os.path.exists(os.path.join("reports", "roc_curve.png")))


if __name__ == "__main__":
    unittest.main()
