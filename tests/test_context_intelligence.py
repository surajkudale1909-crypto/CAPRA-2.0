"""Phase 3: Context Intelligence tests.

Covers the empirical-category-baseline enrichment (informational only),
data-driven context exemptions, ML decision-threshold calibration, and the
known-app category catalog.

GOLDEN RULE: any test here that pins scores/ranges must be consciously
re-verified if calibration changes semantics (see tests/test_golden.py).
"""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestEmpiricalBaselines(unittest.TestCase):
    """Empirical category baselines derived from real-world app metadata."""

    @classmethod
    def setUpClass(cls):
        from src.context_engine import ContextEngine

        cls.engine = ContextEngine()

    def test_baselines_file_loads(self):
        self.assertTrue(self.engine._empirical_index)
        meta = self.engine._empirical_index.get("__meta__", {})
        self.assertIn("Flashlight", meta)
        self.assertGreater(meta["Flashlight"]["sample_size"], 0)

    def test_empirical_stats_lookup(self):
        stats = self.engine.get_empirical_stats("Flashlight", "android.permission.READ_SMS")
        self.assertIsNotNone(stats)
        self.assertLess(stats["frequency"], 0.25)  # rare for tool-type apps
        self.assertEqual(stats["count"], 2)
        self.assertEqual(stats["n"], 16)

    def test_empirical_stats_normalize_short_names(self):
        a = self.engine.get_empirical_stats("Flashlight", "android.permission.READ_SMS")
        b = self.engine.get_empirical_stats("Flashlight", "READ_SMS")
        self.assertEqual(a["frequency"], b["frequency"])

    def test_empirical_note_on_suspicious_entries(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.READ_SMS"], category="Flashlight"
        )
        flagged = res["suspicious_permissions"] + res["unexpected_dangerous_permissions"]
        self.assertTrue(flagged)
        notes = [f.get("empirical_note") for f in flagged]
        self.assertTrue(any(n and "12" in n for n in notes))

    def test_empirical_context_block(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.READ_SMS", "android.permission.INTERNET"],
            category="Flashlight",
        )
        emp = res["empirical_context"]
        self.assertTrue(emp["available"])
        self.assertEqual(emp["sample_size"], 16)
        self.assertIn("Tools", emp["store_categories"])
        self.assertTrue(any("READ_SMS" in note for note in emp["category_norm_notes"]))

    def test_enrichment_never_changes_scores(self):
        """Empirical blending must be informational only — score invariance."""
        perms = [
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.CAMERA",
            "android.permission.INTERNET",
        ]
        res = self.engine.evaluate_permissions(perms, category="Flashlight")
        without = ContextEngineNoEmpirical().evaluate_permissions(perms, category="Flashlight")
        self.assertEqual(
            res["penalties"]["total_raw_penalty"],
            without["penalties"]["total_raw_penalty"],
        )

    def test_graceful_degradation_without_baselines(self):
        engine = ContextEngineNoEmpirical()
        res = engine.evaluate_permissions(["android.permission.READ_SMS"], category="Flashlight")
        self.assertFalse(res["empirical_context"]["available"])
        self.assertGreater(res["penalties"]["total_raw_penalty"], 0)


def ContextEngineNoEmpirical():
    from src.context_engine import ContextEngine

    return ContextEngine(empirical_path="/nonexistent/empirical.json")


class TestContextualExemptions(unittest.TestCase):
    """Data-driven exempt_categories: expected functionality is not penalized."""

    @classmethod
    def setUpClass(cls):
        from src.context_engine import ContextEngine

        cls.engine = ContextEngine()

    def test_camera_app_visual_combo_exempt(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.CAMERA", "android.permission.INTERNET"],
            category="Camera/Photo",
        )
        ids = [c["id"] for c in res["triggered_combinations"]]
        self.assertNotIn("COMB_VISUAL_SURVEILLANCE", ids)
        exempt_ids = [e["id"] for e in res["contextual_exemptions"]]
        self.assertIn("COMB_VISUAL_SURVEILLANCE", exempt_ids)

    def test_flashlight_with_camera_combo_still_flagged(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.CAMERA", "android.permission.INTERNET"],
            category="Flashlight",
        )
        ids = [c["id"] for c in res["triggered_combinations"]]
        self.assertIn("COMB_VISUAL_SURVEILLANCE", ids)
        self.assertGreater(res["penalties"]["combination_penalty"], 0)

    def test_media_combo_exempt_for_music(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.READ_MEDIA_IMAGES", "android.permission.INTERNET"],
            category="Music/Video",
        )
        ids = [c["id"] for c in res["triggered_combinations"]]
        self.assertNotIn("COMB_MEDIA_EXFILTRATION", ids)

    def test_media_combo_still_fires_in_calculator(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.READ_MEDIA_IMAGES", "android.permission.INTERNET"],
            category="Calculator",
        )
        ids = [c["id"] for c in res["triggered_combinations"]]
        self.assertIn("COMB_MEDIA_EXFILTRATION", ids)

    def test_location_combo_exempt_for_navigation(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
            category="Navigation",
        )
        self.assertEqual(res["penalties"]["combination_penalty"], 0)
        self.assertEqual(
            [e["id"] for e in res["contextual_exemptions"]], ["COMB_LOCATION_TRACKING"]
        )

    def test_sms_combo_exempt_for_messaging(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.READ_SMS", "android.permission.INTERNET"],
            category="Messaging",
        )
        ids = [c["id"] for c in res["triggered_combinations"]]
        self.assertNotIn("COMB_SMS_INTERCEPTION", ids)

    def test_sms_combo_still_critical_signal_for_flashlight(self):
        res = self.engine.evaluate_permissions(
            ["android.permission.READ_SMS", "android.permission.INTERNET"],
            category="Flashlight",
        )
        ids = [c["id"] for c in res["triggered_combinations"]]
        self.assertIn("COMB_SMS_INTERCEPTION", ids)

    def test_exemptions_declared_in_rules_data(self):
        """Exemptions come from data/context_rules.json, not hardcoded logic."""
        import json

        rules = json.load(open(os.path.join(ROOT, "data", "context_rules.json"), encoding="utf-8"))
        by_id = {c["id"]: c for c in rules["dangerous_combinations"]}
        self.assertIn("Camera/Photo", by_id["COMB_VISUAL_SURVEILLANCE"]["exempt_categories"])
        self.assertIn("Navigation", by_id["COMB_LOCATION_TRACKING"]["exempt_categories"])
        self.assertIn("Messaging", by_id["COMB_SMS_INTERCEPTION"]["exempt_categories"])


class TestMLCalibration(unittest.TestCase):
    """Decision-threshold calibration plumbing."""

    def test_calibrate_threshold_helper(self):
        import numpy as np

        from src.ml_pipeline import _calibrate_decision_threshold

        y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        probs = np.array([0.1, 0.2, 0.3, 0.45, 0.55, 0.7, 0.85, 0.95])
        cal = _calibrate_decision_threshold(y, probs)
        self.assertIn("decision_threshold", cal)
        self.assertEqual(cal["criterion"], "max_F1_on_out_of_fold_predictions")
        self.assertGreaterEqual(cal["f1_at_threshold"], 0.9)
        self.assertIn("youden_threshold", cal)

    def test_pipeline_threshold_loaded_from_payload(self):
        from src.ml_pipeline import PermissionMLPipeline

        p = PermissionMLPipeline()
        self.assertLessEqual(abs(p.decision_threshold - 0.45), 0.06)

    def test_predict_risk_uses_decision_threshold(self):
        from src.ml_pipeline import PermissionMLPipeline

        p = PermissionMLPipeline()
        perms = [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ]
        res = p.predict_risk(perms)
        self.assertIn("decision_threshold", res)
        expected = 1 if res["risk_probability"] >= p.decision_threshold else 0
        self.assertEqual(res["predicted_class"], expected)

    def test_threshold_forces_benign_class_when_high(self):
        from src.ml_pipeline import PermissionMLPipeline

        p = PermissionMLPipeline()
        p.decision_threshold = 1.01  # force everything benign
        res = p.predict_risk(["android.permission.READ_SMS", "android.permission.INTERNET"])
        self.assertEqual(res["predicted_class"], 0)
        self.assertEqual(res["ml_verdict"], "Benign Profile")

    def test_payload_contains_threshold(self):
        import joblib

        from src.ml_pipeline import PermissionMLPipeline

        p = PermissionMLPipeline()
        payload = joblib.load(p.model_path)
        self.assertIn("decision_threshold", payload)
        self.assertGreater(payload["decision_threshold"], 0)
        self.assertLess(payload["decision_threshold"], 1)


class TestKnownAppCatalog(unittest.TestCase):
    """Brand-name recognition for real-world app listings."""

    @classmethod
    def setUpClass(cls):
        from src.category_detector import detect_app_category

        cls.detect = staticmethod(detect_app_category)

    def test_brand_names_detected(self):
        cases = {
            "WhatsApp": "Messaging",
            "Spotify": "Music/Video",
            "AliExpress": "Shopping",
            "YouTube": "Music/Video",
            "Roblox": "Games",
            "Venmo": "Banking/Finance",
            "Duolingo": "Education",
            "Instagram": "Social Media",
        }
        for name, expected in cases.items():
            res = self.detect(package_name="", app_name=name)
            self.assertEqual(res.category, expected, name)
            self.assertEqual(res.method, "known_app_catalog", name)

    def test_most_specific_brand_wins(self):
        # "Amazon Alexa" must not collapse to the "Amazon" (Shopping) brand.
        res = self.detect(package_name="", app_name="Amazon Alexa")
        self.assertEqual(res.category, "Productivity")
        res = self.detect(package_name="", app_name="Amazon Shopping")
        self.assertEqual(res.category, "Shopping")

    def test_camelcase_brands_match(self):
        res = self.detect(package_name="", app_name="whatsApp")
        self.assertEqual(res.category, "Messaging")
        res = self.detect(package_name="com.linkedin.android", app_name="")
        self.assertEqual(res.category, "Social Media")

    def test_unknown_app_falls_back_to_keywords(self):
        res = self.detect(package_name="", app_name="My Sudoku Puzzle Game")
        self.assertEqual(res.category, "Games")
        self.assertNotEqual(res.method, "known_app_catalog")


class TestReportEnrichment(unittest.TestCase):
    """Markdown report renders empirical baselines and exemptions."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        from src.pipeline import run_synthetic_demo
        from src.report_generator import generate_markdown_report

        cls.flashlight = run_synthetic_demo("malicious_flashlight", category="Flashlight")
        cls.navigation = run_synthetic_demo("benign_navigation", category="Navigation")

        cls._tmp = tempfile.mkdtemp(prefix="capra_ctxint_")
        p1 = generate_markdown_report(cls.flashlight, output_path=os.path.join(cls._tmp, "f.md"))
        p2 = generate_markdown_report(cls.navigation, output_path=os.path.join(cls._tmp, "n.md"))
        cls.md_flash = open(p1, encoding="utf-8").read()
        cls.md_nav = open(p2, encoding="utf-8").read()

    def test_report_has_empirical_section(self):
        self.assertIn("Real-World Category Baselines", self.md_flash)
        self.assertIn("data/empirical_baselines.json", self.md_flash)

    def test_report_renders_exemptions_for_navigation(self):
        self.assertIn("Expected Functionality Combinations", self.md_nav)
        self.assertIn("Continuous Location Exfiltration Risk", self.md_nav)

    def test_report_suspicious_table_has_baseline_column(self):
        self.assertIn("Real-World Baseline", self.md_flash)


if __name__ == "__main__":
    unittest.main()
