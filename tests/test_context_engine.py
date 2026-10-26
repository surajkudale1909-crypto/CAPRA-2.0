"""Tests for the context-aware permission evaluation engine."""

import os
import unittest

from src.context_engine import ContextEngine, ContextRuleError


class TestContextEngine(unittest.TestCase):
    """Tests for the contextual permission evaluation engine."""

    def setUp(self):
        self.engine = ContextEngine()

    def test_supported_categories(self):
        """Ensure default categories are correctly recognized."""
        cats = self.engine.get_supported_categories()
        self.assertIn("Calculator", cats)
        self.assertIn("Flashlight", cats)
        self.assertIn("Navigation", cats)

    def test_category_resolution(self):
        """Test case-insensitive category matching."""
        self.assertEqual(self.engine.resolve_category("calculator"), "Calculator")
        self.assertEqual(self.engine.resolve_category("FLASHLIGHT"), "Flashlight")
        self.assertEqual(self.engine.resolve_category("navigation"), "Navigation")

    def test_unsupported_category_raises(self):
        """Test error raised for unknown app categories."""
        with self.assertRaises(ContextRuleError):
            self.engine.resolve_category("CryptocurrencyMiner")

    def test_calculator_benign_permissions(self):
        """Calculator with only VIBRATE should yield 0 penalty points."""
        res = self.engine.evaluate_permissions(
            requested_permissions=["android.permission.VIBRATE"],
            category="Calculator",
        )
        self.assertEqual(res["breakdown"]["acceptable_count"], 1)
        self.assertEqual(res["breakdown"]["suspicious_count"], 0)
        self.assertEqual(res["penalties"]["total_raw_penalty"], 0)

    def test_calculator_suspicious_permissions(self):
        """Calculator requesting Contacts and Camera should trigger suspicious penalties."""
        perms = [
            "android.permission.VIBRATE",
            "android.permission.READ_CONTACTS",
            "android.permission.CAMERA",
        ]
        res = self.engine.evaluate_permissions(perms, category="Calculator")
        self.assertEqual(res["breakdown"]["suspicious_count"], 2)
        self.assertGreater(res["penalties"]["mismatch_penalty"], 0)

    def test_dangerous_combination_detection(self):
        """Test detection of Storage + Internet exfiltration combination."""
        perms = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.INTERNET",
        ]
        res = self.engine.evaluate_permissions(perms, category="Calculator")
        comb_ids = [c["id"] for c in res["triggered_combinations"]]
        self.assertIn("COMB_STORAGE_EXFILTRATION", comb_ids)
        self.assertGreater(res["penalties"]["combination_penalty"], 0)

    def test_contextual_exemption_navigation(self):
        """Navigation app should be exempt from location+internet tracking penalty."""
        nav_perms = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
        ]
        nav_res = self.engine.evaluate_permissions(nav_perms, category="Navigation")
        # In navigation, COMB_LOCATION_TRACKING should NOT be triggered
        comb_ids_nav = [c["id"] for c in nav_res["triggered_combinations"]]
        self.assertNotIn("COMB_LOCATION_TRACKING", comb_ids_nav)

        # In flashlight, the same combination MUST be triggered
        flash_res = self.engine.evaluate_permissions(nav_perms, category="Flashlight")
        comb_ids_flash = [c["id"] for c in flash_res["triggered_combinations"]]
        self.assertIn("COMB_LOCATION_TRACKING", comb_ids_flash)


class TestExpandedContextRules(unittest.TestCase):
    """Tests for 13 categories and modern permissions in ContextEngine (Phase 2)."""

    def setUp(self):
        self.engine = ContextEngine()

    def test_thirteen_categories_present(self):
        cats = self.engine.get_supported_categories()
        expected = [
            "Calculator",
            "Flashlight",
            "Navigation",
            "Social Media",
            "Messaging",
            "Banking/Finance",
            "Health/Fitness",
            "Games",
            "Camera/Photo",
            "Music/Video",
            "Shopping",
            "Productivity",
            "Education",
        ]
        for cat in expected:
            self.assertIn(cat, cats)

    def test_category_aliases_resolution(self):
        self.assertEqual(self.engine.resolve_category("finance"), "Banking/Finance")
        self.assertEqual(self.engine.resolve_category("banking"), "Banking/Finance")
        self.assertEqual(self.engine.resolve_category("workout"), "Health/Fitness")
        self.assertEqual(self.engine.resolve_category("photo"), "Camera/Photo")
        self.assertEqual(self.engine.resolve_category("ecommerce"), "Shopping")

    def test_modern_permissions_recognized(self):
        self.assertIn("android.permission.POST_NOTIFICATIONS", self.engine.aosp_dangerous)
        self.assertIn("android.permission.READ_MEDIA_IMAGES", self.engine.aosp_dangerous)
        self.assertIn("android.permission.NEARBY_WIFI_DEVICES", self.engine.aosp_dangerous)

    def test_media_exfiltration_combination(self):
        perms = [
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.INTERNET",
        ]
        res = self.engine.evaluate_permissions(perms, category="Calculator")
        comb_ids = [c["id"] for c in res["triggered_combinations"]]
        self.assertIn("COMB_MEDIA_EXFILTRATION", comb_ids)

    def test_pipeline_auto_detects_calculator(self):
        from src.pipeline import analyze_apk

        sample_path = os.path.join("data", "apks", "calculator_sample.apk")
        if os.path.exists(sample_path):
            res = analyze_apk(sample_path)  # No category passed!
            self.assertEqual(res["category"], "Calculator")
            self.assertIn("category_detection", res)
            self.assertGreater(res["category_detection"]["confidence"], 0.70)


if __name__ == "__main__":
    unittest.main()
