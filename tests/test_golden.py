"""Golden Regression Tests — freeze verified CAPRA 2.0 behavior.

These tests pin today's *verified* outcomes so that no future change can
silently alter what the demo shows or what the reports claim.

IMPORTANT for future maintainers (esp. scoring calibration work):
  * Assertions use INVARIANTS and safe RANGES, not exact scores.
  * If a change intentionally breaks one of these (e.g. Phase-3 weight
    calibration), that is a signal to consciously re-verify the demo
    behavior and update this file in the same commit — never just delete it.
"""

import os
import unittest

from src.fusion_engine import FusionEngine, RiskVerdict
from src.pipeline import analyze_apk, run_synthetic_demo

SAMPLE_APK = os.path.join("data", "apks", "calculator_sample.apk")
HAS_SAMPLE = os.path.exists(SAMPLE_APK)

# Options that make scans deterministic and side-effect free for tests
DETERMINISTIC_OPTS = {"skip_threat": True, "skip_history": True}


@unittest.skipUnless(HAS_SAMPLE, "sample APK not present")
class TestGoldenSampleAPK(unittest.TestCase):
    """Golden expectations for the bundled Fossify Calculator sample APK."""

    @classmethod
    def setUpClass(cls):
        cls.result = analyze_apk(SAMPLE_APK, options=DETERMINISTIC_OPTS)

    def test_metadata_identity(self):
        manifest = self.result["manifest"]
        self.assertEqual(manifest["package_name"], "org.fossify.math")
        self.assertEqual(manifest["app_name"], "Calculator")
        self.assertEqual(manifest["target_sdk_version"], 36)

    def test_auto_detected_category(self):
        self.assertEqual(self.result["category"], "Calculator")
        detection = self.result["category_detection"]
        self.assertGreaterEqual(detection["confidence"], 0.80)

    def test_verdict_is_safe(self):
        fusion = self.result["fusion"]
        self.assertEqual(fusion["verdict"], RiskVerdict.SAFE)
        self.assertLessEqual(fusion["score"], 30)

    def test_ml_component_is_benign(self):
        ml = self.result["ml"]
        self.assertLess(ml["risk_percentage"], 50.0)
        self.assertEqual(ml["predicted_class"], 0)

    def test_findings_mention_context(self):
        findings = " ".join(self.result["fusion"]["findings"])
        self.assertTrue(len(findings) > 0)

    def test_analysis_is_deterministic(self):
        second = analyze_apk(SAMPLE_APK, options=DETERMINISTIC_OPTS)
        self.assertEqual(second["fusion"]["score"], self.result["fusion"]["score"])
        self.assertEqual(second["fusion"]["verdict"], self.result["fusion"]["verdict"])
        self.assertEqual(second["category"], self.result["category"])


class TestGoldenDemoScenarios(unittest.TestCase):
    """Golden expectations for the three presentation demo scenarios."""

    def test_benign_calculator_demo(self):
        r = run_synthetic_demo("benign_calculator", category="Calculator")
        fusion, context = r["fusion"], r["context"]
        self.assertEqual(context["category"], "Calculator")
        self.assertEqual(fusion["verdict"], RiskVerdict.SAFE)
        self.assertLessEqual(fusion["score"], 10)
        self.assertEqual(context["triggered_combinations"], [])

    def test_benign_navigation_demo(self):
        """Navigation app: location is contextually justified, NOT an exfil combo."""
        r = run_synthetic_demo("benign_navigation", category="Navigation")
        fusion, context = r["fusion"], r["context"]
        self.assertEqual(context["category"], "Navigation")
        self.assertIn(fusion["verdict"], (RiskVerdict.SAFE, RiskVerdict.LOW))
        self.assertLessEqual(fusion["score"], 15)
        combo_ids = [c["id"] for c in context["triggered_combinations"]]
        self.assertNotIn("COMB_LOCATION_TRACKING", combo_ids)

    def test_malicious_flashlight_demo(self):
        """Spyware flashlight: exfil combos + threat-intel override -> Critical."""
        r = run_synthetic_demo("malicious_flashlight", category="Flashlight")
        fusion, context, threat = r["fusion"], r["context"], r["threat"]
        self.assertEqual(fusion["verdict"], RiskVerdict.CRITICAL)
        self.assertGreaterEqual(fusion["score"], 90)
        combo_ids = {c["id"] for c in context["triggered_combinations"]}
        self.assertIn("COMB_STORAGE_EXFILTRATION", combo_ids)
        self.assertIn("COMB_CONTACTS_HARVESTING", combo_ids)
        self.assertIn("COMB_LOCATION_TRACKING", combo_ids)
        self.assertTrue(threat.get("is_flagged"))
        self.assertTrue(fusion["score_breakdown"]["threat_intel_override"])


class TestGoldenFusionSemantics(unittest.TestCase):
    """Pin the scoring contract: verdict threshold boundaries and threat override."""

    def test_verdict_threshold_boundaries(self):
        engine = FusionEngine()
        boundaries = {
            0: RiskVerdict.SAFE,
            20: RiskVerdict.SAFE,
            21: RiskVerdict.LOW,
            45: RiskVerdict.LOW,
            46: RiskVerdict.MEDIUM,
            70: RiskVerdict.MEDIUM,
            71: RiskVerdict.HIGH,
            89: RiskVerdict.HIGH,
            90: RiskVerdict.CRITICAL,
            100: RiskVerdict.CRITICAL,
        }
        for score, expected in boundaries.items():
            self.assertEqual(engine.get_verdict(score), expected, f"score={score}")

    def test_threat_override_forces_critical(self):
        engine = FusionEngine()
        context_result = {
            "category": "Calculator",
            "penalties": {"total_raw_penalty": 0, "exported_component_penalty": 0},
            "breakdown": {"acceptable_count": 1, "suspicious_count": 0},
            "suspicious_permissions": [],
            "triggered_combinations": [],
            "unexpected_dangerous_permissions": [],
        }
        threat_data = {
            "is_flagged": True,
            "threat_details": {"family": "Joker", "threat_type": "trojan"},
            "vt_stats": {"malicious": 48, "total_engines": 65},
        }
        result = engine.fuse(context_result=context_result, threat_data=threat_data)
        self.assertGreaterEqual(result["score"], 98)
        self.assertEqual(result["verdict"], RiskVerdict.CRITICAL)
        self.assertTrue(result["score_breakdown"]["threat_intel_override"])


if __name__ == "__main__":
    unittest.main()
