"""Tests for multi-signal risk score fusion and verdict mapping."""

import unittest

from src.fusion_engine import FusionEngine, RiskVerdict


class TestFusionEngine(unittest.TestCase):
    """Tests for risk score normalization and verdict thresholds."""

    def setUp(self):
        self.fusion = FusionEngine(raw_ceiling=160)

    def test_score_normalization_bounds(self):
        """Score must always be strictly bounded between 0 and 100."""
        self.assertEqual(self.fusion.calculate_score(0), 0)
        self.assertEqual(self.fusion.calculate_score(-10), 0)
        self.assertEqual(self.fusion.calculate_score(80), 50)
        self.assertEqual(self.fusion.calculate_score(160), 100)
        self.assertEqual(self.fusion.calculate_score(300), 100)

    def test_verdict_thresholds(self):
        """Verify correct categorical verdict assignment."""
        self.assertEqual(self.fusion.get_verdict(0), RiskVerdict.SAFE)
        self.assertEqual(self.fusion.get_verdict(15), RiskVerdict.SAFE)
        self.assertEqual(self.fusion.get_verdict(25), RiskVerdict.LOW)
        self.assertEqual(self.fusion.get_verdict(45), RiskVerdict.LOW)
        self.assertEqual(self.fusion.get_verdict(50), RiskVerdict.MEDIUM)
        self.assertEqual(self.fusion.get_verdict(70), RiskVerdict.MEDIUM)
        self.assertEqual(self.fusion.get_verdict(75), RiskVerdict.HIGH)
        self.assertEqual(self.fusion.get_verdict(89), RiskVerdict.HIGH)
        self.assertEqual(self.fusion.get_verdict(90), RiskVerdict.CRITICAL)
        self.assertEqual(self.fusion.get_verdict(100), RiskVerdict.CRITICAL)

    def test_full_fusion_output_structure(self):
        """Verify fused output contains all required keys, findings, and recommendations."""
        context_mock = {
            "category": "Flashlight",
            "breakdown": {"acceptable_count": 1, "suspicious_count": 2},
            "suspicious_permissions": [
                {"permission": "android.permission.INTERNET", "penalty": 20, "reason": "No need"}
            ],
            "unexpected_dangerous_permissions": [],
            "triggered_combinations": [
                {
                    "id": "COMB_STORAGE_EXFILTRATION",
                    "name": "Local Storage Exfiltration",
                    "description": "Storage data exfiltration",
                    "penalty": 30,
                }
            ],
            "penalties": {
                "mismatch_penalty": 20,
                "combination_penalty": 30,
                "exported_component_penalty": 0,
                "total_raw_penalty": 50,
            },
            "scoring_weights": {"max_raw_score_ceiling": 160},
        }

        result = self.fusion.fuse(context_mock)
        self.assertIn("score", result)
        self.assertIn("verdict", result)
        self.assertIn("findings", result)
        self.assertIn("recommendations", result)
        self.assertEqual(result["verdict"], RiskVerdict.LOW)  # 50/160 * 100 = 31 -> Low
        self.assertTrue(len(result["findings"]) > 0)
        self.assertTrue(len(result["recommendations"]) > 0)


class TestScoreBlending(unittest.TestCase):
    """Tests for multi-signal composite score blending with tunable weights (Phase 3)."""

    def setUp(self):
        self.fusion = FusionEngine(
            raw_ceiling=160, weights={"heuristic": 0.50, "ml": 0.35, "surface": 0.15}
        )

    def test_blended_score_breakdown(self):
        context_mock = {
            "category": "Flashlight",
            "breakdown": {"acceptable_count": 1, "suspicious_count": 1},
            "suspicious_permissions": [
                {"permission": "android.permission.INTERNET", "penalty": 20}
            ],
            "penalties": {"total_raw_penalty": 32, "exported_component_penalty": 6},
            "scoring_weights": {"max_raw_score_ceiling": 160},
        }
        ml_mock = {"risk_probability": 0.80, "risk_percentage": 80.0, "model_type": "RandomForest"}
        manifest_mock = {
            "target_sdk_version": 34,
            "components": {"exported": {"unprotected_exported": 2}},
        }

        res = self.fusion.fuse(context_mock, manifest_data=manifest_mock, ml_data=ml_mock)
        self.assertIn("score_breakdown", res)
        sb = res["score_breakdown"]
        self.assertEqual(sb["heuristic_weight"], 0.50)
        self.assertEqual(sb["ml_weight"], 0.35)
        self.assertEqual(sb["surface_weight"], 0.15)
        self.assertFalse(sb["threat_intel_override"])
        self.assertGreater(res["score"], 0)

    def test_threat_intel_critical_override(self):
        context_mock = {
            "category": "Calculator",
            "penalties": {"total_raw_penalty": 0, "exported_component_penalty": 0},
            "scoring_weights": {"max_raw_score_ceiling": 160},
        }
        threat_flagged = {
            "is_flagged": True,
            "threat_details": {"family": "Anubis", "threat_type": "Trojan"},
        }
        res = self.fusion.fuse(context_mock, threat_data=threat_flagged)
        self.assertGreaterEqual(res["score"], 98)
        self.assertEqual(res["verdict"], RiskVerdict.CRITICAL)
        self.assertTrue(res["score_breakdown"]["threat_intel_override"])


if __name__ == "__main__":
    unittest.main()
