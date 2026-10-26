"""Tests for the unified analysis pipeline orchestration."""

import os
import unittest

from src.extractor import (
    APKNotFoundError,
)
from src.fusion_engine import RiskVerdict


class TestPipelineCore(unittest.TestCase):
    """Tests for the unified pipeline orchestrator (src/pipeline.py)."""

    def test_pipeline_nonexistent_apk_raises(self):
        """Pipeline must raise APKNotFoundError when file is missing."""
        from src.pipeline import analyze_apk

        with self.assertRaises(APKNotFoundError):
            analyze_apk("non_existent_dummy_file.apk")

    def test_pipeline_real_sample_analysis(self):
        """Analyze real sample APK and verify all stage results are returned."""
        from src.pipeline import analyze_apk

        sample_path = os.path.join("data", "apks", "calculator_sample.apk")
        if os.path.exists(sample_path):
            res = analyze_apk(sample_path, category="Calculator")
            self.assertIn("manifest", res)
            self.assertIn("threat", res)
            self.assertIn("context", res)
            self.assertIn("ml", res)
            self.assertIn("fusion", res)
            self.assertEqual(res["category"], "Calculator")
            self.assertIn("score", res["fusion"])
            self.assertIn("verdict", res["fusion"])

    def test_pipeline_synthetic_demo_scenarios(self):
        """Verify all 3 demo scenarios produce valid output schemas."""
        from src.pipeline import run_synthetic_demo

        for scenario in ["benign_calculator", "malicious_flashlight", "benign_navigation"]:
            res = run_synthetic_demo(scenario)
            self.assertIn("manifest", res)
            self.assertIn("threat", res)
            self.assertIn("context", res)
            self.assertIn("ml", res)
            self.assertIn("fusion", res)
            self.assertIn(
                res["fusion"]["verdict"],
                [
                    RiskVerdict.SAFE,
                    RiskVerdict.LOW,
                    RiskVerdict.MEDIUM,
                    RiskVerdict.HIGH,
                    RiskVerdict.CRITICAL,
                ],
            )


class TestPipelinePhase4Integration(unittest.TestCase):
    """Integration tests verifying Phase 4 Advanced Static Analysis in full pipeline."""

    def test_demo_contains_static_analysis(self):
        from src.pipeline import run_synthetic_demo

        res = run_synthetic_demo("malicious_flashlight")
        self.assertIn("static_analysis", res)
        static = res["static_analysis"]
        self.assertIn("trackers", static)
        self.assertIn("network", static)
        self.assertIn("security", static)
        self.assertIn("reachability", static)
        self.assertTrue(static["trackers"]["has_trackers"])
        self.assertTrue(static["reachability"]["has_leakage_path"])

    def test_real_apk_static_analysis_if_present(self):
        from src.pipeline import analyze_apk

        apk_path = os.path.join("data", "apks", "calculator_sample.apk")
        if os.path.exists(apk_path):
            res = analyze_apk(apk_path)
            self.assertIn("static_analysis", res)
            static = res["static_analysis"]
            self.assertIn("trackers", static)
            self.assertIn("network", static)
            self.assertIn("security", static)
            self.assertIn("reachability", static)
            self.assertGreater(static["network"]["total_urls"], 0)


if __name__ == "__main__":
    unittest.main()
