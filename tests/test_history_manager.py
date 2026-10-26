"""Tests for SQLite audit history and report generation."""

import os
import shutil
import tempfile
import unittest


class TestPhase6HistoryAndReporting(unittest.TestCase):
    """Tests for Phase 6 Audit History Manager and Report Generation."""

    def setUp(self):
        from src.history_manager import HistoryManager

        self.temp_db = tempfile.mktemp(suffix=".db")
        self.temp_reports_dir = tempfile.mkdtemp()
        self.history_mgr = HistoryManager(db_path=self.temp_db)

    def tearDown(self):
        import gc

        gc.collect()
        if os.path.exists(self.temp_db):
            try:
                os.remove(self.temp_db)
            except OSError:
                pass
        if os.path.exists(self.temp_reports_dir):
            shutil.rmtree(self.temp_reports_dir, ignore_errors=True)

    def test_history_save_and_retrieve(self):
        """Verify saving and retrieving analysis records from SQLite."""
        from src.pipeline import run_synthetic_demo

        demo_res = run_synthetic_demo("benign_calculator")

        rec_id = self.history_mgr.save_analysis(demo_res)
        self.assertGreater(rec_id, 0)

        record = self.history_mgr.get_analysis(rec_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["package_name"], "org.foss.simplecalculator")
        self.assertEqual(record["score"], demo_res["fusion"]["score"])
        self.assertEqual(record["verdict"], demo_res["fusion"]["verdict"])
        self.assertEqual(record["threat_status"], "VERIFIED_BENIGN")
        self.assertIn("report", record)
        self.assertEqual(record["report"]["manifest"]["package_name"], "org.foss.simplecalculator")

    def test_history_search_and_list(self):
        """Verify querying history records by limit and package name."""
        from src.pipeline import run_synthetic_demo

        res1 = run_synthetic_demo("benign_calculator")
        res2 = run_synthetic_demo("malicious_flashlight")

        id1 = self.history_mgr.save_analysis(res1)
        id2 = self.history_mgr.save_analysis(res2)

        history_list = self.history_mgr.get_history(limit=10)
        self.assertEqual(len(history_list), 2)
        # Most recent first
        self.assertEqual(history_list[0]["id"], id2)
        self.assertEqual(history_list[1]["id"], id1)

        search_res = self.history_mgr.search_by_package("flashlight")
        self.assertEqual(len(search_res), 1)
        self.assertEqual(search_res[0]["id"], id2)

    def test_history_delete_and_clear(self):
        """Verify record deletion and full table purge."""
        from src.pipeline import run_synthetic_demo

        res = run_synthetic_demo("benign_navigation")
        rec_id = self.history_mgr.save_analysis(res)

        self.assertTrue(self.history_mgr.delete_analysis(rec_id))
        self.assertIsNone(self.history_mgr.get_analysis(rec_id))

        # Test clear
        self.history_mgr.save_analysis(res)
        self.history_mgr.save_analysis(res)
        self.assertEqual(len(self.history_mgr.get_history()), 2)
        deleted_count = self.history_mgr.clear_history()
        self.assertEqual(deleted_count, 2)
        self.assertEqual(len(self.history_mgr.get_history()), 0)

    def test_comparative_differential_audit(self):
        """Verify scan-to-scan comparative diff between builds."""
        from src.pipeline import run_synthetic_demo

        res_v1 = run_synthetic_demo("benign_calculator")
        res_v2 = run_synthetic_demo("malicious_flashlight")

        id1 = self.history_mgr.save_analysis(res_v1)
        id2 = self.history_mgr.save_analysis(res_v2)

        diff = self.history_mgr.compare_analyses(id1, id2)
        self.assertIn("comparison", diff)
        cmp = diff["comparison"]

        self.assertGreater(cmp["score_delta"], 0)
        self.assertEqual(cmp["trajectory"], "REGRESSION")
        self.assertIn("android.permission.CAMERA", cmp["permissions_added"])
        self.assertIn("android.permission.READ_CONTACTS", cmp["permissions_added"])
        self.assertGreater(len(cmp["trackers_added"]), 0)

    def test_markdown_report_generation(self):
        """Verify generation and formatting of publication-grade Markdown reports."""
        from src.pipeline import run_synthetic_demo
        from src.report_generator import generate_markdown_report

        res = run_synthetic_demo("malicious_flashlight")
        out_file = os.path.join(self.temp_reports_dir, "test_report.md")

        generated_path = generate_markdown_report(res, output_path=out_file)
        self.assertEqual(os.path.abspath(generated_path), os.path.abspath(out_file))
        self.assertTrue(os.path.exists(out_file))

        with open(out_file, encoding="utf-8") as f:
            md_text = f.read()

        self.assertIn("# CAPRA 2.0 - Privacy Risk Audit Report", md_text)
        self.assertIn("Executive Summary", md_text)
        self.assertIn("com.flashlight.bright.led", md_text)
        self.assertIn("Super Bright LED Flashlight", md_text)
        self.assertIn("Threat Intelligence", md_text)
        self.assertIn("Contextual Permission Evaluation", md_text)
        self.assertIn("Dangerous Permission Combinations", md_text)
        self.assertIn("Machine Learning Permission Risk Estimation", md_text)
        self.assertIn("Advanced Static Analysis & Attack Surface", md_text)
        self.assertIn("Google AdMob", md_text)
        self.assertIn("Actionable Hardening Recommendations", md_text)

    def test_json_report_export(self):
        """Verify exporting complete structured analysis JSON."""
        import json

        from src.pipeline import run_synthetic_demo
        from src.report_generator import export_json_report

        res = run_synthetic_demo("benign_navigation")
        out_file = os.path.join(self.temp_reports_dir, "test_report.json")

        json_path = export_json_report(res, output_path=out_file)
        self.assertTrue(os.path.exists(json_path))

        with open(json_path, encoding="utf-8") as f:
            loaded_data = json.load(f)

        self.assertEqual(loaded_data["manifest"]["package_name"], "org.osm.navigator")
        self.assertIn("fusion", loaded_data)
        self.assertIn("context", loaded_data)

    def test_pipeline_audit_history_integration(self):
        """Verify pipeline automatic audit logging to history_manager."""
        import gc

        from src.pipeline import PrivacyAnalysisPipeline

        temp_db = tempfile.mktemp(suffix=".db")
        try:
            pipeline = PrivacyAnalysisPipeline(history_db_path=temp_db)
            apk_path = os.path.join("data", "apks", "calculator_sample.apk")
            if os.path.exists(apk_path):
                # 1. Normal run logs to history
                res = pipeline.analyze(apk_path, category="Calculator")
                self.assertIsNotNone(res.get("history_id"))

                history = pipeline.get_history()
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0]["id"], res["history_id"])

                # 2. Skip history flag works
                res_skip = pipeline.analyze(
                    apk_path, category="Calculator", options={"skip_history": True}
                )
                self.assertIsNone(res_skip.get("history_id"))
                self.assertEqual(len(pipeline.get_history()), 1)
        finally:
            gc.collect()
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
