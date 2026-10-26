"""Unit and Integration Tests for Context-Aware Mobile App Privacy Risk Analyzer.

EDAI Group 8 - VIT Pune
"""

import os
import tempfile
import unittest

from src.context_engine import ContextEngine, ContextRuleError
from src.extractor import (
    APKCorruptedError,
    APKNotFoundError,
    extract_manifest_info,
)
from src.fusion_engine import FusionEngine, RiskVerdict


def _tk_available() -> bool:
    """Return True when Tkinter can create a root window (import + display)."""
    try:
        import tkinter as tk

        root = tk.Tk()
        root.destroy()
        return True
    except Exception:
        return False


HAS_TK = _tk_available()


class TestExtractor(unittest.TestCase):
    """Tests for the manifest extraction module."""

    def test_nonexistent_apk(self):
        """Verify APKNotFoundError is raised when file does not exist."""
        with self.assertRaises(APKNotFoundError):
            extract_manifest_info("non_existent_dummy_file.apk")

    def test_corrupted_apk(self):
        """Verify APKCorruptedError is raised when file is not a valid zip archive."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"NOT_A_VALID_ZIP_HEADER_DATA")
            bad_apk_path = f.name

        try:
            with self.assertRaises(APKCorruptedError):
                extract_manifest_info(bad_apk_path)
        finally:
            if os.path.exists(bad_apk_path):
                os.remove(bad_apk_path)

    def test_real_sample_apk_extraction(self):
        """Test extraction on actual downloaded sample APK if present."""
        sample_path = os.path.join("data", "apks", "calculator_sample.apk")
        if os.path.exists(sample_path):
            data = extract_manifest_info(sample_path)
            self.assertEqual(data["package_name"], "org.fossify.math")
            self.assertEqual(data["app_name"], "Calculator")
            self.assertGreater(data["components"]["activities_count"], 0)


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


class TestThreatIntel(unittest.TestCase):
    """Tests for Threat Intelligence hash database and reputation lookup (Suraj's Module)."""

    def setUp(self):
        from src.threat_intel import ThreatIntelEngine
        self.engine = ThreatIntelEngine()

    def test_database_loads(self):
        """Verify database indices load."""
        stats = self.engine.get_database_stats()
        self.assertGreater(stats["malware_signatures_count"], 0)
        self.assertGreater(stats["benign_signatures_count"], 0)

    def test_benign_apk_hash_lookup(self):
        """Check hash matching for sample Fossify Calculator."""
        sample_path = os.path.join("data", "apks", "calculator_sample.apk")
        if os.path.exists(sample_path):
            res = self.engine.lookup_apk(sample_path)
            self.assertEqual(res["status"], "VERIFIED_BENIGN")
            self.assertTrue(res["is_verified_benign"])
            self.assertFalse(res["is_flagged"])

    def test_unknown_hash_lookup(self):
        """Check behavior on dummy file with unindexed hash."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"UNIQUE_RANDOM_BYTES_FOR_UNKNOWN_HASH_TEST_9999")
            temp_apk = f.name

        try:
            res = self.engine.lookup_apk(temp_apk)
            self.assertEqual(res["status"], "UNKNOWN")
            self.assertFalse(res["is_flagged"])
        finally:
            if os.path.exists(temp_apk):
                os.remove(temp_apk)


class TestMLPipeline(unittest.TestCase):
    """Tests for Random Forest permission risk estimation (Ishan's Module)."""

    def setUp(self):
        from src.ml_pipeline import FEATURE_PERMISSIONS, PermissionMLPipeline
        self.pipeline = PermissionMLPipeline()
        self.features = FEATURE_PERMISSIONS

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


@unittest.skipUnless(HAS_TK, "tkinter/display not available in this environment")
class TestDesktopGUI(unittest.TestCase):
    """Tests for Desktop Tkinter GUI connection and execution (Samriddhi's Module)."""

    def test_gui_initialization_and_pipeline_connection(self):
        """Verify GUI connects to all 5 pipeline modules without import errors."""
        import tkinter as tk
        from src.gui import PrivacyAnalyzerGUI

        root = tk.Tk()
        root.withdraw()
        try:
            app = PrivacyAnalyzerGUI(root)
            self.assertIsNotNone(app.threat_engine)
            self.assertIsNotNone(app.context_engine)
            self.assertIsNotNone(app.ml_pipeline)
            self.assertIsNotNone(app.fusion_engine)
            self.assertIsNotNone(app.gauge)

            # Test execution of the 5-stage pipeline on sample APK
            sample_path = os.path.join("data", "apks", "calculator_sample.apk")
            if os.path.exists(sample_path):
                app._execute_analysis(sample_path, "Calculator")
                root.update()
                self.assertIn("Calculator", app.txt_overview.get("1.0", tk.END))
                self.assertEqual(app.status_var.get(), "Analysis completed successfully.")
        finally:
            root.destroy()


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
            self.assertIn(res["fusion"]["verdict"], [RiskVerdict.SAFE, RiskVerdict.LOW, RiskVerdict.MEDIUM, RiskVerdict.HIGH, RiskVerdict.CRITICAL])


class TestConfig(unittest.TestCase):
    """Tests for application settings and logging configuration."""

    def test_settings_paths_exist(self):
        """Ensure settings paths point to valid directories."""
        from src.config import settings, setup_logging
        self.assertTrue(settings.data_dir.is_dir())
        self.assertTrue(settings.rules_path.is_file())
        logger = setup_logging()
        self.assertIsNotNone(logger)


class TestCategoryDetector(unittest.TestCase):
    """Tests for automatic category detection and confidence scoring (Phase 2)."""

    def setUp(self):
        from src.category_detector import detect_app_category
        self.detect = detect_app_category

    def test_detect_calculator_by_package_and_name(self):
        res = self.detect(package_name="org.fossify.math", app_name="Calculator")
        self.assertEqual(res.category, "Calculator")
        self.assertGreaterEqual(res.confidence, 0.70)
        self.assertFalse(res.is_overridden)

    def test_detect_flashlight(self):
        res = self.detect(package_name="com.devuni.flashlight", app_name="Torch Light")
        self.assertEqual(res.category, "Flashlight")
        self.assertGreaterEqual(res.confidence, 0.70)

    def test_detect_navigation(self):
        res = self.detect(package_name="org.osm.navigator", app_name="Offline Maps GPS")
        self.assertEqual(res.category, "Navigation")

    def test_detect_banking_finance(self):
        res = self.detect(package_name="com.chase.sig.android", app_name="Chase Mobile Banking")
        self.assertEqual(res.category, "Banking/Finance")

    def test_detect_messaging(self):
        res = self.detect(package_name="org.telegram.messenger", app_name="Telegram Chat")
        self.assertEqual(res.category, "Messaging")

    def test_detect_social_media(self):
        res = self.detect(package_name="com.twitter.android", app_name="Social Network Feed")
        self.assertEqual(res.category, "Social Media")

    def test_detect_health_fitness(self):
        res = self.detect(
            package_name="com.strava.workout",
            app_name="Running & Cycling",
            declared_permissions=["android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION"],
        )
        self.assertEqual(res.category, "Health/Fitness")

    def test_detect_games(self):
        res = self.detect(package_name="com.supercell.clashofclans", app_name="Strategy Arcade Game")
        self.assertEqual(res.category, "Games")

    def test_detect_camera_photo(self):
        res = self.detect(package_name="org.fossify.camera", app_name="HD Photo Camera")
        self.assertEqual(res.category, "Camera/Photo")

    def test_detect_music_video(self):
        res = self.detect(package_name="com.spotify.music", app_name="Music & Podcast Streaming")
        self.assertEqual(res.category, "Music/Video")

    def test_detect_shopping(self):
        res = self.detect(package_name="com.amazon.mShop.android.shopping", app_name="Online Store & Deals")
        self.assertEqual(res.category, "Shopping")

    def test_detect_productivity(self):
        res = self.detect(package_name="com.microsoft.office.word", app_name="Office Document Notes")
        self.assertEqual(res.category, "Productivity")

    def test_detect_education(self):
        res = self.detect(package_name="com.duolingo", app_name="Language Learning Study")
        self.assertEqual(res.category, "Education")

    def test_manual_category_override(self):
        res = self.detect(
            package_name="org.fossify.math",
            app_name="Calculator",
            override_category="Education",
        )
        self.assertEqual(res.category, "Education")
        self.assertTrue(res.is_overridden)
        self.assertEqual(res.confidence, 1.0)


class TestExpandedContextRules(unittest.TestCase):
    """Tests for 13 categories and modern permissions in ContextEngine (Phase 2)."""

    def setUp(self):
        self.engine = ContextEngine()

    def test_thirteen_categories_present(self):
        cats = self.engine.get_supported_categories()
        expected = [
            "Calculator", "Flashlight", "Navigation", "Social Media",
            "Messaging", "Banking/Finance", "Health/Fitness", "Games",
            "Camera/Photo", "Music/Video", "Shopping", "Productivity", "Education"
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


class TestMLEvaluationAndExplainability(unittest.TestCase):
    """Tests for dataset loader, model comparison, and local explainability (Phase 3)."""

    def test_empirical_dataset_loader(self):
        from src.ml_pipeline import load_dataset
        csv_path = os.path.join("data", "datasets", "sample_android_malware_dataset.csv")
        X, y, source_type, source_desc = load_dataset(csv_path)
        self.assertEqual(source_type, "EMPIRICAL")
        self.assertIn("sample_android_malware_dataset.csv", source_desc)
        self.assertGreater(len(X), 20)
        self.assertEqual(len(X), len(y))

    def test_synthetic_fallback_loader(self):
        from src.ml_pipeline import load_dataset
        X, y, source_type, source_desc = load_dataset("non_existent_dataset.csv")
        self.assertEqual(source_type, "SYNTHETIC")
        self.assertIn("SYNTHETIC", source_desc)

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


class TestScoreBlending(unittest.TestCase):
    """Tests for multi-signal composite score blending with tunable weights (Phase 3)."""

    def setUp(self):
        self.fusion = FusionEngine(raw_ceiling=160, weights={"heuristic": 0.50, "ml": 0.35, "surface": 0.15})

    def test_blended_score_breakdown(self):
        context_mock = {
            "category": "Flashlight",
            "breakdown": {"acceptable_count": 1, "suspicious_count": 1},
            "suspicious_permissions": [{"permission": "android.permission.INTERNET", "penalty": 20}],
            "penalties": {"total_raw_penalty": 32, "exported_component_penalty": 6},
            "scoring_weights": {"max_raw_score_ceiling": 160},
        }
        ml_mock = {"risk_probability": 0.80, "risk_percentage": 80.0, "model_type": "RandomForest"}
        manifest_mock = {"target_sdk_version": 34, "components": {"exported": {"unprotected_exported": 2}}}

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
        threat_flagged = {"is_flagged": True, "threat_details": {"family": "Anubis", "threat_type": "Trojan"}}
        res = self.fusion.fuse(context_mock, threat_data=threat_flagged)
        self.assertGreaterEqual(res["score"], 98)
        self.assertEqual(res["verdict"], RiskVerdict.CRITICAL)
        self.assertTrue(res["score_breakdown"]["threat_intel_override"])


class TestTrackerDetector(unittest.TestCase):
    """Tests for Phase 4 Tracker Detection module."""

    def setUp(self):
        from src.tracker_detector import TrackerDetector
        self.detector = TrackerDetector()

    def test_clean_classes_return_zero_trackers(self):
        classes = ["com.example.calculator.MainActivity", "com.example.calculator.MathUtils"]
        res = self.detector.detect_from_classes(classes)
        self.assertEqual(res["tracker_count"], 0)
        self.assertFalse(res["has_trackers"])
        self.assertEqual(res["risk_level"], "None")

    def test_detects_common_trackers(self):
        classes = [
            "Lcom/google/android/gms/ads/AdView;",
            "Lcom/appsflyer/AppsFlyerLib;",
            "Lcom/facebook/ads/AudienceNetworkAds;"
        ]
        res = self.detector.detect_from_classes(classes)
        self.assertEqual(res["tracker_count"], 3)
        self.assertTrue(res["has_trackers"])
        self.assertIn("Advertising", res["categories"])
        self.assertIn("Analytics / Attribution", res["categories"])
        names = [t["name"] for t in res["detected_trackers"]]
        self.assertIn("Google AdMob", names)
        self.assertIn("AppsFlyer", names)
        self.assertIn("Meta / Facebook Audience Network", names)


class TestNetworkDetector(unittest.TestCase):
    """Tests for Phase 4 Network Footprint Extraction module."""

    def setUp(self):
        from src.network_detector import NetworkDetector
        self.detector = NetworkDetector()

    def test_detects_insecure_http_and_public_ips(self):
        strings = [
            "http://insecure-api.test.com/payload",
            "https://secure.example.com/data",
            "198.51.100.42",
            "127.0.0.1",  # Localhost - should be ignored
            "192.168.1.1",  # Private LAN - should be ignored
            "http://malicious.top/track"
        ]
        res = self.detector.analyze_strings(strings)
        self.assertEqual(res["insecure_http_count"], 2)
        self.assertIn("198.51.100.42", res["raw_public_ips"])
        self.assertNotIn("127.0.0.1", res["raw_public_ips"])
        self.assertNotIn("192.168.1.1", res["raw_public_ips"])
        self.assertGreater(res["network_risk_score"], 0)
        self.assertGreater(len(res["findings"]), 0)


class TestSecurityAnalyzer(unittest.TestCase):
    """Tests for Phase 4 Security Analyzer module."""

    def setUp(self):
        from src.security_analyzer import SecurityAnalyzer
        self.analyzer = SecurityAnalyzer()

    def test_dcl_and_native_libs_detection(self):
        classes = ["dalvik.system.DexClassLoader", "com.example.app.MainActivity"]
        strings = ["dalvik.system.DexClassLoader", "Ljava/lang/reflect/Method;", "getDeclaredMethod"]
        files = ["lib/arm64-v8a/libpayload.so", "res/layout/activity_main.xml"]

        res = self.analyzer.analyze_bytecode_features(classes, strings, files)
        self.assertTrue(res["has_dcl"])
        self.assertTrue(res["has_native_code"])
        self.assertEqual(res["native_libraries_count"], 1)
        self.assertGreater(res["security_risk_score"], 0)

    def test_obfuscation_detection(self):
        # 30 short named classes and 10 normal named classes
        classes = [f"com.example.a.{chr(97 + (i % 26))}" for i in range(30)]
        classes += [f"com.example.app.ServiceComponent{i}" for i in range(10)]
        res = self.analyzer.analyze_bytecode_features(classes, [], [])
        self.assertTrue(res["is_obfuscated"])
        self.assertGreater(res["obfuscation_ratio"], 0.20)


class TestReachabilityAnalyzer(unittest.TestCase):
    """Tests for Phase 4 Call-Graph Reachability module."""

    def setUp(self):
        from src.reachability import ReachabilityAnalyzer
        self.analyzer = ReachabilityAnalyzer()

    def test_intra_method_direct_leak_path(self):
        mock_graph = {
            "com.example.Tracker.exfiltrate": {
                "class": "com.example.Tracker",
                "sources": ["getLastKnownLocation"],
                "sinks": ["openConnection"]
            }
        }
        res = self.analyzer.analyze_mock_graph(mock_graph)
        self.assertTrue(res["has_leakage_path"])
        self.assertEqual(res["leakage_paths_count"], 1)
        path = res["paths"][0]
        self.assertEqual(path["type"], "intra-method")
        self.assertEqual(path["confidence"], "High (Direct Call)")
        self.assertIn("limitations_disclaimer", res)

    def test_clean_graph_no_leaks(self):
        mock_graph = {
            "com.example.Calc.compute": {
                "class": "com.example.Calc",
                "sources": [],
                "sinks": []
            }
        }
        res = self.analyzer.analyze_mock_graph(mock_graph)
        self.assertFalse(res["has_leakage_path"])
        self.assertEqual(res["leakage_paths_count"], 0)


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


class TestThreatIntelPhase5(unittest.TestCase):
    """Tests for Phase 5 Threat Intelligence & VirusTotal Integration (Suraj's Module)."""

    def setUp(self):
        from src.threat_intel import ThreatIntelEngine
        self.engine = ThreatIntelEngine(api_key=None)

    def test_local_malware_signatures(self):
        """Verify known malware families are recognized from local database."""
        # Anubis
        res_anubis = self.engine.lookup_hash("a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0")
        self.assertEqual(res_anubis["status"], "MALICIOUS")
        self.assertTrue(res_anubis["is_flagged"])
        self.assertEqual(res_anubis["threat_details"]["family"], "Anubis")
        self.assertEqual(res_anubis["source"], "LOCAL_DATABASE")

        # SharkBot
        res_shark = self.engine.lookup_hash("2233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011")
        self.assertEqual(res_shark["status"], "MALICIOUS")
        self.assertTrue(res_shark["is_flagged"])
        self.assertEqual(res_shark["threat_details"]["family"], "SharkBot")

        # Cerberus
        res_cerb = self.engine.lookup_hash("33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122")
        self.assertEqual(res_cerb["status"], "MALICIOUS")
        self.assertEqual(res_cerb["threat_details"]["family"], "Cerberus")

    def test_local_benign_signatures(self):
        """Verify verified open-source apps are recognized from local whitelist."""
        # Fossify Calculator
        res_calc = self.engine.lookup_hash("7c5443c22d6d62c67dfe80df33ea9161ff0fa440f92590bcb45d7008b57613ed")
        self.assertEqual(res_calc["status"], "VERIFIED_BENIGN")
        self.assertTrue(res_calc["is_verified_benign"])
        self.assertEqual(res_calc["source"], "LOCAL_DATABASE")

        # Signal
        res_signal = self.engine.lookup_hash("9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c")
        self.assertEqual(res_signal["status"], "VERIFIED_BENIGN")
        self.assertTrue(res_signal["is_verified_benign"])

    def test_virustotal_api_malicious_detection(self):
        """Verify parsing of live VirusTotal positive detections."""
        import tempfile
        from unittest.mock import patch
        from src.threat_intel import ThreatIntelEngine

        temp_cache = tempfile.mktemp(suffix=".json")
        engine = ThreatIntelEngine(api_key="mock_vt_key_test", cache_path=temp_cache)
        mock_vt_payload = {
            "data": {
                "attributes": {
                    "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 3,
                        "undetected": 15,
                        "harmless": 0,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.banker/anubis",
                        "popular_threat_category": [{"value": "trojan"}],
                    },
                    "names": ["malicious_banking_sample.apk"],
                }
            }
        }

        with patch.object(engine, "_fetch_from_virustotal", return_value=(mock_vt_payload, "OK")):
            res = engine.lookup_hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
            self.assertEqual(res["status"], "MALICIOUS")
            self.assertTrue(res["is_flagged"])
            self.assertEqual(res["source"], "VIRUSTOTAL_API")
            self.assertIsNotNone(res["vt_stats"])
            self.assertEqual(res["vt_stats"]["malicious"], 45)
            self.assertEqual(res["vt_stats"]["total_engines"], 63)
            self.assertEqual(res["threat_details"]["family"], "trojan.banker/anubis")

        if os.path.exists(temp_cache):
            os.remove(temp_cache)

    def test_virustotal_api_clean_detection(self):
        """Verify clean VirusTotal evaluation with 0 detections."""
        import tempfile
        from unittest.mock import patch
        from src.threat_intel import ThreatIntelEngine

        temp_cache = tempfile.mktemp(suffix=".json")
        engine = ThreatIntelEngine(api_key="mock_vt_key_test", cache_path=temp_cache)
        mock_clean_payload = {
            "data": {
                "attributes": {
                    "sha256": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 68,
                        "harmless": 2,
                    },
                    "popular_threat_classification": {},
                    "names": ["clean_utility_app.apk"],
                }
            }
        }

        with patch.object(engine, "_fetch_from_virustotal", return_value=(mock_clean_payload, "OK")):
            res = engine.lookup_hash("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff")
            self.assertEqual(res["status"], "VERIFIED_BENIGN")
            self.assertTrue(res["is_verified_benign"])
            self.assertEqual(res["source"], "VIRUSTOTAL_API")
            self.assertEqual(res["vt_stats"]["malicious"], 0)

        if os.path.exists(temp_cache):
            os.remove(temp_cache)

    def test_virustotal_rate_limit_graceful_fallback(self):
        """Verify that HTTP 429 rate limits do not crash the engine and fall back gracefully."""
        import tempfile
        from unittest.mock import patch
        from src.threat_intel import ThreatIntelEngine

        temp_cache = tempfile.mktemp(suffix=".json")
        engine = ThreatIntelEngine(api_key="mock_key", cache_path=temp_cache)
        with patch.object(engine, "_fetch_from_virustotal", return_value=(None, "RATE_LIMIT")):
            res = engine.lookup_hash("9999999999999999999999999999999999999999999999999999999999999999")
            self.assertEqual(res["status"], "UNKNOWN")
            self.assertFalse(res["is_flagged"])
            self.assertIn("OFFLINE_FALLBACK", res["source"])

        if os.path.exists(temp_cache):
            os.remove(temp_cache)


    def test_virustotal_caching_layer(self):
        """Verify persistent caching prevents redundant API queries."""
        import tempfile
        from unittest.mock import patch
        from src.threat_intel import ThreatIntelEngine

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            cache_file = f.name

        try:
            engine = ThreatIntelEngine(api_key="mock_key", cache_path=cache_file)
            test_hash = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            mock_payload = {
                "data": {
                    "attributes": {
                        "sha256": test_hash,
                        "last_analysis_stats": {"malicious": 12, "suspicious": 1, "undetected": 50, "harmless": 0},
                        "popular_threat_classification": {"suggested_threat_label": "adware.agent"},
                    }
                }
            }

            with patch.object(engine, "_fetch_from_virustotal", return_value=(mock_payload, "OK")) as mock_fetch:
                # First call: hits API and caches
                res1 = engine.lookup_hash(test_hash)
                self.assertEqual(res1["source"], "VIRUSTOTAL_API")
                self.assertEqual(mock_fetch.call_count, 1)

                # Second call: hits cache, does NOT call API again
                res2 = engine.lookup_hash(test_hash)
                self.assertEqual(res2["source"], "VIRUSTOTAL_CACHE")
                self.assertEqual(mock_fetch.call_count, 1)  # Still 1
        finally:
            if os.path.exists(cache_file):
                os.remove(cache_file)



class TestPhase6HistoryAndReporting(unittest.TestCase):
    """Tests for Phase 6 Audit History Manager and Report Generation."""

    def setUp(self):
        import tempfile
        from src.history_manager import HistoryManager

        self.temp_db = tempfile.mktemp(suffix=".db")
        self.temp_reports_dir = tempfile.mkdtemp()
        self.history_mgr = HistoryManager(db_path=self.temp_db)

    def tearDown(self):
        import gc
        import shutil
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

        with open(out_file, "r", encoding="utf-8") as f:
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

        with open(json_path, "r", encoding="utf-8") as f:
            loaded_data = json.load(f)

        self.assertEqual(loaded_data["manifest"]["package_name"], "org.osm.navigator")
        self.assertIn("fusion", loaded_data)
        self.assertIn("context", loaded_data)

    def test_pipeline_audit_history_integration(self):
        """Verify pipeline automatic audit logging to history_manager."""
        import gc
        import tempfile
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
                res_skip = pipeline.analyze(apk_path, category="Calculator", options={"skip_history": True})
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





