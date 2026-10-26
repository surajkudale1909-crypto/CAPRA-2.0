"""Tests for tracker, network, security, and reachability analyzers."""

import unittest


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
            "Lcom/facebook/ads/AudienceNetworkAds;",
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
            "http://malicious.top/track",
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
        strings = [
            "dalvik.system.DexClassLoader",
            "Ljava/lang/reflect/Method;",
            "getDeclaredMethod",
        ]
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
                "sinks": ["openConnection"],
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
            "com.example.Calc.compute": {"class": "com.example.Calc", "sources": [], "sinks": []}
        }
        res = self.analyzer.analyze_mock_graph(mock_graph)
        self.assertFalse(res["has_leakage_path"])
        self.assertEqual(res["leakage_paths_count"], 0)


if __name__ == "__main__":
    unittest.main()
