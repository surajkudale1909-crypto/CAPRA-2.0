"""Phase 4: Analysis Depth tests.

Covers the fixed + deepened call-graph reachability (inter-method paths, correct
xref direction), hardcoded-secret detection with redaction, deep-link attack
surface parsing, the expanded tracker catalog, and model provenance.

GOLDEN RULE: any test here that pins scores/ranges must be consciously
re-verified if detector changes shift scoring semantics (tests/test_golden.py).
"""

import os
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CALCULATOR_APK = os.path.join(ROOT, "data", "apks", "calculator_sample.apk")

NS = "{http://schemas.android.com/apk/res/android}"


class TestInterMethodReachability(unittest.TestCase):
    """Call-graph paths between source-calling and sink-calling methods."""

    @classmethod
    def setUpClass(cls):
        from src.reachability import ReachabilityAnalyzer

        cls.analyzer = ReachabilityAnalyzer()
        cls.methods_map = {
            "Lcom/ex/A;->getData": {
                "class": "Lcom/ex/A;",
                "sources": ["Location (getLastKnownLocation)"],
                "sinks": [],
            },
            "Lcom/ex/B;->sendData": {
                "class": "Lcom/ex/B;",
                "sources": [],
                "sinks": ["HttpURLConnection (connect)"],
            },
            "Lcom/ex/C;->both": {
                "class": "Lcom/ex/C;",
                "sources": ["Clipboard (getPrimaryClip)"],
                "sinks": ["Raw Socket (connect)"],
            },
        }

    def test_inter_method_path_forward_edge(self):
        res = self.analyzer.analyze_mock_graph(
            self.methods_map,
            call_edges=[("Lcom/ex/A;->getData", "Lcom/ex/B;->sendData")],
        )
        inter = [p for p in res["paths"] if p["type"] == "inter-method"]
        self.assertEqual(len(inter), 1)
        self.assertIn("invokes", inter[0]["description"])
        self.assertEqual(inter[0]["confidence_score"], 0.75)

    def test_inter_method_path_reverse_edge(self):
        # B (sink) calls A (source): A's data flows into B's egress
        res = self.analyzer.analyze_mock_graph(
            self.methods_map,
            call_edges=[("Lcom/ex/B;->sendData", "Lcom/ex/A;->getData")],
        )
        inter = [p for p in res["paths"] if p["type"] == "inter-method"]
        self.assertEqual(len(inter), 1)
        self.assertIn("invokes", inter[0]["description"])

    def test_no_edges_no_inter_method_paths(self):
        res = self.analyzer.analyze_mock_graph(self.methods_map)
        self.assertFalse(any(p["type"] == "inter-method" for p in res["paths"]))
        self.assertTrue(any(p["type"] == "intra-method" for p in res["paths"]))

    def test_call_graph_finding_reported(self):
        res = self.analyzer.analyze_mock_graph(
            self.methods_map,
            call_edges=[("Lcom/ex/A;->getData", "Lcom/ex/B;->sendData")],
        )
        self.assertTrue(any("Call-graph-mediated" in f for f in res["findings"]))

    def test_inter_method_deduplicated(self):
        res = self.analyzer.analyze_mock_graph(
            self.methods_map,
            call_edges=[
                ("Lcom/ex/A;->getData", "Lcom/ex/B;->sendData"),
                ("Lcom/ex/A;->getData", "Lcom/ex/B;->sendData"),
            ],
        )
        inter = [p for p in res["paths"] if p["type"] == "inter-method"]
        self.assertEqual(len(inter), 1)

    def test_path_count_capped(self):
        big_map = {}
        edges = []
        for i in range(40):
            big_map[f"Lcom/x/S{i};->get"] = {
                "class": f"Lcom/x/S{i};",
                "sources": ["Location (getLastKnownLocation)"],
                "sinks": [],
            }
            big_map[f"Lcom/x/T{i};->post"] = {
                "class": f"Lcom/x/T{i};",
                "sources": [],
                "sinks": ["HttpURLConnection (connect)"],
            }
            edges.append((f"Lcom/x/S{i};->get", f"Lcom/x/T{i};->post"))
        res = self.analyzer.analyze_mock_graph(big_map, call_edges=edges)
        self.assertLessEqual(len(res["paths"]), 25)

    @unittest.skipUnless(os.path.exists(CALCULATOR_APK), "sample APK missing")
    def test_xref_direction_finds_callers_on_real_apk(self):
        """Regression: callers of framework APIs must come from get_xref_from().

        The pre-Phase-4 code read get_xref_to() (callees) which is always empty
        for external APIs — silently disabling reachability on every real APK.
        """
        from loguru import logger as lg

        lg.disable("androguard")
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.apk import APK
        from androguard.core.dex import DEX

        apk = APK(CALCULATOR_APK)
        dx = Analysis()
        for b in apk.get_all_dex():
            dx.add(DEX(b))
        dx.create_xref()

        total_callers = 0
        for m in dx.find_methods(classname="Ljava/lang/String;", methodname="length"):
            total_callers += len(self.analyzer._app_callers(m))
        self.assertGreater(total_callers, 0)


class TestHardcodedSecrets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from src.security_analyzer import SecurityAnalyzer

        cls.analyzer = SecurityAnalyzer()

    def test_aws_key_detected_and_redacted(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        res = self.analyzer.detect_hardcoded_secrets([f'const KEY = "{secret}";'])
        self.assertEqual(res["secrets_count"], 1)
        det = res["secrets_detected"][0]
        self.assertEqual(det["type"], "AWS Access Key ID")
        sample = det["samples"][0]
        self.assertNotIn(secret, sample)
        self.assertIn("…", sample)

    def test_google_api_key_and_jwt(self):
        strings = [
            "AIzaSyD12345678901234567890123456789012",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
        ]
        res = self.analyzer.detect_hardcoded_secrets(strings)
        types = {d["type"] for d in res["secrets_detected"]}
        self.assertIn("Google API Key", types)
        self.assertIn("JSON Web Token", types)

    def test_private_key_block(self):
        res = self.analyzer.detect_hardcoded_secrets(
            ["-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."]
        )
        self.assertEqual(res["secrets_detected"][0]["type"], "Embedded Private Key Block")

    def test_generic_credential_assignment(self):
        res = self.analyzer.detect_hardcoded_secrets(
            ['String api_key = "sk_live_51H8xYzABCDEF1234567890";']
        )
        self.assertEqual(res["secrets_detected"][0]["type"], "Hardcoded Credential Assignment")

    def test_clean_strings_no_secrets(self):
        res = self.analyzer.detect_hardcoded_secrets(
            ["Hello world", "https://example.com/api", "length", "calculator"]
        )
        self.assertEqual(res["secrets_count"], 0)
        self.assertEqual(res["secret_risk_score"], 0.0)

    def test_secrets_flow_into_bytecode_score(self):
        res = self.analyzer.analyze_bytecode_features(
            [], ['const KEY = "AKIAIOSFODNN7EXAMPLE";'], []
        )
        self.assertTrue(res["secrets_detected"])
        self.assertGreater(res["security_risk_score"], 0)

    def test_full_secret_never_in_findings(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        res = self.analyzer.detect_hardcoded_secrets([secret])
        for f in res["findings"]:
            self.assertNotIn(secret, f)


class TestDeepLinkSurface(unittest.TestCase):
    """Exported-component intent-filter / deep-link parsing."""

    MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.ex.app">
      <application>
        <activity android:name=".DeepActivity" android:exported="true">
          <intent-filter>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="https" android:host="ex.example.com" android:pathPrefix="/pay"/>
          </intent-filter>
        </activity>
        <activity android:name=".GuardedActivity" android:exported="true" android:permission="com.ex.PERM">
          <intent-filter>
            <action android:name="com.ex.ACTION"/>
          </intent-filter>
        </activity>
        <service android:name=".InternalService" android:exported="false"/>
      </application>
    </manifest>
    """

    def _parse(self):
        from src.extractor import _parse_exported_components

        root = ET.fromstring(self.MANIFEST_XML)

        class StubAPK:
            def get_android_manifest_xml(self):
                return root

        return _parse_exported_components(StubAPK(), target_sdk=34)

    def test_exported_counts(self):
        res = self._parse()
        self.assertEqual(res["total_exported"], 2)
        self.assertEqual(res["unprotected_exported"], 1)

    def test_deeplink_extracted(self):
        res = self._parse()
        self.assertIn("https://ex.example.com", res["deeplinks"])
        self.assertEqual(res["browsable_unprotected"], 1)

    def test_component_intent_filters(self):
        res = self._parse()
        deep = [c for c in res["activities"] if c["name"] == ".DeepActivity"][0]
        self.assertTrue(deep["is_browsable"])
        self.assertIn("https://ex.example.com", deep["deeplinks"])
        filt = deep["intent_filters"][0]
        self.assertIn("android.intent.action.VIEW", filt["actions"])
        self.assertEqual(filt["data"][0]["pathPrefix"], "/pay")

    def test_guarded_component_not_browsable_flagged(self):
        res = self._parse()
        guarded = [c for c in res["activities"] if c["name"] == ".GuardedActivity"][0]
        self.assertTrue(guarded["is_protected"])
        self.assertFalse(guarded["is_browsable"])


class TestTrackerCatalog(unittest.TestCase):
    def test_catalog_expanded(self):
        import json

        data = json.load(open(os.path.join(ROOT, "data", "trackers.json"), encoding="utf-8"))
        self.assertGreaterEqual(len(data["trackers"]), 30)

    def test_new_trackers_detectable(self):
        from src.tracker_detector import TrackerDetector

        det = TrackerDetector()
        res = det.detect_from_classes(
            ["com.onesignal.OneSignal", "com.amplitude.AmplitudeClient", "com.example.app.Main"]
        )
        names = {t["name"] for t in res["detected_trackers"]}
        self.assertIn("OneSignal", names)
        self.assertIn("Amplitude", names)


class TestModelProvenance(unittest.TestCase):
    def test_payload_carries_provenance(self):
        import joblib

        from src.ml_pipeline import PermissionMLPipeline

        p = PermissionMLPipeline()
        payload = joblib.load(p.model_path)
        prov = payload.get("provenance", {})
        self.assertTrue(prov.get("dataset_files"))
        self.assertTrue(prov.get("dataset_sha256"))
        for sha in prov["dataset_sha256"].values():
            self.assertEqual(len(sha), 64)
        self.assertIn("sklearn_version", prov)
        self.assertIn("trained_at", prov)

    def test_predict_risk_exposes_provenance(self):
        from src.ml_pipeline import PermissionMLPipeline

        p = PermissionMLPipeline()
        res = p.predict_risk(["android.permission.INTERNET"])
        self.assertIn("model_provenance", res)


if __name__ == "__main__":
    unittest.main()
