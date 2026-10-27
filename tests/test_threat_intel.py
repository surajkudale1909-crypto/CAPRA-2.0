"""Tests for threat intelligence lookups and malware hash reputation."""

import os
import tempfile
import unittest


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


class TestThreatIntelPhase5(unittest.TestCase):
    """Tests for Phase 5 Threat Intelligence & VirusTotal Integration (Suraj's Module)."""

    def setUp(self):
        from src.threat_intel import ThreatIntelEngine

        self.engine = ThreatIntelEngine(api_key=None)

    def test_local_malware_signatures(self):
        """Verify known malware families are recognized from local database."""
        # Anubis
        res_anubis = self.engine.lookup_hash(
            "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
        )
        self.assertEqual(res_anubis["status"], "MALICIOUS")
        self.assertTrue(res_anubis["is_flagged"])
        self.assertEqual(res_anubis["threat_details"]["family"], "Anubis")
        self.assertEqual(res_anubis["source"], "LOCAL_DATABASE")

        # SharkBot
        res_shark = self.engine.lookup_hash(
            "2233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011"
        )
        self.assertEqual(res_shark["status"], "MALICIOUS")
        self.assertTrue(res_shark["is_flagged"])
        self.assertEqual(res_shark["threat_details"]["family"], "SharkBot")

        # Cerberus
        res_cerb = self.engine.lookup_hash(
            "33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122"
        )
        self.assertEqual(res_cerb["status"], "MALICIOUS")
        self.assertEqual(res_cerb["threat_details"]["family"], "Cerberus")

    def test_local_benign_signatures(self):
        """Verify verified open-source apps are recognized from local whitelist."""
        # Fossify Calculator
        res_calc = self.engine.lookup_hash(
            "7c5443c22d6d62c67dfe80df33ea9161ff0fa440f92590bcb45d7008b57613ed"
        )
        self.assertEqual(res_calc["status"], "VERIFIED_BENIGN")
        self.assertTrue(res_calc["is_verified_benign"])
        self.assertEqual(res_calc["source"], "LOCAL_DATABASE")

        # Signal
        res_signal = self.engine.lookup_hash(
            "9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c"
        )
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
            res = engine.lookup_hash(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            )
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

        with patch.object(
            engine, "_fetch_from_virustotal", return_value=(mock_clean_payload, "OK")
        ):
            res = engine.lookup_hash(
                "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
            )
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
            res = engine.lookup_hash(
                "9999999999999999999999999999999999999999999999999999999999999999"
            )
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
                        "last_analysis_stats": {
                            "malicious": 12,
                            "suspicious": 1,
                            "undetected": 50,
                            "harmless": 0,
                        },
                        "popular_threat_classification": {"suggested_threat_label": "adware.agent"},
                    }
                }
            }

            with patch.object(
                engine, "_fetch_from_virustotal", return_value=(mock_payload, "OK")
            ) as mock_fetch:
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


if __name__ == "__main__":
    unittest.main()
