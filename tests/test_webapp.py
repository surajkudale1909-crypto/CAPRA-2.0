"""Phase 5: Web Dashboard tests.

Headless FastAPI TestClient coverage: home page, demo endpoints, upload
validation (bad bytes / oversize), end-to-end real-APK analysis, and XSS-safe
rendering of untrusted APK metadata.

GOLDEN RULE: web tests assert the same pinned semantics as tests/test_golden.py
(demo scores/verdicts) — re-verify together if scoring changes.
"""

import io
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CALCULATOR_APK = os.path.join(ROOT, "data", "apks", "calculator_sample.apk")

try:
    from fastapi.testclient import TestClient

    HAS_FASTAPI = True
except Exception:
    HAS_FASTAPI = False


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class TestWebDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from src.webapp import create_app

        cls.client = TestClient(create_app())

    def test_home_page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("CAPRA", r.text)
        self.assertIn("Analyze an Android APK", r.text)

    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")

    def test_demo_endpoint_html(self):
        r = self.client.post("/demo", data={"scenario": "malicious_flashlight"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Critical", r.text)
        self.assertIn("Flashlight", r.text)

    def test_demo_endpoint_json(self):
        r = self.client.get("/api/demo/benign_calculator")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertLessEqual(data["fusion"]["score"], 10)
        self.assertEqual(data["fusion"]["verdict"], "Safe")

    def test_demo_unknown_scenario_404(self):
        r = self.client.get("/api/demo/invented_scenario")
        self.assertEqual(r.status_code, 404)

    def test_upload_garbage_bytes_rejected(self):
        r = self.client.post(
            "/api/analyze",
            files={
                "file": (
                    "evil.apk",
                    io.BytesIO(b"this is not a zip archive"),
                    "application/octet-stream",
                )
            },
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("detail", r.json())

    def test_upload_empty_rejected(self):
        r = self.client.post(
            "/analyze",
            files={"file": ("empty.apk", io.BytesIO(b""), "application/octet-stream")},
        )
        self.assertEqual(r.status_code, 400)

    def test_upload_oversize_rejected(self):
        # Patch the upload cap down to ~1 KB instead of allocating a huge payload.
        from fastapi.testclient import TestClient as TC

        import src.extractor as extractor_mod
        from src.webapp import create_app

        original = extractor_mod.APKSecurityLimits.from_settings
        try:
            extractor_mod.APKSecurityLimits.from_settings = classmethod(
                lambda cls: extractor_mod.APKSecurityLimits(max_apk_size_mb=0.001)
            )
            client = TC(create_app())
            r = client.post(
                "/api/analyze",
                files={"file": ("big.apk", io.BytesIO(b"x" * 4096), "application/octet-stream")},
            )
            self.assertEqual(r.status_code, 413)
        finally:
            extractor_mod.APKSecurityLimits.from_settings = original

    @unittest.skipUnless(os.path.exists(CALCULATOR_APK), "sample APK missing")
    def test_upload_real_apk_end_to_end(self):
        with open(CALCULATOR_APK, "rb") as f:
            r = self.client.post(
                "/analyze",
                files={"file": ("calculator_sample.apk", f, "application/octet-stream")},
                data={"category": "Calculator"},
            )
        self.assertEqual(r.status_code, 200)
        self.assertIn("Risk Score", r.text)
        self.assertIn("Safe", r.text)
        self.assertIn("Context Engine", r.text)

    def test_xss_app_name_escaped(self):
        from src.webapp import render_result

        result = {
            "manifest": {"app_name": "<script>alert(1)</script>", "package_name": "com.x"},
            "fusion": {"score": 5, "verdict": "Safe", "findings": [], "recommendations": []},
            "context": {},
            "ml": {},
            "threat": {},
            "static_analysis": {},
        }
        page = render_result(result)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_error_page_rendering(self):
        from src.webapp import render_result

        page = render_result({}, error="APK file is corrupted <b>")
        self.assertIn("Analysis Failed", page)
        self.assertIn("&lt;b&gt;", page)


if __name__ == "__main__":
    unittest.main()
