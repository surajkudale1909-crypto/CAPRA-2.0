"""Tests for APK manifest extraction and untrusted-input hardening."""

import os
import shutil
import tempfile
import time
import unittest
import zipfile

from src.extractor import (
    APKCorruptedError,
    APKNotFoundError,
    APKParseTimeoutError,
    APKSecurityError,
    APKSecurityLimits,
    APKTooLargeError,
    extract_manifest_info,
    run_with_timeout,
    validate_apk_archive,
)


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


class TestAPKHardening(unittest.TestCase):
    """Tests for untrusted-input hardening: size caps, zip-bomb guards, timeouts."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._counter = 0

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _path(self, name):
        return os.path.join(self.tmpdir, name)

    def _make_zip(self, name, entries, compress=zipfile.ZIP_DEFLATED):
        """entries: list of (inner_name, payload_bytes)."""
        path = self._path(name)
        with zipfile.ZipFile(path, "w", compress) as zf:
            for inner, payload in entries:
                zf.writestr(inner, payload)
        return path

    def test_oversized_file_rejected(self):
        # The size cap applies to the file on disk, checked before any zip parsing
        path = self._path("big.apk")
        with open(path, "wb") as f:
            f.write(b"x" * 50_000)
        limits = APKSecurityLimits(max_apk_size_mb=0.01)  # ~10 KB cap
        with self.assertRaises(APKTooLargeError):
            validate_apk_archive(path, limits=limits)

    def test_zip_bomb_ratio_rejected(self):
        # 5 MB of zeros compresses to a few KB -> ratio far above the limit
        path = self._make_zip("bomb.apk", [("zeros.bin", b"\x00" * (5 * 1024 * 1024))])
        limits = APKSecurityLimits(max_compression_ratio=50.0, max_uncompressed_mb=100)
        with self.assertRaises(APKSecurityError):
            validate_apk_archive(path, limits=limits)

    def test_uncompressed_size_bomb_rejected(self):
        # Random bytes -> low compression ratio, so the uncompressed cap triggers
        payload = os.urandom(2 * 1024 * 1024)
        path = self._make_zip("bigdata.apk", [("data.bin", payload)])
        limits = APKSecurityLimits(max_uncompressed_mb=1, max_compression_ratio=1000)
        with self.assertRaises(APKSecurityError):
            validate_apk_archive(path, limits=limits)

    def test_entry_count_bomb_rejected(self):
        entries = [(f"f{i}.txt", b"ok") for i in range(50)]
        path = self._make_zip("many.apk", entries)
        limits = APKSecurityLimits(max_zip_entries=10)
        with self.assertRaises(APKSecurityError):
            validate_apk_archive(path, limits=limits)

    def test_valid_small_archive_passes(self):
        path = self._make_zip("ok.apk", [("a.txt", b"hello"), ("b.txt", b"world")])
        stats = validate_apk_archive(path, limits=APKSecurityLimits())
        self.assertEqual(stats["entry_count"], 2)
        self.assertGreater(stats["file_size_bytes"], 0)

    def test_missing_file_rejected_by_validator(self):
        from src.extractor import APKNotFoundError

        with self.assertRaises(APKNotFoundError):
            validate_apk_archive(self._path("ghost.apk"))

    def test_run_with_timeout_exhaustion(self):
        with self.assertRaises(APKParseTimeoutError):
            run_with_timeout(time.sleep, 5, timeout_seconds=0.2)

    def test_run_with_timeout_returns_value(self):
        result = run_with_timeout(lambda a, b: a + b, 2, 3, timeout_seconds=5)
        self.assertEqual(result, 5)

    def test_run_with_timeout_propagates_inner_exception(self):

        def _boom():
            raise ValueError("inner failure")

        with self.assertRaises(ValueError):
            run_with_timeout(_boom, timeout_seconds=5)

    def test_extract_manifest_info_times_out(self):
        """A hung parser must hit the time budget instead of blocking forever."""
        from unittest import mock

        import src.extractor as extractor_mod
        from src.extractor import extract_manifest_info

        path = self._make_zip("slow.apk", [("a.txt", b"x")])

        def _slow_apk(*args, **kwargs):
            time.sleep(5)
            return mock.MagicMock()

        with (
            mock.patch.object(extractor_mod, "APK", _slow_apk),
            mock.patch("src.config.settings.apk_parse_timeout_seconds", 1),
        ):
            with self.assertRaises(APKParseTimeoutError):
                extract_manifest_info(path)

    def test_extract_manifest_info_rejects_bomb_via_settings(self):
        """extract_manifest_info enforces the configured limits before parsing."""
        from unittest import mock

        from src.extractor import extract_manifest_info

        path = self._make_zip("bomb2.apk", [("zeros.bin", b"\x00" * (5 * 1024 * 1024))])
        with (
            mock.patch("src.config.settings.max_compression_ratio", 10.0),
            mock.patch("src.config.settings.max_uncompressed_mb", 10_000),
        ):
            with self.assertRaises(APKSecurityError):
                extract_manifest_info(path)


if __name__ == "__main__":
    unittest.main()
