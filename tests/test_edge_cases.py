"""Edge-Case Corpus Tests — malformed/hostile inputs must fail cleanly.

Every weird or hostile input must produce a typed APKExtractionError subclass
with an actionable message — never a bare stack trace, hang, or silent success.
"""

import os
import shutil
import tempfile
import unittest
import zipfile

from src.extractor import (
    APKCorruptedError,
    APKExtractionError,
    APKNotFoundError,
    APKParseTimeoutError,
    APKSecurityError,
    APKTooLargeError,
    extract_manifest_info,
    friendly_error_message,
)
from src.pipeline import analyze_apk


class TestMalformedArchiveCorpus(unittest.TestCase):
    """A corpus of broken/hostile archives, each expecting a typed error."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _path(self, name):
        return os.path.join(self.tmpdir, name)

    def test_empty_file(self):
        path = self._path("empty.apk")
        open(path, "wb").close()
        with self.assertRaises(APKCorruptedError):
            extract_manifest_info(path)

    def test_garbage_text_renamed_apk(self):
        path = self._path("garbage.apk")
        with open(path, "wb") as f:
            f.write(b"THIS IS DEFINITELY NOT AN APK " * 40)
        with self.assertRaises(APKCorruptedError):
            extract_manifest_info(path)

    def test_truncated_zip(self):
        path = self._path("truncated.apk")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("classes.dex", b"\xd8" * 5000)
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[:200])  # chop off the central directory
        with self.assertRaises(APKCorruptedError):
            extract_manifest_info(path)

    def test_zip_without_manifest(self):
        path = self._path("nomanifest.apk")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("classes.dex", b"hello")
        with self.assertRaises(APKExtractionError):
            extract_manifest_info(path)

    def test_zip_with_plain_text_manifest(self):
        """AndroidManifest.xml must be binary AXML; a text stub must not parse."""
        path = self._path("textmanifest.apk")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b'<?xml version="1.0"?><manifest package="com.fake"/>')
            zf.writestr("classes.dex", b"hello")
        with self.assertRaises(APKExtractionError):
            extract_manifest_info(path)

    def test_missing_file(self):
        with self.assertRaises(APKNotFoundError):
            extract_manifest_info(self._path("ghost.apk"))

    def test_every_failure_is_typed(self):
        """No malformed input may leak a non-APKExtractionError exception."""
        corpus = {
            "empty2.apk": b"",
            "garbage2.apk": b"\x00\x01\x02NOTZIP",
            "halfzip.apk": None,  # built below
        }
        with zipfile.ZipFile(self._path("halfzip.apk"), "w") as zf:
            zf.writestr("x", b"y")
        with open(self._path("halfzip.apk"), "rb") as f:
            corpus["halfzip.apk"] = f.read()[:40]

        for name, payload in corpus.items():
            path = self._path(name)
            with open(path, "wb") as f:
                f.write(payload)
            with self.subTest(case=name):
                with self.assertRaises(APKExtractionError):
                    extract_manifest_info(path)


class TestPipelineErrorPropagation(unittest.TestCase):
    """analyze_apk must surface typed errors, never swallow them."""

    def test_pipeline_missing_file(self):
        with self.assertRaises(APKNotFoundError):
            analyze_apk("does_not_exist.apk", options={"skip_threat": True, "skip_history": True})

    def test_pipeline_garbage_file(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "junk.apk")
            with open(path, "wb") as f:
                f.write(b"junk" * 100)
            with self.assertRaises(APKExtractionError):
                analyze_apk(path, options={"skip_threat": True, "skip_history": True})
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestFriendlyErrorMessages(unittest.TestCase):
    """User-facing error mapping stays actionable for every typed failure."""

    def test_timeout_message_is_actionable(self):
        msg = friendly_error_message(APKParseTimeoutError("took too long"))
        self.assertIn("timed out", msg.lower())
        self.assertIn("safely abandoned", msg.lower())

    def test_security_message_flags_bomb(self):
        msg = friendly_error_message(APKSecurityError("ratio 9999:1"))
        self.assertIn("zip bomb", msg.lower())

    def test_size_message_mentions_limit(self):
        msg = friendly_error_message(APKTooLargeError("too big"))
        self.assertIn("safety limit", msg.lower())

    def test_not_found_message(self):
        msg = friendly_error_message(APKNotFoundError("gone"))
        self.assertIn("not found", msg.lower())

    def test_corrupted_message(self):
        msg = friendly_error_message(APKCorruptedError("bad zip"))
        self.assertIn("valid apk", msg.lower())

    def test_unknown_exception_passthrough(self):
        self.assertEqual(friendly_error_message(ValueError("meh")), "meh")


if __name__ == "__main__":
    unittest.main()
