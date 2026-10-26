"""Tests for application configuration and settings."""

import unittest


class TestConfig(unittest.TestCase):
    """Tests for application settings and logging configuration."""

    def test_settings_paths_exist(self):
        """Ensure settings paths point to valid directories."""
        from src.config import settings, setup_logging

        self.assertTrue(settings.data_dir.is_dir())
        self.assertTrue(settings.rules_path.is_file())
        logger = setup_logging()
        self.assertIsNotNone(logger)


if __name__ == "__main__":
    unittest.main()
