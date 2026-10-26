"""Tests for automatic app-category detection."""

import unittest


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
            declared_permissions=[
                "android.permission.BODY_SENSORS",
                "android.permission.ACTIVITY_RECOGNITION",
            ],
        )
        self.assertEqual(res.category, "Health/Fitness")

    def test_detect_games(self):
        res = self.detect(
            package_name="com.supercell.clashofclans", app_name="Strategy Arcade Game"
        )
        self.assertEqual(res.category, "Games")

    def test_detect_camera_photo(self):
        res = self.detect(package_name="org.fossify.camera", app_name="HD Photo Camera")
        self.assertEqual(res.category, "Camera/Photo")

    def test_detect_music_video(self):
        res = self.detect(package_name="com.spotify.music", app_name="Music & Podcast Streaming")
        self.assertEqual(res.category, "Music/Video")

    def test_detect_shopping(self):
        res = self.detect(
            package_name="com.amazon.mShop.android.shopping", app_name="Online Store & Deals"
        )
        self.assertEqual(res.category, "Shopping")

    def test_detect_productivity(self):
        res = self.detect(
            package_name="com.microsoft.office.word", app_name="Office Document Notes"
        )
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


if __name__ == "__main__":
    unittest.main()
