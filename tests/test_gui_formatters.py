"""Tests for GUI presentation logic (src/gui_formatters.py — Tk-free).

These run everywhere (including headless CI) and cover every visual decision
the desktop GUI makes: risk bands, gauge geometry, permission row colors,
theme palettes, settings persistence, and text builders.
"""

import math
import os
import tempfile
import unittest

from src.gui_formatters import (
    RISK_BANDS,
    add_recent_file,
    build_comparison_text,
    build_overview_text,
    build_recommendations_text,
    combination_rows,
    default_settings,
    format_bytes,
    format_file_label,
    gauge_geometry,
    load_settings,
    permission_rows,
    save_settings,
    score_band,
    theme_palette,
)


class TestScoreBands(unittest.TestCase):
    def test_band_boundaries_match_golden_semantics(self):
        self.assertEqual(score_band(0)["name"], "Safe")
        self.assertEqual(score_band(20)["name"], "Safe")
        self.assertEqual(score_band(21)["name"], "Low")
        self.assertEqual(score_band(45)["name"], "Low")
        self.assertEqual(score_band(46)["name"], "Medium")
        self.assertEqual(score_band(70)["name"], "Medium")
        self.assertEqual(score_band(71)["name"], "High")
        self.assertEqual(score_band(89)["name"], "High")
        self.assertEqual(score_band(90)["name"], "Critical")
        self.assertEqual(score_band(100)["name"], "Critical")

    def test_out_of_range_scores_clamped(self):
        self.assertEqual(score_band(-5)["name"], "Safe")
        self.assertEqual(score_band(150)["name"], "Critical")

    def test_every_band_has_color(self):
        for band in RISK_BANDS:
            self.assertTrue(band["color"].startswith("#"))


class TestGaugeGeometry(unittest.TestCase):
    def test_geometry_scales_with_size(self):
        geo = gauge_geometry(50, size=240)
        cx, cy = geo["center"]
        self.assertAlmostEqual(cx, 120.0)
        self.assertGreater(cy, 0)
        self.assertGreater(geo["radius"], 50)

    def test_needle_at_zero_points_left(self):
        geo = gauge_geometry(0, size=200)
        cx, cy = geo["center"]
        nx, ny = geo["needle"]
        self.assertLess(nx, cx)  # points toward 9 o'clock
        self.assertAlmostEqual(ny, cy, delta=1.0)

    def test_needle_at_full_points_right(self):
        geo = gauge_geometry(100, size=200)
        cx, cy = geo["center"]
        nx, ny = geo["needle"]
        self.assertGreater(nx, cx)
        self.assertAlmostEqual(ny, cy, delta=1.0)

    def test_needle_at_half_points_up(self):
        geo = gauge_geometry(50, size=200)
        cx, cy = geo["center"]
        nx, ny = geo["needle"]
        self.assertAlmostEqual(nx, cx, delta=1.0)
        self.assertLess(ny, cy)  # screen y grows downward

    def test_progress_extent_tracks_score(self):
        # Signed Tk extents sweep over the top (negative direction).
        self.assertAlmostEqual(gauge_geometry(0)["progress_extent"], 0.0)
        self.assertAlmostEqual(gauge_geometry(100)["progress_extent"], -180.0)
        self.assertAlmostEqual(gauge_geometry(50)["progress_extent"], -90.0)

    def test_segments_cover_full_sweep(self):
        geo = gauge_geometry(0)
        total = sum(s["extent"] for s in geo["segments"])
        self.assertAlmostEqual(total, -180.0, delta=1.0)

    def test_band_sweep_direction_over_the_top(self):
        # Tk create_arc angles increase counter-clockwise (point at
        # cx + r·cos α, cy − r·sin α), so the top-half sweep must start at
        # 180° (9 o'clock) with NEGATIVE extents ending at 0° (3 o'clock).
        geo = gauge_geometry(50)
        self.assertAlmostEqual(geo["segments"][0]["start"], 180.0)
        self.assertLess(geo["segments"][0]["extent"], 0)
        last = geo["segments"][-1]
        self.assertAlmostEqual(last["start"] + last["extent"], 0.0, delta=1.0)

    def test_text_stack_sits_below_hub(self):
        # Score/unit/verdict live below the hub so the needle sweep never
        # crosses the numbers (the layout bug this geometry was rebuilt for).
        geo = gauge_geometry(65, size=250)
        cx, cy = geo["center"]
        for key in ("score_pos", "unit_pos", "verdict_pos"):
            px, py = geo[key]
            self.assertGreater(py, cy, f"{key} must sit below the hub")
        # verdict is the lowest element and must fit inside the canvas
        self.assertLess(geo["verdict_pos"][1] + 16, geo["height"])

    def test_needle_stays_inside_arc(self):
        geo = gauge_geometry(65, size=250)
        cx, cy = geo["center"]
        nx, ny = geo["needle"]
        self.assertLess(math.hypot(nx - cx, ny - cy), geo["radius"])


class TestPermissionRows(unittest.TestCase):
    CONTEXT = {
        "suspicious_permissions": [
            {
                "permission": "android.permission.ACCESS_FINE_LOCATION",
                "penalty": 15,
                "reason": "unexpected for Calculator",
            }
        ],
        "unexpected_dangerous_permissions": [
            {
                "permission": "android.permission.READ_SMS",
                "penalty": 40,
                "reason": "not in category baseline",
            }
        ],
        "triggered_combinations": [
            {
                "name": "SMS Interception",
                "risk_type": "Credential Theft",
                "penalty": 45,
                "matched_permissions": [
                    "android.permission.READ_SMS",
                    "android.permission.INTERNET",
                ],
                "description": "2FA theft",
            }
        ],
        "contextual_exemptions": [
            {
                "name": "Location Tracking",
                "risk_type": "Geolocation",
                "penalty": 0,
                "matched_permissions": ["android.permission.ACCESS_FINE_LOCATION"],
                "exempt_reason": "expected for Navigation",
            }
        ],
        "acceptable_permissions": [{"permission": "android.permission.VIBRATE", "penalty": 0}],
        "neutral_permissions": ["android.permission.INTERNET"],
    }

    def test_rows_carry_color_tags(self):
        rows = permission_rows(self.CONTEXT)
        tags = {r["name"]: r["tag"] for r in rows}
        self.assertEqual(tags["ACCESS_FINE_LOCATION"], "warn")
        self.assertEqual(tags["READ_SMS"], "bad")
        self.assertEqual(tags["SMS Interception"], "bad")
        self.assertEqual(tags["Location Tracking"], "info")
        self.assertEqual(tags["VIBRATE"], "ok")
        self.assertEqual(tags["INTERNET"], "muted")

    def test_permission_names_shortened(self):
        rows = permission_rows(self.CONTEXT)
        for r in rows:
            self.assertNotIn("android.permission.", r["name"])

    def test_combination_rows_include_exemptions(self):
        rows = combination_rows(self.CONTEXT)
        triggered = [r for r in rows if not r["exempt"]]
        exempt = [r for r in rows if r["exempt"]]
        self.assertEqual(len(triggered), 1)
        self.assertEqual(len(exempt), 1)
        self.assertIn("READ_SMS + INTERNET", triggered[0]["permissions"])
        self.assertEqual(exempt[0]["penalty"], 0)

    def test_empty_context(self):
        self.assertEqual(permission_rows({}), [])
        self.assertEqual(combination_rows({}), [])


class TestThemes(unittest.TestCase):
    def test_dark_and_light_palettes_complete(self):
        for dark in (True, False):
            pal = theme_palette(dark)
            for key in ("bg", "card_bg", "text", "muted", "ok", "warn", "bad", "info"):
                self.assertIn(key, pal)

    def test_palettes_differ(self):
        self.assertNotEqual(theme_palette(True)["bg"], theme_palette(False)["bg"])


class TestSettingsPersistence(unittest.TestCase):
    def test_defaults(self):
        s = default_settings()
        self.assertEqual(s["theme"], "dark")
        self.assertEqual(s["recent_files"], [])

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "gui_settings.json")
            s = default_settings()
            s["theme"] = "light"
            s["recent_files"] = ["/a/x.apk", "/a/y.apk"]
            self.assertTrue(save_settings(s, path))
            loaded = load_settings(path)
            self.assertEqual(loaded["theme"], "light")
            self.assertEqual(loaded["recent_files"], ["/a/x.apk", "/a/y.apk"])

    def test_corrupt_settings_fall_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "gui_settings.json")
            with open(path, "w") as f:
                f.write("{not json!!")
            loaded = load_settings(path)
            self.assertEqual(loaded, default_settings())

    def test_missing_settings_file(self):
        loaded = load_settings("/nonexistent/dir/gui_settings.json")
        self.assertEqual(loaded, default_settings())

    def test_recent_files_dedupe_and_cap(self):
        s = default_settings()
        with tempfile.TemporaryDirectory() as tmp:
            paths = [os.path.join(tmp, f"app{i}.apk") for i in range(12)]
            for p in paths:
                add_recent_file(s, p)
            self.assertLessEqual(len(s["recent_files"]), 8)
            self.assertEqual(s["recent_files"][0], os.path.abspath(paths[-1]))
            add_recent_file(s, paths[-1])  # re-add newest -> stays first, no dupe
            self.assertEqual(len(s["recent_files"]), 8)
            self.assertEqual(s["recent_files"][0], os.path.abspath(paths[-1]))


class TestTextBuilders(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(500), "500 B")
        self.assertIn("KB", format_bytes(2048))
        self.assertIn("MB", format_bytes(5 * 1024 * 1024))

    def test_format_file_label_missing_file(self):
        self.assertEqual(format_file_label("/nope/missing.apk"), "missing.apk")

    def test_overview_contains_identity_and_category(self):
        text = build_overview_text(
            {
                "app_name": "Calculator",
                "package_name": "org.fossify.math",
                "target_sdk_version": 36,
                "min_sdk_version": 26,
                "version_name": "1.0",
                "version_code": 1,
                "total_permissions_count": 1,
                "components": {"exported": {"total_exported": 6, "unprotected_exported": 5}},
            },
            {"category": "Calculator", "category_description": "numerical app"},
            {"score": 15, "verdict": "Safe", "findings": ["ok"]},
            {"status": "VERIFIED_BENIGN", "hashes": {"sha256": "abc"}},
            {"risk_percentage": 7.7, "ml_verdict": "Benign Profile", "decision_threshold": 0.45},
        )
        self.assertIn("Calculator", text)
        self.assertIn("org.fossify.math", text)
        self.assertIn("ML Risk Estimation", text)

    def test_overview_includes_static_and_empirical(self):
        text = build_overview_text(
            {"app_name": "X", "package_name": "x", "components": {"exported": {}}},
            {
                "category": "Flashlight",
                "category_description": "d",
                "empirical_context": {
                    "available": True,
                    "sample_size": 16,
                    "store_categories": ["Tools"],
                    "category_norm_notes": ["READ_SMS is rare"],
                },
            },
            {"score": 98, "verdict": "Critical", "findings": ["threat flagged"]},
            {"status": "MALICIOUS", "hashes": {}},
            {"risk_percentage": 91.2, "ml_verdict": "High Risk / Anomaly"},
            static_analysis={
                "trackers": {"tracker_count": 4},
                "network": {"total_urls": 8, "insecure_http_count": 3},
                "security": {"secrets_detected": [{"type": "AWS Access Key ID"}]},
                "reachability": {"has_leakage_path": True, "leakage_paths_count": 2},
            },
        )
        self.assertIn("Trackers Detected:  4", text)
        self.assertIn("AWS Access Key ID", text)
        self.assertIn("Egress Paths", text)
        self.assertIn("READ_SMS is rare", text)
        self.assertIn("threat flagged", text)

    def test_recommendations_text(self):
        text = build_recommendations_text({"recommendations": ["R1", "R2"]})
        self.assertIn("1. R1", text)
        self.assertIn("2. R2", text)
        self.assertIn("No specific", build_recommendations_text({}))

    def test_comparison_text(self):
        text = build_comparison_text(
            {
                "record_1": {"id": 1, "package_name": "a", "score": 10, "verdict": "Safe"},
                "record_2": {"id": 2, "package_name": "a", "score": 40, "verdict": "Low"},
                "trajectory": "REGRESSION",
                "trajectory_summary": "Privacy risk increased by +30 points",
                "score_delta": 30,
                "ml_delta": 12.5,
                "added_trackers": ["EvilTracker"],
            }
        )
        self.assertIn("REGRESSION", text)
        self.assertIn("EvilTracker", text)
        self.assertIn("#1", text)


if __name__ == "__main__":
    unittest.main()
