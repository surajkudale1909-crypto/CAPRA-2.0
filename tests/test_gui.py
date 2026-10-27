"""Tests for the desktop Tkinter GUI (skipped when tkinter/display is unavailable)."""

import os
import unittest


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
                # Worker posts to the UI queue; main thread drains it explicitly
                app._pump_ui_queue()
                self.assertIn("Calculator", app.txt_overview.get("1.0", tk.END))
                self.assertEqual(app.status_var.get(), "Analysis completed successfully.")
                self.assertFalse(app._analysis_running)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
