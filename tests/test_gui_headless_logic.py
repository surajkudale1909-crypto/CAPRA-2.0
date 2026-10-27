"""Headless harness that drives PrivacyAnalyzerGUI against a mock Tk.

The real GUI test (tests/test_gui.py) requires an X display + python3-tk, so it
skips locally and runs under xvfb in CI. This module reproduces CI's exact
pinned flow against a faithful-enough mock so init-path / wiring bugs surface
in any environment. sys.modules is restored afterwards so tests/test_gui.py
still sees real tkinter in CI.
"""

import importlib
import os
import sys
import types
import unittest

APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

HISTORY_ID = "gui_headless_history"


# --------------------------------------------------------------------------
# Mock widgets: implement exactly the surface src/gui.py touches.
# --------------------------------------------------------------------------
class _Widget:
    def __init__(self, master=None, **kw):
        self.master = master
        self.kw = dict(kw)
        self._bindings = []

    # geometry managers
    def pack(self, **kw):
        self.kw.update(kw)
        return self

    def grid(self, **kw):
        self.kw.update(kw)
        return self

    def place(self, **kw):
        self.kw.update(kw)
        return self

    def place_forget(self):
        return self

    def configure(self, **kw):
        self.kw.update(kw)

    config = configure

    def bind(self, seq=None, func=None, **kw):
        self._bindings.append((seq, func))

    def focus_set(self):
        pass

    def update_idletasks(self):
        pass

    def update(self):
        pass

    def destroy(self):
        pass

    def winfo_exists(self):
        return 1

    def winfo_rootx(self):
        return 0

    def winfo_rooty(self):
        return 0

    def winfo_width(self):
        return 280

    def winfo_height(self):
        return 300

    def after(self, ms, fn=None, *args):
        return f"after-{len(self._bindings)}"

    def after_cancel(self, ident):
        pass

    def title(self, *a):
        pass

    def geometry(self, *a):
        pass

    def protocol(self, *a):
        pass

    def resizable(self, *a):
        pass

    def option_add(self, *a):
        pass

    def grab_set(self):
        pass

    def __getattr__(self, name):
        # Catch-all for any remaining widget method (minsize, lift, state, ...).
        # Only widget surfaces are mocked; PrivacyAnalyzerGUI's own attributes
        # still raise AttributeError normally, so wiring bugs are not masked.
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *a, **kw: None


class _Tk(_Widget):
    pass


class _Toplevel(_Widget):
    pass


class _Canvas(_Widget):
    def __init__(self, master=None, **kw):
        super().__init__(master, **kw)
        self._next = 1
        self._items = {}

    def create_arc(self, *a, **kw):
        self._items[self._next] = kw
        self._next += 1
        return self._next - 1

    def create_line(self, *a, **kw):
        return self.create_arc(*a, **kw)

    def create_text(self, *a, **kw):
        return self.create_arc(*a, **kw)

    def create_oval(self, *a, **kw):
        return self.create_arc(*a, **kw)

    def delete(self, *items):
        self._items.clear()

    def coords(self, *a):
        return [0, 0, 0, 0]

    def itemconfig(self, item, **kw):
        pass

    itemconfigure = itemconfig


class _Text(_Widget):
    def __init__(self, master=None, **kw):
        super().__init__(master, **kw)
        self._content = ""

    def insert(self, index, text):
        self._content += str(text)

    def delete(self, start, end=None):
        self._content = ""

    def get(self, start, end=None):
        return self._content

    def see(self, *a):
        pass


class _Entry(_Widget):
    def __init__(self, master=None, **kw):
        super().__init__(master, **kw)
        self._value = str(kw.get("textvariable", ""))

    def get(self):
        var = self.kw.get("textvariable")
        return var.get() if hasattr(var, "get") else self._value

    def delete(self, a, b=None):
        self._value = ""

    def insert(self, index, text):
        self._value += str(text)

    def selection_range(self, *a):
        pass

    def icursor(self, *a):
        pass


class _StringVar:
    def __init__(self, master=None, value=""):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class _Menu(_Widget):
    def add_cascade(self, **kw):
        pass

    def add_command(self, **kw):
        pass

    def add_separator(self, **kw):
        pass


class _Label(_Widget):
    pass


class _Frame(_Widget):
    pass


class _Button(_Widget):
    pass


# ---- ttk ----
class _Style:
    def __init__(self, master=None):
        self._rules = {}

    def configure(self, name, **kw):
        self._rules[name] = kw

    def theme_use(self, name=None):
        return "clam"


class _Combobox(_Widget):
    def set(self, value):
        self.kw["value"] = value

    def get(self):
        return self.kw.get("value", "")

    def current(self, index=None):
        return 0


class _Progressbar(_Widget):
    def start(self, *a):
        pass

    def stop(self):
        pass

    def step(self, *a):
        pass


class _Notebook(_Widget):
    def add(self, child, **kw):
        pass


class _Scrollbar(_Widget):
    def set(self, *a):
        pass


class _Treeview(_Widget):
    def __init__(self, master=None, **kw):
        super().__init__(master, **kw)
        self._rows = {}
        self._seq = 0
        self._selection = []

    def insert(self, parent, index, iid=None, text="", values=(), tags=()):
        if iid is None:
            self._seq += 1
            iid = f"I{self._seq}"
        self._rows[iid] = {"text": text, "values": list(values), "tags": tags}
        return iid

    def delete(self, *items):
        for i in items:
            self._rows.pop(i, None)

    def get_children(self, item=None):
        return list(self._rows)

    def item(self, iid, **kw):
        if kw:
            self._rows.setdefault(iid, {"text": "", "values": [], "tags": []}).update(kw)
            return None
        return self._rows.get(iid, {"text": "", "values": [], "tags": []})

    def heading(self, *a, **kw):
        pass

    def column(self, *a, **kw):
        pass

    def selection(self):
        return list(self._selection)

    def see(self, *a):
        pass

    def tag_configure(self, *a, **kw):
        pass

    def yview(self, *a):
        pass

    def xview(self, *a):
        pass


class _FakeMessagebox(types.ModuleType):
    def __init__(self):
        super().__init__("tkinter.messagebox")
        self.calls = []

    def showerror(self, title, message, **kw):
        self.calls.append(("error", title, message))

    def showinfo(self, title, message, **kw):
        self.calls.append(("info", title, message))

    def showwarning(self, title, message, **kw):
        self.calls.append(("warning", title, message))

    def askyesno(self, title, message, **kw):
        self.calls.append(("yesno", title, message))
        return True


class _FakeFiledialog(types.ModuleType):
    def __init__(self):
        super().__init__("tkinter.filedialog")
        self.next_path = ""

    def askopenfilename(self, **kw):
        return self.next_path

    def asksaveasfilename(self, **kw):
        return self.next_path


def _build_fake_tk_modules():
    tk_mod = types.ModuleType("tkinter")
    tk_mod.Tk = _Tk
    tk_mod.Toplevel = _Toplevel
    tk_mod.Canvas = _Canvas
    tk_mod.Text = _Text
    tk_mod.Entry = _Entry
    tk_mod.Label = _Label
    tk_mod.Frame = _Frame
    tk_mod.Button = _Button
    tk_mod.Menu = _Menu
    tk_mod.StringVar = _StringVar
    tk_mod.END = "end"
    tk_mod.LEFT = "left"
    tk_mod.RIGHT = "right"
    tk_mod.X = "x"
    tk_mod.Y = "y"
    tk_mod.BOTH = "both"
    tk_mod.NONE = "none"

    ttk_mod = types.ModuleType("tkinter.ttk")
    ttk_mod.Style = _Style
    ttk_mod.Combobox = _Combobox
    ttk_mod.Progressbar = _Progressbar
    ttk_mod.Notebook = _Notebook
    ttk_mod.Scrollbar = _Scrollbar
    ttk_mod.Treeview = _Treeview
    ttk_mod.Button = _Button
    ttk_mod.Frame = _Frame
    ttk_mod.Label = _Label
    tk_mod.ttk = ttk_mod

    messagebox_mod = _FakeMessagebox()
    filedialog_mod = _FakeFiledialog()
    tk_mod.messagebox = messagebox_mod
    tk_mod.filedialog = filedialog_mod
    return {
        "tkinter": tk_mod,
        "tkinter.ttk": ttk_mod,
        "tkinter.messagebox": messagebox_mod,
        "tkinter.filedialog": filedialog_mod,
    }


_SAVED_MODULES = {}
_FAKE_MODULES = {}


def setUpModule():
    global _FAKE_MODULES
    _FAKE_MODULES = _build_fake_tk_modules()
    for name, mod in _FAKE_MODULES.items():
        _SAVED_MODULES[name] = sys.modules.get(name)
        sys.modules[name] = mod
    sys.modules.pop("src.gui", None)


def tearDownModule():
    for name, original in _SAVED_MODULES.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    sys.modules.pop("src.gui", None)
    _SAVED_MODULES.clear()


class TestHeadlessGUIPinnedFlow(unittest.TestCase):
    """Reproduce tests/test_gui.py's pinned expectations against mock Tk."""

    @classmethod
    def setUpClass(cls):
        cls.gui_mod = importlib.import_module("src.gui")
        cls.tk = _FAKE_MODULES["tkinter"]
        root = _Tk()
        cls.app = cls.gui_mod.PrivacyAnalyzerGUI(root)

    def test_engine_wiring(self):
        self.assertIsNotNone(self.app.threat_engine)
        self.assertIsNotNone(self.app.context_engine)
        self.assertIsNotNone(self.app.ml_pipeline)
        self.assertIsNotNone(self.app.fusion_engine)
        self.assertIsNotNone(self.app.gauge)

    def test_pinned_synchronous_flow(self):
        """Exact CI pins: overview text, status message, busy flag."""
        reports_dir = os.path.join(APP_DIR, "reports")
        before = set(os.listdir(reports_dir)) if os.path.isdir(reports_dir) else set()
        sample = os.path.join(APP_DIR, "data", "apks", "calculator_sample.apk")
        try:
            self.app._execute_analysis(sample, "Calculator")
            self.app._pump_ui_queue()
            overview = self.app.txt_overview.get("1.0", self.tk.END)
            self.assertIn("Calculator", overview)
            self.assertEqual(self.app.status_var.get(), "Analysis completed successfully.")
            self.assertFalse(self.app._analysis_running)
        finally:
            after = set(os.listdir(reports_dir)) if os.path.isdir(reports_dir) else set()
            for name in after - before:
                if name.startswith("privacy_audit_") and name.endswith(".md"):
                    os.remove(os.path.join(reports_dir, name))

    def test_theme_toggle_keeps_running(self):
        self.app._toggle_theme()
        self.assertIn(self.app._settings["theme"], ("dark", "light"))
        self.app._toggle_theme()

    def test_cancel_and_busy_guard(self):
        self.app._analysis_running = False
        self.app._set_busy(True)
        self.assertTrue(self.app._analysis_running)
        self.app._cancel_requested = True
        self.app._set_busy(False)
        self.assertFalse(self.app._analysis_running)

    def test_history_window(self):
        self.app._open_history()

    def test_error_queue_item(self):
        self.app._analysis_running = True
        self.app._ui_queue.put(("error", RuntimeError("boom")))
        self.app._pump_ui_queue()
        self.assertFalse(self.app._analysis_running)

    def test_export_helpers_exist(self):
        self.assertTrue(callable(self.app._export_markdown))
        self.assertTrue(callable(self.app._export_json))

    def test_vt_key_apply_and_clear(self):
        """Settings dialog logic: persist + live-apply + clear (no real file I/O)."""
        saved = {}
        original_save = self.gui_mod.save_settings
        self.gui_mod.save_settings = lambda s, **kw: saved.update(s) or True
        try:
            self.assertTrue(self.app._apply_vt_key("  test-key-1234567890  "))
            self.assertEqual(self.app._settings["vt_api_key"], "test-key-1234567890")
            self.assertEqual(saved.get("vt_api_key"), "test-key-1234567890")
            self.assertEqual(self.app.pipeline.threat_engine.api_key, "test-key-1234567890")
            self.assertFalse(self.app._apply_vt_key("   "))  # empty -> rejected
            self.app._clear_vt_key()
            self.assertEqual(self.app._settings["vt_api_key"], "")
            self.assertIsNone(self.app.pipeline.threat_engine.api_key)
        finally:
            self.gui_mod.save_settings = original_save

    def test_vt_key_dialog_opens(self):
        self.app._open_vt_key_dialog()


if __name__ == "__main__":
    unittest.main()
