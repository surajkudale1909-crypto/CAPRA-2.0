"""Desktop Graphical User Interface (GUI) Module.

Samriddhi's Module (EDAI Group 8), polished in the GUI Polish phase.
Built using Python Tkinter and TTK. Provides an interactive desktop workbench
with an APK file chooser (recent files + optional drag & drop), category
dropdown, a banded risk-gauge canvas with needle, a color-coded permissions
table, exfiltration-combination views, scan history with two-scan comparison,
Markdown/JSON export, light/dark theming, and ML feature importance inspection.

Threading contract (Phase 1 — do not regress):
    Worker threads NEVER touch Tk widgets. They post (kind, payload) messages
    to self._ui_queue; a main-thread `root.after` poller drains the queue and
    performs every widget update. Busy-state guards prevent concurrent scans.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time

# Ensure repository root is on sys.path for direct execution (e.g. python src/gui.py)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from src.extractor import friendly_error_message
from src.gui_formatters import (
    RISK_BANDS,
    add_recent_file,
    build_comparison_text,
    build_overview_text,
    build_recommendations_text,
    combination_rows,
    display_threat_status,
    format_file_label,
    gauge_geometry,
    load_settings,
    mask_api_key,
    permission_rows,
    save_settings,
    theme_palette,
)
from src.pipeline import get_default_pipeline, run_synthetic_demo

CATEGORY_CHOICES = [
    "(Auto-Detect)",
    "Calculator",
    "Flashlight",
    "Navigation",
    "Social Media",
    "Messaging",
    "Banking/Finance",
    "Health/Fitness",
    "Games",
    "Camera/Photo",
    "Music/Video",
    "Shopping",
    "Productivity",
    "Education",
]

STATUS_READY = "Ready to analyze APK."
STATUS_SUCCESS = "Analysis completed successfully."


class RiskGaugeCanvas(tk.Canvas):
    """Semicircular risk gauge with color bands, needle, and animated re-draw."""

    def __init__(
        self,
        parent,
        size: int = 240,
        bg_color: str = "#ffffff",
        palette: Optional[Dict[str, str]] = None,
        **kwargs,
    ):
        super().__init__(
            parent,
            width=size,
            height=int(size * 0.88),
            bg=bg_color,
            highlightthickness=0,
            **kwargs,
        )
        self.size = size
        self.palette = palette or theme_palette(True)
        self._anim_job: Optional[str] = None
        self._current_score = 0.0
        self.draw_gauge(score=0, verdict="SAFE")

    def _get_score_color(self, score: int) -> str:
        for band in RISK_BANDS:
            if band["lo"] <= score <= band["hi"]:
                return band["color"]
        return RISK_BANDS[-1]["color"]

    def restyle(self, palette: Dict[str, str], score: float = 0.0, verdict: str = "SAFE"):
        """Re-color for theme changes and redraw."""
        self.palette = palette
        self.config(bg=palette.get("gauge_bg", "#ffffff"))
        self.draw_gauge(score=score, verdict=verdict)

    def draw_gauge(self, score: int, verdict: str):
        """Draw the banded semicircular gauge with needle and score text."""
        self._current_score = float(max(0, min(100, int(score))))
        self._draw_static(self._current_score, verdict or "SAFE", animate=False)

    def _draw_static(self, score: float, verdict: str, animate: bool = True):
        self.delete("all")
        geo = gauge_geometry(score, self.size)
        cx, cy = geo["center"]
        radius = geo["radius"]
        band_color = geo["band_color"]

        # Background band segments
        for seg in geo["segments"]:
            self.create_arc(
                cx - radius,
                cy - radius,
                cx + radius,
                cy + radius,
                start=seg["start"],
                extent=seg["extent"],
                style="arc",
                width=max(10, self.size // 14),
                outline=seg["color"],
            )

        # Progress arc overlay (the traversed portion, in its band color)
        if abs(geo["progress_extent"]) > 0.5:
            self.create_arc(
                cx - radius,
                cy - radius,
                cx + radius,
                cy + radius,
                start=geo["progress_start"],
                extent=geo["progress_extent"],
                style="arc",
                width=max(6, self.size // 22),
                outline=band_color,
            )

        # Needle + hub
        nx, ny = geo["needle"]
        self.create_line(cx, cy, nx, ny, width=max(3, self.size // 60), fill=band_color)
        hub = geo["hub_radius"]
        self.create_oval(cx - hub, cy - hub, cx + hub, cy + hub, fill=band_color, outline="")

        # Score / unit / verdict text (stacked BELOW the hub — the needle
        # sweep and the number never overlap).
        sx, sy = geo["score_pos"]
        self.create_text(
            sx,
            sy,
            text=f"{int(round(score))}",
            font=("Segoe UI", max(22, self.size // 7), "bold"),
            fill=band_color,
        )
        ux, uy = geo["unit_pos"]
        self.create_text(
            ux,
            uy,
            text="/ 100",
            anchor="w",
            font=("Segoe UI", max(8, self.size // 24)),
            fill=self.palette.get("muted", "#64748b"),
        )
        vx, vy = geo["verdict_pos"]
        self.create_text(
            vx,
            vy,
            text=f"{str(verdict).upper()} RISK",
            font=("Segoe UI", max(11, self.size // 18), "bold"),
            fill=band_color,
        )

        if animate:
            self._anim_job = None

    def animate_to(self, score: int, verdict: str, steps: int = 8):
        """Smoothly animate the needle from the current score to the target."""
        if self._anim_job is not None:
            try:
                self.after_cancel(self._anim_job)
            except Exception:
                pass
            self._anim_job = None
        target = float(max(0, min(100, int(score))))
        start = self._current_score
        step = (target - start) / max(1, steps)

        def tick(i: int = 0, current: float = None):
            if current is None:
                current = start
            if i >= steps:
                self._draw_static(target, verdict, animate=False)
                self._current_score = target
                self._anim_job = None
                return
            current += step
            self._draw_static(current, verdict, animate=False)
            self._anim_job = self.after(25, tick, i + 1, current)

        tick()


class PrivacyAnalyzerGUI:
    """Main Desktop Application Window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CAPRA 2.0 - Context-Aware Mobile App Privacy Risk Analyzer")
        self.root.geometry("1120x780")
        self.root.minsize(960, 660)

        # Initialize pipeline and engine instances
        self.pipeline = get_default_pipeline()
        self.context_engine = self.pipeline.context_engine
        self.fusion_engine = self.pipeline.fusion_engine
        self.threat_engine = self.pipeline.threat_engine
        self.ml_pipeline = self.pipeline.ml_pipeline

        # Persisted preferences (theme, last dir, recent files)
        self._settings = load_settings()
        self._dark = self._settings.get("theme", "dark") != "light"
        self.palette = theme_palette(self._dark)
        self._last_verdict = "SAFE"

        self.apk_path_var = tk.StringVar()
        self.recent_var = tk.StringVar()
        self.category_var = tk.StringVar(value="(Auto-Detect)")
        self.status_var = tk.StringVar(value=STATUS_READY)
        self.file_info_var = tk.StringVar(value="No file selected")
        self.elapsed_var = tk.StringVar(value="")

        # Thread-safe UI messaging: worker threads never touch Tk widgets
        # directly; they post to this queue and the main thread drains it.
        self._ui_queue: queue.Queue = queue.Queue()
        self._analysis_running = False
        self._busy_widgets: List[Any] = []
        self._poller_started = False
        self._cancel_requested = False
        self._busy_started_at: Optional[float] = None
        self._last_result: Optional[Dict[str, Any]] = None

        self._configure_styles()
        self._build_ui()
        self._apply_theme()
        self._start_ui_poller()
        self._enable_drag_drop()

    # ------------------------------------------------------------------
    # Styles & theming
    # ------------------------------------------------------------------

    def _configure_styles(self):
        self._style = ttk.Style(self.root)
        try:
            self._style.theme_use("clam")
        except Exception:
            pass
        self._style.configure("TButton", padding=(12, 6), font=("Segoe UI", 10))
        self._style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        self._style.configure("TCombobox", padding=4)
        self._style.configure("Treeview", rowheight=24, font=("Consolas", 9))
        self._style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        self._style.configure("Horizontal.TProgressbar", thickness=10)

    def _apply_theme(self):
        pal = self.palette
        self.root.configure(bg=pal["bg"])
        self._style.configure("TFrame", background=pal["bg"])
        self._style.configure("Card.TFrame", background=pal["card_bg"])
        self._style.configure("TLabel", background=pal["bg"], foreground=pal["text"])
        self._style.configure("Card.TLabel", background=pal["card_bg"], foreground=pal["text"])
        self._style.configure(
            "Muted.Card.TLabel", background=pal["card_bg"], foreground=pal["muted"]
        )
        self._style.configure(
            "Header.TLabel", background=pal["header_bg"], foreground=pal["header_fg"]
        )
        self._style.configure(
            "Treeview",
            background=pal["tree_bg"],
            fieldbackground=pal["tree_bg"],
            foreground=pal["tree_fg"],
        )
        self._style.configure("TNotebook", background=pal["bg"])
        self._style.configure("TNotebook.Tab", padding=(12, 5))

        for widget, role in getattr(self, "_themed_widgets", []):
            try:
                if role == "header":
                    widget.configure(bg=pal["header_bg"], fg=pal["header_fg"])
                elif role == "surface":
                    widget.configure(bg=pal["card_bg"], fg=pal["text"])
                elif role == "status":
                    widget.configure(bg=pal["status_bg"], fg=pal["muted"])
                elif role == "text":
                    widget.configure(
                        bg=pal["tree_bg"],
                        fg=pal["tree_fg"],
                        insertbackground=pal["text"],
                        selectbackground=pal["accent"],
                    )
            except Exception:
                pass

        # Treeview row tags (color-coded permissions)
        for tree in getattr(self, "_trees", []):
            try:
                tree.tag_configure("ok", foreground=pal["ok"])
                tree.tag_configure("warn", foreground=pal["warn"])
                tree.tag_configure("bad", foreground=pal["bad"])
                tree.tag_configure("info", foreground=pal["info"])
                tree.tag_configure("muted", foreground=pal["muted"])
            except Exception:
                pass

        if getattr(self, "gauge", None):
            score = getattr(self.gauge, "_current_score", 0.0)
            self.gauge.restyle(pal, score=score, verdict=self._last_verdict)

        if getattr(self, "_theme_btn", None):
            self._theme_btn.configure(text="☀ Light Mode" if self._dark else "☾ Dark Mode")

    def _register(self, widget, role: str):
        if not hasattr(self, "_themed_widgets"):
            self._themed_widgets = []
        self._themed_widgets.append((widget, role))
        return widget

    def _mklabel(self, parent, role: str = "surface", **kwargs) -> tk.Label:
        pal = self.palette
        bg = pal["card_bg"] if role == "surface" else pal["bg"]
        fg = pal["text"]
        lbl = tk.Label(parent, bg=bg, fg=fg, **kwargs)
        return self._register(lbl, role)

    def _toggle_theme(self):
        self._dark = not self._dark
        self.palette = theme_palette(self._dark)
        self._settings["theme"] = "dark" if self._dark else "light"
        save_settings(self._settings)
        self._apply_theme()

    # ------------------------------------------------------------------
    # VirusTotal API key (Settings dialog)
    # ------------------------------------------------------------------

    def _apply_vt_key(self, key: str) -> bool:
        """Persist and activate a VirusTotal API key (env var still wins)."""
        key = (key or "").strip()
        if not key:
            self.status_var.set("VirusTotal API key is empty — nothing changed.")
            return False
        self._settings["vt_api_key"] = key
        save_settings(self._settings)
        try:
            from src.config import settings as app_settings

            app_settings.virustotal_api_key = key
            self.pipeline.threat_engine.api_key = key
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("API Key Error", self._format_error(e))
            return False
        self.status_var.set(
            f"VirusTotal API key saved ({mask_api_key(key)}) — live AV reputation enabled."
        )
        return True

    def _clear_vt_key(self):
        self._settings["vt_api_key"] = ""
        save_settings(self._settings)
        try:
            from src.config import settings as app_settings

            app_settings.virustotal_api_key = None
            self.pipeline.threat_engine.api_key = None
        except Exception:  # noqa: BLE001
            pass
        self.status_var.set("VirusTotal API key removed — scans fall back to offline intel.")

    def _open_vt_key_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("VirusTotal API Key")
        win.configure(bg=self.palette["bg"])
        win.geometry("460x250")
        win.resizable(False, False)

        self._mklabel(
            win,
            text="Threat-Intel API Key (VirusTotal v3)",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=14, pady=(14, 2))

        current = str(self._settings.get("vt_api_key") or "")
        source = "GUI settings"
        if not current:
            from src.config import settings as app_settings

            env_key = getattr(app_settings, "virustotal_api_key", None)
            if env_key:
                current = str(env_key)
                source = "environment / .env"
        self._mklabel(
            win,
            text=f"Current key: {mask_api_key(current)}   (source: {current and source or 'none'})",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=14, pady=(0, 8))

        entry_row = tk.Frame(win, bg=self.palette["card_bg"], padx=8, pady=8)
        entry_row.pack(fill="x", padx=14)
        self._register(entry_row, "surface")
        self._mklabel(entry_row, text="Key:", font=("Segoe UI", 9, "bold")).pack(
            side="left", padx=(0, 6)
        )
        key_var = tk.StringVar(value=current)
        key_entry = tk.Entry(
            entry_row, textvariable=key_var, show="•", font=("Consolas", 10), width=36
        )
        key_entry.pack(side="left", fill="x", expand=True)

        self._mklabel(
            win,
            text="Free VirusTotal keys: 4 requests/min, 500/day. CAPRA caches every\n"
            "lookup (data/vt_cache.json), so each APK is queried only once. The\n"
            "VIRUSTOTAL_API_KEY environment variable overrides this setting.",
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=14, pady=(8, 4))

        btns = tk.Frame(win, bg=self.palette["bg"])
        btns.pack(pady=(2, 12))

        def on_save():
            if self._apply_vt_key(key_var.get()):
                win.destroy()

        def on_remove():
            self._clear_vt_key()
            win.destroy()

        ttk.Button(btns, text="💾 Save", command=on_save).pack(side="left", padx=5)
        ttk.Button(btns, text="🗑 Remove", command=on_remove).pack(side="left", padx=5)
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side="left", padx=5)
        key_entry.focus_set()
        win.bind("<Return>", lambda _e: on_save())

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # ---- Header ----
        header = tk.Frame(self.root, bg=self.palette["header_bg"], pady=10, padx=16)
        header.pack(fill="x")
        self._register(header, "header")
        self._mklabel(
            header,
            role="header",
            text="🛡  Context-Aware Mobile App Privacy Risk Analyzer",
            font=("Segoe UI", 15, "bold"),
        ).pack(side="left")
        self._theme_btn = tk.Button(
            header,
            text="☀ Light Mode",
            command=self._toggle_theme,
            bd=0,
            padx=10,
            pady=4,
            font=("Segoe UI", 9),
            cursor="hand2",
        )
        self._theme_btn.pack(side="right", padx=4)
        self._register(self._theme_btn, "header")
        tk.Button(
            header,
            text="⚙ API Key",
            command=self._open_vt_key_dialog,
            bd=0,
            padx=10,
            pady=4,
            font=("Segoe UI", 9),
            cursor="hand2",
        ).pack(side="right", padx=4)
        tk.Button(
            header,
            text="🕘 History",
            command=self._open_history,
            bd=0,
            padx=10,
            pady=4,
            font=("Segoe UI", 9),
            cursor="hand2",
        ).pack(side="right", padx=4)

        # ---- Controls card ----
        controls = tk.Frame(self.root, bg=self.palette["card_bg"], padx=12, pady=10)
        controls.pack(fill="x", padx=12, pady=(10, 6))
        self._register(controls, "surface")

        self._mklabel(controls, text="APK File:", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky="w", pady=4
        )
        self.apk_entry = tk.Entry(controls, textvariable=self.apk_path_var, font=("Consolas", 10))
        self.apk_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=4)
        self._register(self.apk_entry, "text")

        self.browse_btn = ttk.Button(controls, text="📂 Browse APK…", command=self._browse_apk)
        self.browse_btn.grid(row=0, column=2, padx=4, pady=4)

        self._mklabel(controls, text="Recent:", font=("Segoe UI", 10, "bold")).grid(
            row=1, column=0, sticky="w", pady=4
        )
        self.recent_combo = ttk.Combobox(
            controls,
            textvariable=self.recent_var,
            values=self._settings.get("recent_files", []),
            state="readonly",
            width=48,
        )
        self.recent_combo.grid(row=1, column=1, sticky="ew", padx=8, pady=4)
        self.recent_combo.bind("<<ComboboxSelected>>", self._on_recent_selected)

        self._mklabel(controls, text="Category:", font=("Segoe UI", 10, "bold")).grid(
            row=1, column=2, sticky="w", padx=4
        )
        self.cat_combo = ttk.Combobox(
            controls,
            textvariable=self.category_var,
            values=CATEGORY_CHOICES,
            state="readonly",
            width=18,
        )
        self.cat_combo.grid(row=1, column=3, sticky="e", padx=4)

        controls.columnconfigure(1, weight=1)

        # Selected-file info line
        self._mklabel(
            controls,
            role="surface",
            textvariable=self.file_info_var,
            font=("Segoe UI", 9),
            anchor="w",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(2, 4))

        # Action buttons row
        actions = tk.Frame(controls, bg=self.palette["card_bg"])
        actions.grid(row=3, column=0, columnspan=4, sticky="w", pady=(6, 2))
        self._register(actions, "surface")
        self.analyze_btn = ttk.Button(
            actions,
            text="▶  Run Privacy Analysis",
            style="Accent.TButton",
            command=self._start_analysis_thread,
        )
        self.analyze_btn.pack(side="left", padx=(0, 6))
        self.demo_btn = ttk.Button(actions, text="🎬 Load Demo…", command=self._show_demo_menu)
        self.demo_btn.pack(side="left", padx=6)
        self.cancel_btn = ttk.Button(actions, text="✖ Cancel", command=self._request_cancel)
        self.cancel_btn.pack(side="left", padx=6)
        ttk.Button(actions, text="⬇ Export Markdown", command=self._export_markdown).pack(
            side="left", padx=6
        )
        ttk.Button(actions, text="⬇ Export JSON", command=self._export_json).pack(
            side="left", padx=6
        )
        ttk.Button(actions, text="📁 Reports Folder", command=self._open_reports_folder).pack(
            side="left", padx=6
        )

        # Progress row
        self.progress = ttk.Progressbar(controls, mode="indeterminate")
        self.progress.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 2))
        self._mklabel(
            controls,
            role="surface",
            textvariable=self.elapsed_var,
            font=("Consolas", 9),
        ).grid(row=4, column=3, sticky="e", pady=(8, 2))

        # ---- Body: gauge card + notebook card ----
        body = tk.Frame(self.root, bg=self.palette["bg"])
        body.pack(fill="both", expand=True, padx=12, pady=6)

        left_panel = tk.Frame(body, bg=self.palette["card_bg"], padx=12, pady=12)
        left_panel.pack(side="left", fill="y", padx=(0, 8))
        self._register(left_panel, "surface")

        self._mklabel(
            left_panel,
            text="COMPOSITE PRIVACY RISK",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="center", pady=(0, 6))

        self.gauge = RiskGaugeCanvas(
            left_panel, size=250, bg_color=self.palette["gauge_bg"], palette=self.palette
        )
        self.gauge.pack(anchor="center", pady=4)

        # Band legend
        legend = tk.Frame(left_panel, bg=self.palette["card_bg"])
        legend.pack(fill="x", pady=(2, 8))
        self._register(legend, "surface")
        for band in RISK_BANDS:
            sw = tk.Canvas(
                legend, width=12, height=12, bg=self.palette["card_bg"], highlightthickness=0
            )
            sw.create_rectangle(0, 0, 12, 12, fill=band["color"], outline="")
            sw.pack(side="left", padx=(2, 0))
            self._mklabel(legend, text=band["name"], font=("Segoe UI", 7)).pack(
                side="left", padx=(2, 6)
            )

        # Metric chips
        self.metric_threat = self._mklabel(
            left_panel, text="Threat Intel: Idle", font=("Segoe UI", 9, "bold")
        )
        self.metric_threat.pack(fill="x", pady=2)
        self.metric_ml = self._mklabel(
            left_panel, text="ML Risk Prob: Idle", font=("Segoe UI", 9, "bold")
        )
        self.metric_ml.pack(fill="x", pady=2)
        self.metric_perms = self._mklabel(
            left_panel, text="Total Permissions: 0", font=("Segoe UI", 9)
        )
        self.metric_perms.pack(fill="x", pady=2)

        self.plot_btn = ttk.Button(
            left_panel, text="📊 View ML Feature Plot", command=self._open_feature_plot
        )
        self.plot_btn.pack(fill="x", pady=(10, 4))
        ttk.Button(left_panel, text="🕘 Scan History & Compare", command=self._open_history).pack(
            fill="x", pady=4
        )

        # Right Panel: Tabbed Notebook
        right_panel = tk.Frame(body, bg=self.palette["card_bg"], bd=0)
        right_panel.pack(side="left", fill="both", expand=True)
        self._register(right_panel, "surface")

        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=6)

        # Tab 1: Overview (plain text — pinned by tests)
        self.tab_overview = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_overview, text=" Overview ")
        self.txt_overview = self._create_scrolled_text(self.tab_overview)

        # Tab 2: Permissions Breakdown (color-coded table)
        self.tab_context = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_context, text=" Permissions Breakdown ")
        self.tree_perms = self._create_tree(
            self.tab_context,
            columns=("group", "name", "penalty", "detail"),
            headings=("Group", "Permission / Signal", "Pts", "Detail"),
            widths=(120, 220, 50, 320),
        )

        # Tab 3: Exfiltration Combinations (table)
        self.tab_combos = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_combos, text=" Exfiltration Combinations ")
        self.tree_combos = self._create_tree(
            self.tab_combos,
            columns=("name", "risk", "perms", "penalty", "status"),
            headings=("Combination", "Risk Type", "Co-occurring Permissions", "Pts", "Status"),
            widths=(180, 120, 220, 45, 110),
        )

        # Tab 4: Recommendations (styled text)
        self.tab_recs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_recs, text=" Recommendations ")
        self.txt_recs = self._create_scrolled_text(self.tab_recs)

        # ---- Bottom Status Bar ----
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bd=1,
            relief="sunken",
            anchor="w",
            font=("Segoe UI", 9),
            padx=10,
            pady=3,
        )
        status_bar.pack(side="bottom", fill="x")
        self._register(status_bar, "status")

        # Widgets disabled while an analysis is running (prevents concurrent scans)
        self._busy_widgets = [
            self.apk_entry,
            self.browse_btn,
            self.cat_combo,
            self.demo_btn,
            self.analyze_btn,
            self.recent_combo,
        ]

    def _create_scrolled_text(self, parent) -> tk.Text:
        """Create a styled text widget with scrollbar."""
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side="right", fill="y")

        txt = tk.Text(
            frame,
            wrap="word",
            font=("Consolas", 9),
            yscrollcommand=scrollbar.set,
            padx=10,
            pady=10,
            bd=0,
        )
        txt.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=txt.yview)
        self._register(txt, "text")
        return txt

    def _create_tree(self, parent, columns, headings, widths):
        """Create a color-tagged Treeview table with scrollbars."""
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for col, head, width in zip(columns, headings, widths):
            tree.heading(col, text=head)
            tree.column(col, width=width, anchor="w")
        ysb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ysb.set)
        tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        if not hasattr(self, "_trees"):
            self._trees = []
        self._trees.append(tree)
        return tree

    # ------------------------------------------------------------------
    # Optional drag & drop (tkinterdnd2 when available; graceful otherwise)
    # ------------------------------------------------------------------

    def _enable_drag_drop(self):
        try:
            from tkinterdnd2 import DND_FILES

            def on_drop(event):
                raw = event.data.strip()
                if raw.startswith("{") and raw.endswith("}"):
                    raw = raw[1:-1]
                path = raw.split("} {")[0]
                if path.lower().endswith(".apk") and os.path.isfile(path):
                    self._set_apk_path(path)
                else:
                    self.status_var.set("Dropped file is not a readable .apk file.")

            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind("<<Drop>>", on_drop)
        except Exception:
            # tkinterdnd2 not installed or not initialized — Browse still works.
            pass

    # ------------------------------------------------------------------
    # File selection helpers
    # ------------------------------------------------------------------

    def _set_apk_path(self, path: str):
        self.apk_path_var.set(path)
        self.file_info_var.set(f"Selected file: {format_file_label(path)}")
        self.status_var.set(f"Selected: {os.path.basename(path)}")
        add_recent_file(self._settings, path)
        save_settings(self._settings)
        try:
            self.recent_combo.configure(values=self._settings.get("recent_files", []))
        except Exception:
            pass

    def _on_recent_selected(self, _event=None):
        path = self.recent_var.get().strip()
        if path and os.path.isfile(path):
            self._set_apk_path(path)
        elif path:
            self.status_var.set(f"Recent file no longer exists: {path}")

    def _browse_apk(self):
        initial = self._settings.get("last_dir") or os.path.expanduser("~")
        file_path = filedialog.askopenfilename(
            title="Select an Android APK",
            initialdir=initial if os.path.isdir(initial) else None,
            filetypes=[("Android Package", "*.apk"), ("All Files", "*.*")],
        )
        if file_path:
            self._set_apk_path(file_path)

    # ------------------------------------------------------------------
    # Demo scenarios
    # ------------------------------------------------------------------

    def _show_demo_menu(self):
        if self._analysis_running:
            messagebox.showinfo("Analysis Running", "An analysis is already running. Please wait.")
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(
            label="Benign Calculator (Safe)",
            command=lambda: self._run_demo_scenario("benign_calculator", "Calculator"),
        )
        menu.add_command(
            label="Malicious Flashlight (Critical)",
            command=lambda: self._run_demo_scenario("malicious_flashlight", "Flashlight"),
        )
        menu.add_command(
            label="Benign Navigation (Context Exemption)",
            command=lambda: self._run_demo_scenario("benign_navigation", "Navigation"),
        )
        try:
            menu.tk_popup(self.demo_btn.winfo_rootx(), self.demo_btn.winfo_rooty() + 30)
        finally:
            menu.grab_release()

    def _run_demo_scenario(self, scenario: str, category: str):
        if self._analysis_running:
            messagebox.showinfo("Analysis Running", "An analysis is already running. Please wait.")
            return
        self._set_busy(True)
        self.status_var.set(f"Running demo scenario '{scenario}'...")
        thread = threading.Thread(target=self._execute_demo, args=(scenario, category), daemon=True)
        thread.start()

    def _execute_demo(self, scenario: str, category: str):
        try:
            results = run_synthetic_demo(scenario, category=category)
            self._ui_queue.put(("demo", scenario, results))
        except Exception as e:  # noqa: BLE001 - forwarded to the UI thread
            self._ui_queue.put(("error", e))

    # ------------------------------------------------------------------
    # Busy state & cancellation
    # ------------------------------------------------------------------

    def _set_busy(self, busy: bool) -> None:
        self._analysis_running = busy
        self._cancel_requested = False
        for widget in self._busy_widgets:
            try:
                if isinstance(widget, ttk.Combobox):
                    widget.configure(state="disabled" if busy else "readonly")
                else:
                    widget.configure(state="disabled" if busy else "normal")
            except Exception:
                pass
        try:
            if busy:
                self._busy_started_at = time.monotonic()
                self.progress.start(12)
            else:
                self._busy_started_at = None
                self.progress.stop()
                self.elapsed_var.set("")
        except Exception:
            pass

    def _request_cancel(self):
        if not self._analysis_running:
            self.status_var.set("No analysis is running.")
            return
        self._cancel_requested = True
        self.status_var.set("Cancelling… (the current scan will be discarded when it finishes)")

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def _format_error(self, err: Exception) -> str:
        try:
            return friendly_error_message(err)
        except Exception:
            return str(err)

    # ------------------------------------------------------------------
    # Main-thread UI queue poller (the ONLY place widgets are updated)
    # ------------------------------------------------------------------

    def _start_ui_poller(self) -> None:
        """Start the main-thread queue poller (Tk-safe UI updates)."""
        self._poller_started = True
        self._poll_ui_queue()

    def _process_ui_queue(self) -> int:
        """Drain all pending worker messages. Returns the number processed."""
        processed = 0
        while True:
            try:
                message = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            processed += 1
            kind = message[0]
            try:
                if kind == "results" and len(message) >= 2:
                    if self._cancel_requested:
                        self.status_var.set("Analysis cancelled.")
                    else:
                        self._render_results(message[1])
                        self.status_var.set(STATUS_SUCCESS)
                    self._set_busy(False)
                elif kind == "demo" and len(message) >= 3:
                    scenario, results = message[1], message[2]
                    if self._cancel_requested:
                        self.status_var.set("Analysis cancelled.")
                    else:
                        self._render_results(results)
                        self.status_var.set(f"Demo '{scenario}' evaluation complete.")
                    self._set_busy(False)
                elif kind == "error" and len(message) >= 2:
                    err = message[1]
                    messagebox.showerror("Analysis Error", self._format_error(err))
                    self.status_var.set("Analysis aborted due to error.")
                    self._set_busy(False)
                else:
                    self.status_var.set("Results could not be displayed.")
                    self._set_busy(False)
            except Exception as e:  # noqa: BLE001 - keep the poller alive
                self.status_var.set("Results could not be displayed.")
                self._set_busy(False)
                try:
                    messagebox.showerror("Display Error", self._format_error(e))
                except Exception:
                    pass
        return processed

    def _poll_ui_queue(self) -> None:
        """Periodic queue drain (runs on the Tk main thread)."""
        self._process_ui_queue()
        # Elapsed-time ticker while busy
        if self._analysis_running and self._busy_started_at:
            self.elapsed_var.set(f"elapsed {int(time.monotonic() - self._busy_started_at)}s")
        if not self._poller_started:
            return
        try:
            self.root.after(100, self._poll_ui_queue)
        except Exception:
            # Window is being destroyed; stop polling.
            self._poller_started = False

    def _pump_ui_queue(self) -> int:
        """Process pending worker messages immediately (used by tests/self-test)."""
        return self._process_ui_queue()

    # ------------------------------------------------------------------
    # Analysis execution
    # ------------------------------------------------------------------

    def _start_analysis_thread(self):
        """Launch analysis pipeline in a background thread."""
        if self._analysis_running:
            messagebox.showinfo("Analysis Running", "An analysis is already running. Please wait.")
            return

        apk_path = self.apk_path_var.get().strip()
        category = self.category_var.get().strip()

        if not apk_path:
            messagebox.showwarning(
                "Missing APK", "Please select an APK file or choose a Demo scenario."
            )
            return

        if not os.path.isfile(apk_path):
            messagebox.showerror("File Error", f"Target file does not exist:\n{apk_path}")
            return

        self._set_busy(True)
        self.status_var.set("Analyzing APK manifest and calculating risks...")
        thread = threading.Thread(
            target=self._execute_analysis, args=(apk_path, category), daemon=True
        )
        thread.start()

    def _execute_analysis(self, apk_path: str, category: str):
        """Worker thread executing unified analysis pipeline.

        Never touches Tk widgets directly; results/errors are posted to
        self._ui_queue and rendered by the main-thread poller.
        """
        try:
            chosen_cat = None if category in ("(Auto-Detect)", "", None) else category
            results = self.pipeline.analyze(apk_path, category=chosen_cat)
            self._ui_queue.put(("results", results))
        except Exception as e:  # noqa: BLE001 - forwarded to the UI thread
            self._ui_queue.put(("error", e))

    # ------------------------------------------------------------------
    # Result rendering
    # ------------------------------------------------------------------

    def _render_results(self, results: Dict[str, Any]):
        """Update GUI widgets and tabs with analysis findings."""
        manifest = results.get("manifest", {})
        context = results.get("context", {})
        fusion = results.get("fusion", {})
        threat = results.get("threat", {})
        ml = results.get("ml", {})
        static_analysis = results.get("static_analysis", {})
        self._last_result = results

        score = fusion.get("score", 0)
        verdict = fusion.get("verdict", "SAFE")

        # 1. Gauge (animated needle)
        self._last_verdict = verdict
        try:
            self.gauge.animate_to(score, verdict)
        except Exception:
            self.gauge.draw_gauge(score, verdict)

        # 2. Left summary chips
        t_status = display_threat_status(threat.get("status"), score)
        threat_side = bool(threat.get("is_flagged")) or t_status in (
            "MALICIOUS",
            "SUSPICIOUS",
            "SUSPECTED_THREAT",
        )
        self.metric_threat.config(
            text=f"Threat Intel: {t_status}",
            fg=self.palette["bad"] if threat_side else self.palette["ok"],
        )
        self.metric_ml.config(
            text=f"ML Prob: {ml.get('risk_percentage')}% ({ml.get('ml_verdict')})",
            fg=self.palette["bad"] if ml.get("risk_probability", 0) >= 0.5 else self.palette["ok"],
        )
        self.metric_perms.config(
            text=f"Total Permissions: {manifest.get('total_permissions_count', 0)}"
        )

        # 3. Tab: Overview
        self.txt_overview.delete("1.0", tk.END)
        self.txt_overview.insert(
            tk.END,
            build_overview_text(manifest, context, fusion, threat, ml, static_analysis),
        )

        # 4. Tab: Permissions Breakdown (color-coded)
        self.tree_perms.delete(*self.tree_perms.get_children())
        for row in permission_rows(context):
            self.tree_perms.insert(
                "",
                "end",
                values=(
                    row["group_label"],
                    row["name"],
                    f"+{row['penalty']}" if row["penalty"] else "—",
                    row["detail"][:160],
                ),
                tags=(row["tag"],),
            )

        # 5. Tab: Exfiltration Combinations
        self.tree_combos.delete(*self.tree_combos.get_children())
        for row in combination_rows(context):
            self.tree_combos.insert(
                "",
                "end",
                values=(
                    row["name"],
                    row["risk_type"],
                    row["permissions"],
                    f"+{row['penalty']}" if row["penalty"] else "—",
                    "Exempt (expected)" if row["exempt"] else "TRIGGERED",
                ),
                tags=(row["tag"],),
            )

        # 6. Tab: Recommendations
        self.txt_recs.delete("1.0", tk.END)
        self.txt_recs.insert(tk.END, build_recommendations_text(fusion))

    # ------------------------------------------------------------------
    # Export & external tools
    # ------------------------------------------------------------------

    def _export_markdown(self):
        if not self._last_result:
            messagebox.showinfo("No Results", "Run an analysis first.")
            return
        try:
            from src.report_generator import generate_markdown_report

            pkg = self._last_result.get("manifest", {}).get("package_name", "report")
            path = filedialog.asksaveasfilename(
                title="Export Markdown Report",
                defaultextension=".md",
                initialfile=f"privacy_audit_{pkg}.md",
                filetypes=[("Markdown", "*.md"), ("All Files", "*.*")],
            )
            if not path:
                return
            out = generate_markdown_report(self._last_result, output_path=path)
            self.status_var.set(f"Markdown report saved: {out}")
            messagebox.showinfo("Export Complete", f"Report saved to:\n{out}")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Export Error", self._format_error(e))

    def _export_json(self):
        if not self._last_result:
            messagebox.showinfo("No Results", "Run an analysis first.")
            return
        try:
            import json

            pkg = self._last_result.get("manifest", {}).get("package_name", "report")
            path = filedialog.asksaveasfilename(
                title="Export JSON Report",
                defaultextension=".json",
                initialfile=f"privacy_audit_{pkg}.json",
                filetypes=[("JSON", "*.json"), ("All Files", "*.*")],
            )
            if not path:
                return

            def _default(obj):
                try:
                    return str(obj)
                except Exception:
                    return "<unserializable>"

            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._last_result, f, indent=2, default=_default)
            self.status_var.set(f"JSON report saved: {path}")
            messagebox.showinfo("Export Complete", f"JSON saved to:\n{path}")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Export Error", self._format_error(e))

    def _open_reports_folder(self):
        try:
            from src.config import settings as app_settings

            reports_dir = str(app_settings.reports_dir)
            os.makedirs(reports_dir, exist_ok=True)
            if sys.platform.startswith("win"):
                os.startfile(reports_dir)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", reports_dir])
            else:
                subprocess.Popen(["xdg-open", reports_dir])
            self.status_var.set(f"Opened reports folder: {reports_dir}")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Folder Error", self._format_error(e))

    def _open_feature_plot(self):
        try:
            out = self.ml_pipeline.export_feature_importance_plot()
            self.status_var.set(f"ML feature importance plot: {out}")
            if sys.platform.startswith("win"):
                os.startfile(out)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", out])
            else:
                subprocess.Popen(["xdg-open", out])
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Plot Error", self._format_error(e))

    # ------------------------------------------------------------------
    # History & comparison window
    # ------------------------------------------------------------------

    def _open_history(self):
        try:
            from src.history_manager import HistoryManager
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("History Error", self._format_error(e))
            return

        win = tk.Toplevel(self.root)
        win.title("Scan History & Comparison")
        win.geometry("860x420")
        win.configure(bg=self.palette["bg"])

        info = tk.Label(
            win,
            text="Select one row to inspect · select exactly two rows to compare scans",
            bg=self.palette["bg"],
            fg=self.palette["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        )
        info.pack(fill="x", padx=10, pady=(10, 4))

        tree = ttk.Treeview(
            win,
            columns=("id", "time", "package", "category", "score", "verdict", "threat"),
            show="headings",
            selectmode="extended",
        )
        for col, head, width in zip(
            ("id", "time", "package", "category", "score", "verdict", "threat"),
            ("ID", "Timestamp (UTC)", "Package", "Category", "Score", "Verdict", "Threat"),
            (40, 150, 220, 110, 55, 90, 130),
        ):
            tree.heading(col, text=head)
            tree.column(col, width=width, anchor="w")
        tree.tag_configure("ok", foreground=self.palette["ok"])
        tree.tag_configure("bad", foreground=self.palette["bad"])
        tree.tag_configure("muted", foreground=self.palette["muted"])
        tree.pack(fill="both", expand=True, padx=10, pady=4)

        def refresh():
            tree.delete(*tree.get_children())
            try:
                hm = HistoryManager()
                for rec in hm.get_history(limit=200):
                    t_status = display_threat_status(rec.get("threat_status"), rec.get("score"))
                    if t_status in ("MALICIOUS", "SUSPICIOUS", "SUSPECTED_THREAT"):
                        t_tag = "bad"
                    elif t_status in ("VERIFIED_BENIGN", "NO_THREAT_DETECTED"):
                        t_tag = "ok"
                    else:
                        t_tag = "muted"
                    tree.insert(
                        "",
                        "end",
                        values=(
                            rec.get("id"),
                            rec.get("timestamp"),
                            rec.get("package_name"),
                            rec.get("category"),
                            rec.get("score"),
                            rec.get("verdict"),
                            t_status,
                        ),
                        tags=(t_tag,),
                    )
            except Exception as e:  # noqa: BLE001
                messagebox.showerror("History Error", self._format_error(e))

        def compare():
            selected = tree.selection()
            if len(selected) != 2:
                messagebox.showinfo(
                    "Compare Scans", "Select exactly two scans (Ctrl+Click) to compare."
                )
                return
            id1 = int(tree.item(selected[0])["values"][0])
            id2 = int(tree.item(selected[1])["values"][0])
            try:
                hm = HistoryManager()
                diff = hm.compare_analyses(id1, id2)
                top = tk.Toplevel(win)
                top.title(f"Comparison #{id1} vs #{id2}")
                top.geometry("720x420")
                txt = self._create_scrolled_text(top)
                txt.insert(tk.END, build_comparison_text(diff))
            except Exception as e:  # noqa: BLE001
                messagebox.showerror("Compare Error", self._format_error(e))

        def delete_selected():
            selected = tree.selection()
            if not selected:
                return
            if not messagebox.askyesno("Delete Scans", f"Delete {len(selected)} scan record(s)?"):
                return
            try:
                hm = HistoryManager()
                for item in selected:
                    hm.delete_analysis(int(tree.item(item)["values"][0]))
                refresh()
            except Exception as e:  # noqa: BLE001
                messagebox.showerror("History Error", self._format_error(e))

        btns = tk.Frame(win, bg=self.palette["bg"])
        btns.pack(fill="x", padx=10, pady=(4, 10))
        ttk.Button(btns, text="🔄 Refresh", command=refresh).pack(side="left", padx=4)
        ttk.Button(btns, text="⚖ Compare Selected", command=compare).pack(side="left", padx=4)
        ttk.Button(btns, text="🗑 Delete Selected", command=delete_selected).pack(
            side="left", padx=4
        )

        refresh()


def launch_gui():
    """Create the Tk root (with optional drag & drop) and run the main loop."""
    try:
        from tkinterdnd2 import TkinterDnD

        root = TkinterDnD.Tk()
    except Exception:
        root = tk.Tk()
    PrivacyAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
