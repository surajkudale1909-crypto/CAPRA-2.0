"""Desktop Graphical User Interface (GUI) Module.

Samriddhi's Module (EDAI Group 8).
Built using Python Tkinter and TTK. Provides an interactive desktop workbench
with an APK file chooser, category dropdown, visual risk score arc gauge,
multi-tab privacy analysis dashboard, and ML feature importance inspection.
"""

from __future__ import annotations

import os
import queue
import sys
import threading

# Ensure repository root is on sys.path for direct execution (e.g. python src/gui.py)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict

from src.extractor import friendly_error_message
from src.pipeline import get_default_pipeline, run_synthetic_demo


class RiskGaugeCanvas(tk.Canvas):
    """Custom Tkinter Canvas rendering a modern circular arc risk meter."""

    def __init__(self, parent, size: int = 240, bg_color: str = "#ffffff", **kwargs):
        super().__init__(
            parent, width=size, height=size // 2 + 50, bg=bg_color, highlightthickness=0, **kwargs
        )
        self.size = size
        self.cx = size // 2
        self.cy = size // 2 + 10
        self.radius = (size // 2) - 25
        self.draw_gauge(score=0, verdict="SAFE")

    def _get_score_color(self, score: int) -> str:
        """Interpolate color based on risk score."""
        if score <= 20:
            return "#28a745"  # Green
        elif score <= 45:
            return "#17a2b8"  # Cyan
        elif score <= 70:
            return "#ffc107"  # Yellow / Amber
        elif score <= 89:
            return "#fd7e14"  # Orange
        else:
            return "#dc3545"  # Red

    def draw_gauge(self, score: int, verdict: str):
        """Draw semi-circular gauge with dynamic fill and score text."""
        self.delete("all")
        score = max(0, min(100, score))

        x0 = self.cx - self.radius
        y0 = self.cy - self.radius
        x1 = self.cx + self.radius
        y1 = self.cy + self.radius

        # 1. Background Arc (Grey track from 180° to 0°)
        self.create_arc(
            x0, y0, x1, y1, start=0, extent=180, outline="#e9ecef", width=18, style="arc"
        )

        # 2. Dynamic Filled Arc
        extent_angle = int((score / 100.0) * 180)
        color = self._get_score_color(score)

        if extent_angle > 0:
            self.create_arc(
                x0,
                y0,
                x1,
                y1,
                start=180,
                extent=-extent_angle,
                outline=color,
                width=18,
                style="arc",
            )

        # 3. Center Text: Numerical Score
        self.create_text(
            self.cx,
            self.cy - 18,
            text=f"{score}",
            font=("Segoe UI", 32, "bold"),
            fill=color,
        )
        self.create_text(
            self.cx,
            self.cy + 16,
            text="/ 100",
            font=("Segoe UI", 10, "bold"),
            fill="#6c757d",
        )

        # 4. Verdict Badge Banner below meter
        self.create_text(
            self.cx,
            self.cy + 36,
            text=f"★ {verdict.upper()} RISK ★",
            font=("Segoe UI", 11, "bold"),
            fill=color,
        )


class PrivacyAnalyzerGUI:
    """Main Desktop Application Window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CAPRA 2.0 - Context-Aware Mobile App Privacy Risk Analyzer")
        self.root.geometry("980x720")
        self.root.minsize(860, 620)

        # Initialize pipeline and engine instances
        self.pipeline = get_default_pipeline()
        self.context_engine = self.pipeline.context_engine
        self.fusion_engine = self.pipeline.fusion_engine
        self.threat_engine = self.pipeline.threat_engine
        self.ml_pipeline = self.pipeline.ml_pipeline

        self.apk_path_var = tk.StringVar()
        self.category_var = tk.StringVar(value="Calculator")
        self.status_var = tk.StringVar(value="Ready to analyze APK.")

        # Thread-safe UI messaging: worker threads never touch Tk widgets
        # directly; they post to this queue and the main thread drains it.
        self._ui_queue: queue.Queue = queue.Queue()
        self._analysis_running = False
        self._busy_widgets = []
        self._poller_started = False

        self._configure_styles()
        self._build_ui()
        self._start_ui_poller()

    def _configure_styles(self):
        """Set up TTK widget styling."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#1a365d")
        style.configure("SubHeader.TLabel", font=("Segoe UI", 9), foreground="#4a5568")
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.configure(
            "Action.TButton",
            font=("Segoe UI", 10, "bold"),
            background="#0066cc",
            foreground="#ffffff",
            padding=8,
        )

    def _build_ui(self):
        """Construct application layout."""
        # Top Header Banner
        header_frame = tk.Frame(self.root, bg="#1a365d", height=70)
        header_frame.pack(fill="x", side="top")
        header_frame.pack_propagate(False)

        title_lbl = tk.Label(
            header_frame,
            text="Context-Aware Mobile App Privacy Risk Analyzer",
            font=("Segoe UI", 15, "bold"),
            fg="#ffffff",
            bg="#1a365d",
        )
        title_lbl.pack(anchor="w", padx=20, pady=(10, 2))

        # sub_lbl = tk.Label(
        #     header_frame,
        #     text="EDAI Group 8 | CS-AI Dept, VIT Pune | Static Manifest & Multi-Engine Risk Fusion",
        #     font=("Segoe UI", 9),
        #     fg="#cbd5e0",
        #     bg="#1a365d",
        # )
        # sub_lbl.pack(anchor="w", padx=20)

        # Main Content Container
        main_container = tk.Frame(self.root, bg="#f8f9fa")
        main_container.pack(fill="both", expand=True, padx=15, pady=10)

        # Control & Selection Frame
        controls_frame = tk.LabelFrame(
            main_container,
            text=" Analysis Controls ",
            font=("Segoe UI", 10, "bold"),
            bg="#ffffff",
            padx=15,
            pady=12,
        )
        controls_frame.pack(fill="x", pady=(0, 10))

        # Row 1: APK File Chooser
        tk.Label(controls_frame, text="APK File:", font=("Segoe UI", 9, "bold"), bg="#ffffff").grid(
            row=0, column=0, sticky="w", pady=4
        )
        self.apk_entry = ttk.Entry(controls_frame, textvariable=self.apk_path_var, width=58)
        self.apk_entry.grid(row=0, column=1, padx=8, pady=4, sticky="ew")

        self.browse_btn = ttk.Button(controls_frame, text="Browse APK...", command=self._browse_apk)
        self.browse_btn.grid(row=0, column=2, padx=4, pady=4)

        # Row 2: Category Selector & Run Button
        tk.Label(controls_frame, text="Category:", font=("Segoe UI", 9, "bold"), bg="#ffffff").grid(
            row=1, column=0, sticky="w", pady=6
        )
        self.cat_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.category_var,
            values=["(Auto-Detect)"] + self.context_engine.get_supported_categories(),
            state="readonly",
            width=20,
        )
        self.cat_combo.grid(row=1, column=1, sticky="w", padx=8, pady=6)

        btn_box = tk.Frame(controls_frame, bg="#ffffff")
        btn_box.grid(row=1, column=2, sticky="e")

        self.demo_btn = ttk.Button(btn_box, text="Load Demo...", command=self._show_demo_menu)
        self.demo_btn.pack(side="left", padx=4)

        self.analyze_btn = tk.Button(
            btn_box,
            text="⚡ Run Privacy Analysis",
            command=self._start_analysis_thread,
            bg="#0066cc",
            fg="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
        )
        self.analyze_btn.pack(side="left", padx=4)

        controls_frame.columnconfigure(1, weight=1)

        # Horizontal Split: Left (Risk Gauge) | Right (Tabbed Detailed Report)
        body_paned = tk.PanedWindow(main_container, orient="horizontal", bg="#f8f9fa", sashwidth=4)
        body_paned.pack(fill="both", expand=True)

        # Left Panel: Visual Gauge & Summary Cards
        left_panel = tk.Frame(body_paned, bg="#ffffff", bd=1, relief="solid", padx=12, pady=12)
        body_paned.add(left_panel, width=280)

        gauge_lbl = tk.Label(
            left_panel,
            text="COMPOSITE PRIVACY RISK",
            font=("Segoe UI", 10, "bold"),
            bg="#ffffff",
            fg="#4a5568",
        )
        gauge_lbl.pack(anchor="center", pady=(0, 4))

        self.gauge = RiskGaugeCanvas(left_panel, size=240, bg_color="#ffffff")
        self.gauge.pack(anchor="center", pady=4)

        # Mini Metrics Box
        self.metrics_frame = tk.Frame(
            left_panel, bg="#f8f9fa", bd=1, relief="groove", padx=8, pady=8
        )
        self.metrics_frame.pack(fill="x", pady=10)

        self.metric_threat = tk.Label(
            self.metrics_frame,
            text="Threat Intel: Idle",
            font=("Segoe UI", 8),
            bg="#f8f9fa",
            anchor="w",
        )
        self.metric_threat.pack(fill="x", pady=1)

        self.metric_ml = tk.Label(
            self.metrics_frame,
            text="ML Risk Prob: Idle",
            font=("Segoe UI", 8),
            bg="#f8f9fa",
            anchor="w",
        )
        self.metric_ml.pack(fill="x", pady=1)

        self.metric_perms = tk.Label(
            self.metrics_frame,
            text="Total Permissions: 0",
            font=("Segoe UI", 8),
            bg="#f8f9fa",
            anchor="w",
        )
        self.metric_perms.pack(fill="x", pady=1)

        # Button to View ML Feature Importance Plot
        self.plot_btn = ttk.Button(
            left_panel, text="📊 View ML Feature Plot", command=self._open_feature_plot
        )
        self.plot_btn.pack(fill="x", pady=6)

        # Right Panel: Tabbed Notebook
        right_panel = tk.Frame(body_paned, bg="#ffffff", bd=1, relief="solid")
        body_paned.add(right_panel, width=640)

        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 1: Overview
        self.tab_overview = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_overview, text=" Overview ")
        self.txt_overview = self._create_scrolled_text(self.tab_overview)

        # Tab 2: Context Evaluation
        self.tab_context = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_context, text=" Permissions Breakdown ")
        self.txt_context = self._create_scrolled_text(self.tab_context)

        # Tab 3: Dangerous Combinations
        self.tab_combos = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_combos, text=" Exfiltration Combinations ")
        self.txt_combos = self._create_scrolled_text(self.tab_combos)

        # Tab 4: Recommendations
        self.tab_recs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_recs, text=" Recommendations ")
        self.txt_recs = self._create_scrolled_text(self.tab_recs)

        # Bottom Status Bar
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bd=1,
            relief="sunken",
            anchor="w",
            font=("Segoe UI", 9),
            bg="#edf2f7",
            padx=10,
            pady=3,
        )
        status_bar.pack(side="bottom", fill="x")

        # Widgets disabled while an analysis is running (prevents concurrent scans)
        self._busy_widgets = [
            self.apk_entry,
            self.browse_btn,
            self.cat_combo,
            self.demo_btn,
            self.analyze_btn,
        ]

    def _create_scrolled_text(self, parent) -> tk.Text:
        """Create a styled text widget with scrollbar."""
        frame = tk.Frame(parent)
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
            bg="#ffffff",
            fg="#212529",
            bd=0,
        )
        txt.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=txt.yview)
        return txt

    def _browse_apk(self):
        """Open file dialog to pick an APK file."""
        initial_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "apks"))
        file_path = filedialog.askopenfilename(
            title="Select Target Android APK",
            initialdir=initial_dir if os.path.exists(initial_dir) else os.getcwd(),
            filetypes=[("Android APK Files", "*.apk"), ("All Files", "*.*")],
        )
        if file_path:
            self.apk_path_var.set(file_path)
            self.status_var.set(f"Selected: {os.path.basename(file_path)}")

    def _show_demo_menu(self):
        """Display quick selection dialog for demo scenarios."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Load Presentation Demo Scenario")
        dialog.geometry("420x220")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog, text="Select Evaluation Demo Scenario:", font=("Segoe UI", 10, "bold")
        ).pack(pady=10)

        def pick(scenario: str, cat: str):
            self.category_var.set(cat)
            dialog.destroy()
            self._run_demo_scenario(scenario, cat)

        ttk.Button(
            dialog,
            text="🟢 Benign Calculator (Safe Profile)",
            command=lambda: pick("benign_calculator", "Calculator"),
        ).pack(fill="x", padx=30, pady=4)

        ttk.Button(
            dialog,
            text="🔴 Spyware Flashlight (Exfiltration Combinations)",
            command=lambda: pick("malicious_flashlight", "Flashlight"),
        ).pack(fill="x", padx=30, pady=4)

        ttk.Button(
            dialog,
            text="🔵 OpenStreetMap Navigation (Contextual Exemption)",
            command=lambda: pick("benign_navigation", "Navigation"),
        ).pack(fill="x", padx=30, pady=4)

    def _run_demo_scenario(self, scenario: str, category: str):
        """Run simulated demonstration analysis using unified demo pipeline (async)."""
        if self._analysis_running:
            messagebox.showinfo("Analysis Running", "An analysis is already running. Please wait.")
            return
        self._set_busy(True)
        self.status_var.set(f"Running demo scenario '{scenario}'...")
        threading.Thread(
            target=self._execute_demo,
            args=(scenario, category),
            daemon=True,
        ).start()

    def _execute_demo(self, scenario: str, category: str):
        """Worker thread: run a synthetic demo scenario and post results."""
        try:
            results = run_synthetic_demo(scenario, category=category)
            self._ui_queue.put(("demo", scenario, results))
        except Exception as e:  # noqa: BLE001 - forwarded to the UI thread
            self._ui_queue.put(("error", e))

    def _set_busy(self, busy: bool) -> None:
        """Toggle interactive widgets while an analysis is running (main thread only)."""
        self._analysis_running = busy
        state = tk.DISABLED if busy else tk.NORMAL
        for widget in self._busy_widgets:
            try:
                widget.configure(state=state)
            except Exception:
                pass
        try:
            self.analyze_btn.configure(
                text="⏳ Analyzing..." if busy else "⚡ Run Privacy Analysis",
                bg="#6c757d" if busy else "#0066cc",
            )
        except Exception:
            pass

    def _format_error(self, err: Exception) -> str:
        """Map pipeline exceptions to friendly, actionable dialog messages."""
        return friendly_error_message(err)

    def _start_ui_poller(self) -> None:
        """Start the main-thread queue poller (Tk-safe UI updates)."""
        if not self._poller_started:
            self._poller_started = True
            self.root.after(100, self._poll_ui_queue)

    def _process_ui_queue(self) -> int:
        """Drain all pending worker messages on the main thread. Returns count."""
        processed = 0
        while True:
            try:
                message = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            processed += 1
            kind = message[0]
            try:
                if kind == "results":
                    results = message[1]
                    self._render_results(
                        results["manifest"],
                        results["context"],
                        results["fusion"],
                        results.get("threat", {}),
                        results.get("ml", {}),
                    )
                    self.status_var.set("Analysis completed successfully.")
                elif kind == "demo":
                    scenario, results = message[1], message[2]
                    self._render_results(
                        results["manifest"],
                        results["context"],
                        results["fusion"],
                        results.get("threat", {}),
                        results.get("ml", {}),
                    )
                    self.status_var.set(f"Demo '{scenario}' evaluation complete.")
                elif kind == "error":
                    err = message[1]
                    messagebox.showerror("Analysis Error", self._format_error(err))
                    self.status_var.set("Analysis aborted due to error.")
            except Exception as render_err:  # never let UI errors kill the poller
                messagebox.showerror("UI Error", f"Failed to display results: {render_err}")
                self.status_var.set("Results could not be displayed.")
            finally:
                self._set_busy(False)
        return processed

    def _poll_ui_queue(self) -> None:
        """Periodic main-thread poller for worker results."""
        self._process_ui_queue()
        try:
            self.root.after(100, self._poll_ui_queue)
        except Exception:
            # Window is being destroyed; stop polling.
            self._poller_started = False

    def _pump_ui_queue(self) -> int:
        """Process pending worker messages immediately (used by tests/self-test)."""
        return self._process_ui_queue()

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

    def _render_results(
        self,
        manifest: Dict[str, Any],
        context: Dict[str, Any],
        fusion: Dict[str, Any],
        threat: Dict[str, Any],
        ml: Dict[str, Any],
    ):
        """Update GUI widgets and tabs with analysis findings."""
        score = fusion["score"]
        verdict = fusion["verdict"]

        # 1. Update Gauge
        self.gauge.draw_gauge(score, verdict)

        # 2. Update Left Summary Box
        t_status = threat.get("status", "UNKNOWN")
        self.metric_threat.config(
            text=f"Threat Intel: {t_status}",
            fg="#dc3545"
            if threat.get("is_flagged")
            else ("#28a745" if threat.get("is_verified_benign") else "#495057"),
        )
        self.metric_ml.config(
            text=f"ML Prob: {ml['risk_percentage']}% ({ml['ml_verdict']})",
            fg="#dc3545" if ml["risk_probability"] >= 0.5 else "#28a745",
        )
        self.metric_perms.config(
            text=f"Total Permissions: {manifest.get('total_permissions_count', 0)}"
        )

        # 3. Tab: Overview
        self.txt_overview.delete("1.0", tk.END)
        self.txt_overview.insert(
            tk.END, "===================================================================\n"
        )
        self.txt_overview.insert(
            tk.END, "               APPLICATION OVERVIEW & INTEGRATED AUDIT             \n"
        )
        self.txt_overview.insert(
            tk.END, "===================================================================\n\n"
        )
        self.txt_overview.insert(
            tk.END, f"App Name:           {manifest.get('app_name') or 'N/A'}\n"
        )
        self.txt_overview.insert(tk.END, f"Package Name:       {manifest.get('package_name')}\n")
        self.txt_overview.insert(
            tk.END,
            f"Target SDK:         {manifest.get('target_sdk_version')} (Min SDK: {manifest.get('min_sdk_version')})\n",
        )
        self.txt_overview.insert(
            tk.END,
            f"Version:            {manifest.get('version_name')} (Code: {manifest.get('version_code')})\n",
        )
        self.txt_overview.insert(
            tk.END,
            f"Analyzed Category:  {context.get('category')} - {context.get('category_description')}\n",
        )
        self.txt_overview.insert(
            tk.END, f"Total Permissions:  {manifest.get('total_permissions_count')}\n\n"
        )

        comps = manifest.get("components", {})
        exp = comps.get("exported", {})
        self.txt_overview.insert(
            tk.END,
            f"Exported Surface:   {exp.get('total_exported', 0)} Total | {exp.get('unprotected_exported', 0)} Unprotected\n\n",
        )

        self.txt_overview.insert(
            tk.END, f"Threat Intel Hash:  {threat.get('hashes', {}).get('sha256', 'N/A')}\n"
        )
        self.txt_overview.insert(tk.END, f"Reputation Status:  {threat.get('reputation')}\n")
        if threat.get("threat_details"):
            td = threat["threat_details"]
            self.txt_overview.insert(
                tk.END, f"Matched Threat:     {td.get('family')} [{td.get('threat_type')}]\n"
            )

        self.txt_overview.insert(
            tk.END, f"\nML Risk Estimation: {ml.get('risk_percentage')}% [{ml.get('ml_verdict')}]\n"
        )
        self.txt_overview.insert(tk.END, "\nKey Privacy Findings:\n")
        for f in fusion.get("findings", []):
            self.txt_overview.insert(tk.END, f"  • {f}\n")

        # 4. Tab: Context Permissions Breakdown
        self.txt_context.delete("1.0", tk.END)
        self.txt_context.insert(
            tk.END, "===================================================================\n"
        )
        self.txt_context.insert(
            tk.END, "                 CONTEXTUAL PERMISSION EVALUATION                  \n"
        )
        self.txt_context.insert(
            tk.END, "===================================================================\n\n"
        )

        acceptable = context.get("acceptable_permissions", [])
        self.txt_context.insert(
            tk.END, f"[+] Baseline Acceptable Permissions ({len(acceptable)}):\n"
        )
        for p in acceptable:
            self.txt_context.insert(tk.END, f"    ✓ {p['permission']}\n")

        suspicious = context.get("suspicious_permissions", [])
        self.txt_context.insert(
            tk.END, f"\n[-] Category Mismatches / Suspicious Permissions ({len(suspicious)}):\n"
        )
        for s in suspicious:
            self.txt_context.insert(
                tk.END, f"    ✗ {s['permission']} (+{s['penalty']} penalty pts)\n"
            )
            self.txt_context.insert(tk.END, f"      Reason: {s['reason']}\n")

        unexpected = context.get("unexpected_dangerous_permissions", [])
        if unexpected:
            self.txt_context.insert(
                tk.END, f"\n[!] Unlisted Dangerous AOSP Permissions ({len(unexpected)}):\n"
            )
            for u in unexpected:
                self.txt_context.insert(tk.END, f"    ⚠ {u['permission']} (+{u['penalty']} pts)\n")

        # 5. Tab: Dangerous Combinations
        self.txt_combos.delete("1.0", tk.END)
        self.txt_combos.insert(
            tk.END, "===================================================================\n"
        )
        self.txt_combos.insert(
            tk.END, "          DANGEROUS COMBINATIONS (COLLUSION / EXFILTRATION)         \n"
        )
        self.txt_combos.insert(
            tk.END, "===================================================================\n\n"
        )

        combos = context.get("triggered_combinations", [])
        if combos:
            for c in combos:
                self.txt_combos.insert(
                    tk.END, f"🚨 {c['name']} [{c['risk_type']}] (+{c['penalty']} pts)\n"
                )
                self.txt_combos.insert(
                    tk.END, f"   Matched: {' + '.join(c['matched_permissions'])}\n"
                )
                self.txt_combos.insert(tk.END, f"   Details: {c['description']}\n\n")
        else:
            self.txt_combos.insert(
                tk.END, "✓ No high-risk collusion or exfiltration combinations triggered.\n"
            )

        # 6. Tab: Recommendations
        self.txt_recs.delete("1.0", tk.END)
        self.txt_recs.insert(
            tk.END, "===================================================================\n"
        )
        self.txt_recs.insert(
            tk.END, "                    ACTIONABLE RECOMMENDATIONS                     \n"
        )
        self.txt_recs.insert(
            tk.END, "===================================================================\n\n"
        )
        for r in fusion.get("recommendations", []):
            self.txt_recs.insert(tk.END, f"➔ {r}\n\n")

    def _open_feature_plot(self):
        """Open or generate the feature importance plot."""
        plot_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "data", "feature_importance.png")
        )
        try:
            if not os.path.exists(plot_path):
                self.ml_pipeline.export_feature_importance_plot(plot_path)
        except Exception as e:
            messagebox.showerror("Feature Importance Plot", f"Could not generate the plot:\n{e}")
            return

        # Open in default system viewer
        try:
            if sys.platform == "win32":
                os.startfile(plot_path)
            elif sys.platform == "darwin":
                import subprocess

                subprocess.run(["open", plot_path], check=False)
            else:
                import subprocess

                subprocess.run(["xdg-open", plot_path], check=False)
        except Exception as e:
            messagebox.showinfo(
                "Feature Importance Plot", f"Plot generated at:\n{plot_path}\n({e})"
            )


def launch_gui():
    """Application entrypoint for the Tkinter desktop GUI."""
    root = tk.Tk()
    _app = PrivacyAnalyzerGUI(root)  # keep-alive reference for Tk callbacks
    root.mainloop()


if __name__ == "__main__":
    if "--test" in sys.argv:
        # Automated self-test mode: initialize app, verify components, and exit cleanly
        root = tk.Tk()
        root.withdraw()
        app = PrivacyAnalyzerGUI(root)
        sample_apk = os.path.join(ROOT_DIR, "data", "apks", "calculator_sample.apk")
        if os.path.exists(sample_apk):
            app._execute_analysis(sample_apk, "Calculator")
            app._pump_ui_queue()
        root.destroy()
        print(
            "Self-test passed: Desktop GUI initialized and connected to all pipeline modules successfully!"
        )
        sys.exit(0)

    launch_gui()
