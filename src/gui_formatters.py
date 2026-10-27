# ==============================================================================
# File: src/gui_formatters.py
# Owner: Group 8 (GUI Polish Phase)
# Description: Tk-free presentation logic for the desktop GUI — risk-band
#              colors, gauge geometry, permission table rows, theme palettes,
#              settings persistence, and report/compare text builders. Keeping
#              this module free of tkinter imports means every visual decision
#              is unit-testable on headless machines (CI, sandboxes).
# ==============================================================================

from __future__ import annotations

import json
import math
import os
from typing import Any, Dict, List, Optional

from src.threat_intel import display_threat_status

# ---------------------------------------------------------------------------
# Risk bands (must mirror fusion verdict bands pinned by tests/test_golden.py:
# 0-20 Safe, 21-45 Low, 46-70 Medium, 71-89 High, 90-100 Critical)
# ---------------------------------------------------------------------------

RISK_BANDS: List[Dict[str, Any]] = [
    {"name": "Safe", "lo": 0, "hi": 20, "color": "#22c55e"},
    {"name": "Low", "lo": 21, "hi": 45, "color": "#84cc16"},
    {"name": "Medium", "lo": 46, "hi": 70, "color": "#f59e0b"},
    {"name": "High", "lo": 71, "hi": 89, "color": "#ef4444"},
    {"name": "Critical", "lo": 90, "hi": 100, "color": "#b91c1c"},
]

# Row groups for the color-coded permissions table
ROW_GROUPS: Dict[str, str] = {
    "acceptable": "✓ Expected",
    "neutral": "· Neutral",
    "suspicious": "⚠ Suspicious",
    "dangerous": "✖ Dangerous",
    "combination": "✖ Combination",
    "exempt": "ℹ Exempt (expected)",
}


def score_band(score: float) -> Dict[str, Any]:
    """Return the risk band record ({name, lo, hi, color}) for a 0-100 score."""
    s = max(0.0, min(100.0, float(score)))
    for band in RISK_BANDS:
        if band["lo"] <= s <= band["hi"]:
            return band
    return RISK_BANDS[-1]


def gauge_geometry(score: float, size: int = 240) -> Dict[str, Any]:
    """Compute canvas geometry for the semicircular risk gauge.

    Pure math (no tkinter) so the visual layout is unit-testable.

    Tk's create_arc measures angles counter-clockwise from 3 o'clock
    (a point at angle α sits at cx + r·cos α, cy − r·sin α). The top-half
    sweep therefore runs 180° (9 o'clock, score 0) → 90° (top) → 0°
    (3 o'clock, score 100) — i.e. each band is stroked with a NEGATIVE
    extent starting at its lower-score edge.
    """
    frac = max(0.0, min(1.0, float(score) / 100.0))
    pad = max(12, size // 16)
    cx, cy = size / 2.0, size * 0.55
    radius = size / 2.0 - pad

    segments = []
    cursor = 180.0
    for band in RISK_BANDS:
        extent = 180.0 * ((band["hi"] - band["lo"] + 1) / 101.0)
        segments.append(
            {
                "start": cursor,
                "extent": -extent,
                "color": band["color"],
                "band": band["name"],
            }
        )
        cursor -= extent

    # Needle endpoint (plain screen-cartesian math: 180° = left / score 0,
    # 270° = top, 360° = right / score 100).
    theta = math.radians(180.0 + 180.0 * frac)
    needle = (cx + radius * 0.70 * math.cos(theta), cy + radius * 0.70 * math.sin(theta))

    band = score_band(score)
    return {
        "center": (cx, cy),
        "radius": radius,
        "pad": pad,
        "segments": segments,
        "progress_extent": -180.0 * frac,
        "progress_start": 180.0,
        "needle": needle,
        "hub_radius": max(6, size // 36),
        "height": int(size * 0.88),
        # Text stack lives BELOW the hub so the needle sweep stays clear.
        "score_pos": (cx, cy + radius * 0.28),
        "unit_pos": (cx + radius * 0.36, cy + radius * 0.32),
        "verdict_pos": (cx, cy + radius * 0.58),
        "band_name": band["name"],
        "band_color": band["color"],
    }


def permission_rows(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten a context-engine result into color-coded table rows.

    Each row: {group, group_label, name, penalty, detail, tag}
    where tag maps to a Treeview row tag (ok/warn/bad/muted/info).
    """
    rows: List[Dict[str, Any]] = []

    def _add(group: str, tag: str, entry: Dict[str, Any], detail_key: str = "reason"):
        if isinstance(entry, str):  # neutral lists are plain permission names
            entry = {"permission": entry}
        name = str(entry.get("permission", entry.get("name", "?")))
        rows.append(
            {
                "group": group,
                "group_label": ROW_GROUPS[group],
                "name": name.replace("android.permission.", ""),
                "penalty": int(entry.get("penalty", 0)),
                "detail": str(entry.get(detail_key, "") or ""),
                "tag": tag,
            }
        )

    for entry in context.get("suspicious_permissions", []):
        _add("suspicious", "warn", entry)
    for entry in context.get("unexpected_dangerous_permissions", []):
        _add("dangerous", "bad", entry)
    for entry in context.get("triggered_combinations", []):
        matched = " + ".join(
            p.replace("android.permission.", "") for p in entry.get("matched_permissions", [])
        )
        rows.append(
            {
                "group": "combination",
                "group_label": ROW_GROUPS["combination"],
                "name": str(entry.get("name", "?")),
                "penalty": int(entry.get("penalty", 0)),
                "detail": f"{entry.get('risk_type', '')}: {matched}",
                "tag": "bad",
            }
        )
    for entry in context.get("contextual_exemptions", []):
        matched = " + ".join(
            p.replace("android.permission.", "") for p in entry.get("matched_permissions", [])
        )
        rows.append(
            {
                "group": "exempt",
                "group_label": ROW_GROUPS["exempt"],
                "name": str(entry.get("name", "?")),
                "penalty": 0,
                "detail": f"{matched} — {entry.get('exempt_reason', 'expected functionality')}",
                "tag": "info",
            }
        )
    for entry in context.get("acceptable_permissions", []):
        _add("acceptable", "ok", entry, detail_key="empirical_note")
    for entry in context.get("neutral_permissions", []):
        _add("neutral", "muted", entry, detail_key="empirical_note")

    return rows


def combination_rows(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Rows for the Exfiltration Combinations tab (triggered + exempt)."""
    rows = []
    for entry in context.get("triggered_combinations", []):
        rows.append(
            {
                "name": entry.get("name", "?"),
                "risk_type": entry.get("risk_type", ""),
                "penalty": int(entry.get("penalty", 0)),
                "permissions": " + ".join(
                    p.replace("android.permission.", "")
                    for p in entry.get("matched_permissions", [])
                ),
                "exempt": False,
                "description": entry.get("description", ""),
                "tag": "bad",
            }
        )
    for entry in context.get("contextual_exemptions", []):
        rows.append(
            {
                "name": entry.get("name", "?"),
                "risk_type": entry.get("risk_type", ""),
                "penalty": 0,
                "permissions": " + ".join(
                    p.replace("android.permission.", "")
                    for p in entry.get("matched_permissions", [])
                ),
                "exempt": True,
                "description": entry.get("exempt_reason", "expected functionality"),
                "tag": "info",
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Theme palettes
# ---------------------------------------------------------------------------

_LIGHT_PALETTE = {
    "bg": "#f1f5f9",
    "card_bg": "#ffffff",
    "header_bg": "#0f172a",
    "header_fg": "#f8fafc",
    "text": "#1e293b",
    "muted": "#64748b",
    "accent": "#2563eb",
    "ok": "#16a34a",
    "warn": "#d97706",
    "bad": "#dc2626",
    "info": "#0369a1",
    "gauge_bg": "#ffffff",
    "entry_bg": "#ffffff",
    "status_bg": "#e2e8f0",
    "tree_bg": "#ffffff",
    "tree_fg": "#1e293b",
}

_DARK_PALETTE = {
    "bg": "#0f172a",
    "card_bg": "#1e293b",
    "header_bg": "#111c33",
    "header_fg": "#e2e8f0",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
    "accent": "#3b82f6",
    "ok": "#22c55e",
    "warn": "#f59e0b",
    "bad": "#ef4444",
    "info": "#38bdf8",
    "gauge_bg": "#1e293b",
    "entry_bg": "#0f172a",
    "status_bg": "#1e293b",
    "tree_bg": "#0f172a",
    "tree_fg": "#e2e8f0",
}


def theme_palette(dark: bool = True) -> Dict[str, str]:
    """Return the full color palette for the requested theme."""
    return dict(_DARK_PALETTE if dark else _LIGHT_PALETTE)


# ---------------------------------------------------------------------------
# Settings persistence (~/.capra/gui_settings.json)
# ---------------------------------------------------------------------------

MAX_RECENT_FILES = 8


def default_settings_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".capra", "gui_settings.json")


def default_settings() -> Dict[str, Any]:
    return {
        "theme": "dark",
        "last_dir": "",
        "recent_files": [],
        "vt_api_key": "",
    }


def mask_api_key(key: Any) -> str:
    """Masked display form of an API key (never log or show raw keys)."""
    s = str(key or "").strip()
    if not s:
        return "(not set)"
    if len(s) >= 12:
        return f"{s[:4]}…{s[-4:]}"
    return "••••••"


def load_settings(path: Optional[str] = None) -> Dict[str, Any]:
    """Load GUI settings; missing/corrupt files fall back to defaults."""
    path = path or default_settings_path()
    settings = default_settings()
    try:
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            settings.update({k: v for k, v in loaded.items() if k in settings})
    except (OSError, ValueError):
        pass
    return settings


def save_settings(settings: Dict[str, Any], path: Optional[str] = None) -> bool:
    """Persist GUI settings; returns True on success."""
    path = path or default_settings_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "theme": settings.get("theme", "dark"),
                    "last_dir": settings.get("last_dir", ""),
                    "recent_files": list(settings.get("recent_files", []))[:MAX_RECENT_FILES],
                    "vt_api_key": settings.get("vt_api_key", ""),
                },
                f,
                indent=2,
            )
        return True
    except OSError:
        return False


def add_recent_file(settings: Dict[str, Any], path: str) -> List[str]:
    """Prepend a file to the recent-files list (deduped, capped)."""
    path = os.path.abspath(path)
    recent = [p for p in settings.get("recent_files", []) if p != path]
    recent.insert(0, path)
    recent = recent[:MAX_RECENT_FILES]
    settings["recent_files"] = recent
    settings["last_dir"] = os.path.dirname(path)
    return recent


# ---------------------------------------------------------------------------
# Text formatting helpers
# ---------------------------------------------------------------------------


def format_bytes(num_bytes: int) -> str:
    """Human-readable file size."""
    size = float(max(0, int(num_bytes)))
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def format_file_label(path: str) -> str:
    """Short label for the selected-file line: 'app.apk (2.3 MB)'."""
    name = os.path.basename(path) or path
    try:
        size = os.path.getsize(path)
        return f"{name}  ({format_bytes(size)})"
    except OSError:
        return name


def build_overview_text(
    manifest: Dict[str, Any],
    context: Dict[str, Any],
    fusion: Dict[str, Any],
    threat: Dict[str, Any],
    ml: Dict[str, Any],
    static_analysis: Optional[Dict[str, Any]] = None,
) -> str:
    """Compose the Overview tab text (kept plain-text for copy/paste)."""
    lines: List[str] = []
    lines.append("=" * 68)
    lines.append("           APPLICATION OVERVIEW & INTEGRATED AUDIT")
    lines.append("=" * 68)
    lines.append("")
    lines.append(f"App Name:           {manifest.get('app_name') or 'N/A'}")
    lines.append(f"Package Name:       {manifest.get('package_name')}")
    lines.append(
        f"Target SDK:         {manifest.get('target_sdk_version')} "
        f"(Min SDK: {manifest.get('min_sdk_version')})"
    )
    lines.append(
        f"Version:            {manifest.get('version_name')} (Code: {manifest.get('version_code')})"
    )
    lines.append(
        f"Analyzed Category:  {context.get('category')} - {context.get('category_description')}"
    )
    lines.append(f"Total Permissions:  {manifest.get('total_permissions_count')}")
    lines.append("")

    comps = manifest.get("components", {})
    exp = comps.get("exported", {})
    lines.append(
        f"Exported Surface:   {exp.get('total_exported', 0)} Total | "
        f"{exp.get('unprotected_exported', 0)} Unprotected"
    )
    deep = sorted(set(exp.get("deeplinks", [])))
    if deep:
        lines.append(f"Deep Links:         {', '.join(deep)}")
    if exp.get("browsable_unprotected"):
        lines.append(
            f"Deep-Link Warning:   {exp.get('browsable_unprotected')} unprotected "
            "BROWSABLE component(s) reachable externally"
        )
    lines.append("")

    lines.append(f"Threat Intel Hash:  {threat.get('hashes', {}).get('sha256', 'N/A')}")
    t_status = display_threat_status(threat.get("status"), fusion.get("score", 0))
    lines.append(f"Threat Status:      {t_status}")
    lines.append(f"Reputation Status:  {threat.get('reputation') or t_status}")
    lines.append("")
    lines.append(
        f"ML Risk Estimation: {ml.get('risk_percentage')}% [{ml.get('ml_verdict')}] "
        f"(threshold {ml.get('decision_threshold', 0.5)})"
    )
    prov = ml.get("model_provenance") or {}
    if prov.get("dataset_files"):
        lines.append(
            f"Model Provenance:   {', '.join(prov['dataset_files'])} | "
            f"sklearn {prov.get('sklearn_version', '?')} | {prov.get('trained_at', '')}"
        )
    lines.append("")

    if static_analysis:
        t_data = static_analysis.get("trackers", {})
        n_data = static_analysis.get("network", {})
        s_data = static_analysis.get("security", {})
        r_data = static_analysis.get("reachability", {})
        lines.append(f"Trackers Detected:  {t_data.get('tracker_count', 0)}")
        lines.append(
            f"Network Surface:    {n_data.get('total_urls', 0)} URLs | "
            f"{n_data.get('insecure_http_count', 0)} cleartext HTTP"
        )
        secrets = s_data.get("secrets_detected", []) or []
        if secrets:
            lines.append(
                "Hardcoded Secrets:  "
                + ", ".join(s.get("type", "?") for s in secrets)
                + "  (samples redacted)"
            )
        if r_data.get("has_leakage_path"):
            lines.append(
                f"Egress Paths:       {r_data.get('leakage_paths_count', 0)} "
                "source-to-sink reachability path(s)"
            )
        lines.append("")

    lines.append("Key Privacy Findings:")
    findings = fusion.get("findings", [])
    if findings:
        for f in findings:
            lines.append(f"  - {f}")
    else:
        lines.append("  - No major privacy findings.")
    lines.append("")

    emp = context.get("empirical_context") or {}
    if emp.get("available"):
        lines.append(
            f"Real-World Baselines (n={emp.get('sample_size', 0)} apps, "
            f"store: {', '.join(emp.get('store_categories', []))}):"
        )
        for note in emp.get("category_norm_notes", []):
            lines.append(f"  - {note}")
        if not emp.get("category_norm_notes"):
            lines.append("  - No unusually rare permissions for this category.")
        lines.append("")

    return "\n".join(lines)


def build_recommendations_text(fusion: Dict[str, Any]) -> str:
    """Compose the Recommendations tab text."""
    lines: List[str] = ["RECOMMENDATIONS", "=" * 68, ""]
    recs = fusion.get("recommendations", [])
    for i, rec in enumerate(recs, 1):
        lines.append(f"{i}. {rec}")
        lines.append("")
    if not recs:
        lines.append("No specific hardening recommendations.")
    return "\n".join(lines)


def build_comparison_text(compare: Dict[str, Any]) -> str:
    """Compose the history-comparison window text from compare_analyses()."""
    r1 = compare.get("record_1", {})
    r2 = compare.get("record_2", {})
    lines = [
        "SCAN COMPARISON",
        "=" * 68,
        f"Baseline  #{r1.get('id')}: {r1.get('package_name')} "
        f"{r1.get('version_name', '')} — score {r1.get('score')} ({r1.get('verdict')})",
        f"Compared  #{r2.get('id')}: {r2.get('package_name')} "
        f"{r2.get('version_name', '')} — score {r2.get('score')} ({r2.get('verdict')})",
        "",
        f"Trajectory:  {compare.get('trajectory', 'N/A')}",
        f"Summary:     {compare.get('trajectory_summary', '')}",
        f"Score Δ:     {compare.get('score_delta', 0):+}",
        f"ML Δ:        {compare.get('ml_delta', 0):+}",
        "",
    ]
    added = compare.get("added_trackers") or []
    removed = compare.get("removed_trackers") or []
    if added:
        lines.append("New trackers:    " + ", ".join(added))
    if removed:
        lines.append("Removed trackers: " + ", ".join(removed))
    if not added and not removed:
        lines.append("Tracker set unchanged.")
    perm_delta = compare.get("permission_delta") or {}
    if perm_delta:
        lines.append("")
        lines.append(f"Permission changes: {perm_delta}")
    return "\n".join(lines)
