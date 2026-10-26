"""CAPRA 2.0 - Context-Aware Mobile App Privacy Risk Analyzer.

Main Command Line Interface (CLI) Entry Point.
Thin frontend routing requests to the unified analysis pipeline in src.pipeline.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Dict, Optional

# Ensure clean UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import colorama

    colorama.init(autoreset=True)
except ImportError:
    pass

from src.config import settings, setup_logging
from src.context_engine import ContextEngine, ContextRuleError
from src.extractor import APKCorruptedError, APKExtractionError, APKNotFoundError
from src.fusion_engine import RiskVerdict
from src.history_manager import HistoryManager
from src.ml_pipeline import PermissionMLPipeline
from src.pipeline import PrivacyAnalysisPipeline, run_synthetic_demo
from src.report_generator import generate_markdown_report

logger = logging.getLogger("capra.cli")

# ANSI Color Codes for terminal reporting
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_ORANGE = "\033[38;5;208m"
COLOR_RED = "\033[91m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_DIM = "\033[2m"


def get_verdict_color(verdict: str) -> str:
    """Return ANSI color associated with risk verdict."""
    if verdict == RiskVerdict.SAFE:
        return COLOR_GREEN
    elif verdict == RiskVerdict.LOW:
        return COLOR_CYAN
    elif verdict == RiskVerdict.MEDIUM:
        return COLOR_YELLOW
    elif verdict == RiskVerdict.HIGH:
        return COLOR_ORANGE
    else:
        return COLOR_RED


def print_banner() -> None:
    """Print project header banner."""
    banner = f"""{COLOR_CYAN}{COLOR_BOLD}
================================================================================
  CAPRA 2.0 - Context-Aware Mobile App Privacy Risk Analyzer
================================================================================{COLOR_RESET}"""
    print(banner)


def format_report_terminal(
    manifest_data: Dict[str, Any],
    context_data: Dict[str, Any],
    fusion_data: Dict[str, Any],
    threat_data: Optional[Dict[str, Any]] = None,
    ml_data: Optional[Dict[str, Any]] = None,
    detection_data: Optional[Dict[str, Any]] = None,
    static_data: Optional[Dict[str, Any]] = None,
) -> None:
    """Print an aesthetically structured, rich privacy evaluation report."""
    verdict = fusion_data.get("verdict", "Unknown")
    score = fusion_data.get("score", 0)
    v_color = get_verdict_color(verdict)

    print(f"\n{COLOR_BOLD}[1] APPLICATION METADATA & THREAT INTEL{COLOR_RESET}")
    print("-" * 80)
    print(
        f"  {COLOR_BOLD}App Name:{COLOR_RESET}           {manifest_data.get('app_name') or 'N/A'}"
    )
    print(f"  {COLOR_BOLD}Package Name:{COLOR_RESET}       {manifest_data.get('package_name')}")
    print(
        f"  {COLOR_BOLD}Target SDK:{COLOR_RESET}         {manifest_data.get('target_sdk_version') or 'N/A'} (Min SDK: {manifest_data.get('min_sdk_version') or 'N/A'})"
    )
    print(
        f"  {COLOR_BOLD}Version:{COLOR_RESET}            {manifest_data.get('version_name') or 'N/A'} (Code: {manifest_data.get('version_code') or 'N/A'})"
    )

    cat_name = context_data.get("category", "General")
    if detection_data:
        conf = detection_data.get("confidence_percentage", 100.0)
        if detection_data.get("is_overridden"):
            cat_display = f"{COLOR_CYAN}{cat_name}{COLOR_RESET} [Manual Override]"
        else:
            cat_display = f"{COLOR_CYAN}{cat_name}{COLOR_RESET} [Auto-Detected: {conf:.1f}% confidence, {detection_data.get('method')}]"
    else:
        cat_display = cat_name

    print(
        f"  {COLOR_BOLD}Analyzed Category:{COLOR_RESET}  {cat_display} - {COLOR_DIM}{context_data.get('category_description')}{COLOR_RESET}"
    )
    print(
        f"  {COLOR_BOLD}Total Permissions:{COLOR_RESET}  {manifest_data.get('total_permissions_count')}"
    )

    comps = manifest_data.get("components", {})
    exported = comps.get("exported", {})
    print(
        f"  {COLOR_BOLD}Components:{COLOR_RESET}         Activities: {comps.get('activities_count', 0)} | "
        f"Services: {comps.get('services_count', 0)} | Receivers: {comps.get('receivers_count', 0)} | "
        f"Providers: {comps.get('providers_count', 0)}"
    )
    print(
        f"  {COLOR_BOLD}Exported Surface:{COLOR_RESET}   Total Exported: {exported.get('total_exported', 0)} | "
        f"Unprotected: {exported.get('unprotected_exported', 0)}"
    )

    if threat_data:
        h = threat_data.get("hashes", {})
        status = threat_data.get("status")
        source = threat_data.get("source", "LOCAL_DATABASE")
        src_badge = f"{COLOR_CYAN}[{source}]{COLOR_RESET}"
        print(
            f"  {COLOR_BOLD}SHA-256 Hash:{COLOR_RESET}       {COLOR_DIM}{h.get('sha256', 'N/A')}{COLOR_RESET} {src_badge}"
        )

        vt_stats = threat_data.get("vt_stats")
        if vt_stats:
            mal = vt_stats.get("malicious", 0)
            tot = vt_stats.get("total_engines", 0)
            det_color = COLOR_RED if mal >= 3 else (COLOR_YELLOW if mal > 0 else COLOR_GREEN)
            print(
                f"  {COLOR_BOLD}VirusTotal Live:{COLOR_RESET}    {det_color}{COLOR_BOLD}{mal}/{tot} Security Vendors Flagged{COLOR_RESET} ({vt_stats.get('suggested_threat_label') or 'Clean'})"
            )
            print(
                f"  {COLOR_BOLD}VT Analysis Link:{COLOR_RESET}   {COLOR_DIM}{vt_stats.get('permalink')}{COLOR_RESET}"
            )

        if status == "MALICIOUS":
            td = threat_data.get("threat_details", {})
            print(
                f"  {COLOR_RED}{COLOR_BOLD}Threat Intel Alert: [MALICIOUS MATCH] {td.get('family')} ({td.get('threat_type')}){COLOR_RESET}"
            )
        elif status == "VERIFIED_BENIGN":
            print(
                f"  {COLOR_GREEN}{COLOR_BOLD}Threat Intel Alert: [VERIFIED BENIGN] {threat_data.get('reputation')}{COLOR_RESET}"
            )
        elif status == "SUSPICIOUS":
            print(
                f"  {COLOR_YELLOW}{COLOR_BOLD}Threat Intel Alert: [SUSPICIOUS] {threat_data.get('reputation')}{COLOR_RESET}"
            )
        else:
            print(
                f"  {COLOR_DIM}Threat Intel Alert: No matching signature in local malware database.{COLOR_RESET}"
            )

    # Permission Classification Breakdown
    print(f"\n{COLOR_BOLD}[2] CONTEXTUAL PERMISSION EVALUATION (CONTEXT ENGINE){COLOR_RESET}")
    print("-" * 80)

    # Acceptable
    acceptable = context_data.get("acceptable_permissions", [])
    if acceptable:
        print(
            f"  {COLOR_GREEN}[+] Baseline Acceptable Permissions ({len(acceptable)}):{COLOR_RESET}"
        )
        for item in acceptable:
            p_name = item["permission"].replace("android.permission.", "")
            print(f"     - {COLOR_GREEN}{p_name}{COLOR_RESET}")
    else:
        print(f"  {COLOR_DIM}No standard baseline permissions requested.{COLOR_RESET}")

    # Suspicious
    suspicious = context_data.get("suspicious_permissions", [])
    if suspicious:
        print(
            f"\n  {COLOR_RED}[-] Category Mismatches / Suspicious Permissions ({len(suspicious)}):{COLOR_RESET}"
        )
        for item in suspicious:
            p_name = item["permission"].replace("android.permission.", "")
            print(f"     - {COLOR_RED}{COLOR_BOLD}{p_name}{COLOR_RESET} (+{item['penalty']} pts)")
            print(f"       {COLOR_DIM}Reason: {item['reason']}{COLOR_RESET}")
            if item.get("empirical_note"):
                print(f"       {COLOR_DIM}Real-world: {item['empirical_note']}{COLOR_RESET}")

    # Unexpected Dangerous
    unexp = context_data.get("unexpected_dangerous_permissions", [])
    if unexp:
        print(
            f"\n  {COLOR_ORANGE}[!] Unlisted Dangerous AOSP Permissions ({len(unexp)}):{COLOR_RESET}"
        )
        for item in unexp:
            p_name = item["permission"].replace("android.permission.", "")
            print(f"     - {COLOR_ORANGE}{p_name}{COLOR_RESET} (+{item['penalty']} pts)")
            if item.get("empirical_note"):
                print(f"       {COLOR_DIM}Real-world: {item['empirical_note']}{COLOR_RESET}")

    # Dangerous Combinations
    combinations = context_data.get("triggered_combinations", [])
    print(
        f"\n{COLOR_BOLD}[3] DANGEROUS PERMISSION COMBINATIONS (COLLUSION / EXFILTRATION){COLOR_RESET}"
    )
    print("-" * 80)
    if combinations:
        for comb in combinations:
            print(
                f"  {COLOR_RED}[ALERT] {comb['name']} [{comb['risk_type']}]{COLOR_RESET} (+{comb['penalty']} pts)"
            )
            matched = [p.replace("android.permission.", "") for p in comb["matched_permissions"]]
            print(f"     Co-occurring: {COLOR_BOLD}{' + '.join(matched)}{COLOR_RESET}")
            print(f"     {COLOR_DIM}Description: {comb['description']}{COLOR_RESET}")
    else:
        print(
            f"  {COLOR_GREEN}[+] No high-risk collusion or data-exfiltration combinations triggered.{COLOR_RESET}"
        )

    # Contextual exemptions (expected functionality — not penalized)
    exemptions = context_data.get("contextual_exemptions", [])
    if exemptions:
        print(
            f"\n  {COLOR_DIM}[i] Expected Functionality Combinations (not penalized):{COLOR_RESET}"
        )
        for comb in exemptions:
            matched = [p.replace("android.permission.", "") for p in comb["matched_permissions"]]
            print(f"     {COLOR_DIM}- {comb['name']}: {' + '.join(matched)}{COLOR_RESET}")

    # Real-world empirical category baselines (informational)
    empirical = context_data.get("empirical_context", {})
    if empirical.get("available"):
        store_list = ", ".join(empirical.get("store_categories", []))
        print(
            f"\n  {COLOR_DIM}[i] Real-World Baselines (n={empirical.get('sample_size', 0)} apps, "
            f"store: {store_list}):{COLOR_RESET}"
        )
        notes = empirical.get("category_norm_notes", [])
        if notes:
            for note in notes:
                print(f"     {COLOR_DIM}- {note}{COLOR_RESET}")
        else:
            print(
                f"     {COLOR_DIM}- No unusually rare permissions for this category.{COLOR_RESET}"
            )

    # Machine Learning Estimation
    if ml_data:
        ml_prob = ml_data.get("risk_percentage", 0.0)
        ml_verdict = ml_data.get("ml_verdict", "Unknown")
        ml_color = COLOR_RED if ml_prob >= 50 else COLOR_GREEN
        data_source = ml_data.get("data_source", "SYNTHETIC")
        model_name = ml_data.get("model_type", "Random Forest")
        source_badge = (
            f"{COLOR_YELLOW}[SYNTHETIC FALLBACK]{COLOR_RESET}"
            if ml_data.get("is_synthetic")
            else f"{COLOR_CYAN}[{data_source}]{COLOR_RESET}"
        )

        print(f"\n{COLOR_BOLD}[4] MACHINE LEARNING RISK ESTIMATION (ML PIPELINE){COLOR_RESET}")
        print("-" * 80)
        print(f"  {COLOR_BOLD}Model:{COLOR_RESET}                      {model_name} {source_badge}")
        print(
            f"  {COLOR_BOLD}Inference Risk Probability:{COLOR_RESET} [{ml_color}{COLOR_BOLD} {ml_prob}% {COLOR_RESET}] -> {ml_color}{ml_verdict}{COLOR_RESET}"
        )

        top_contrib = ml_data.get("top_contributing_permissions", [])
        if top_contrib:
            print(f"  {COLOR_BOLD}Active Permission Explainability:{COLOR_RESET}")
            for c in top_contrib:
                contrib_val = c.get("risk_contribution_pct", 0.0)
                print(
                    f"     • {COLOR_BOLD}{c['short_name']:<24}{COLOR_RESET} (importance: {c['importance_score']:.4f}, impact: +{contrib_val}%)"
                )

    # Advanced Static Analysis & Reachability
    if static_data:
        print(f"\n{COLOR_BOLD}[5] ADVANCED STATIC ANALYSIS & REACHABILITY{COLOR_RESET}")
        print("-" * 80)
        # Trackers
        t_data = static_data.get("trackers", {})
        t_count = t_data.get("tracker_count", 0)
        if t_count > 0:
            print(f"  {COLOR_RED}[-] Embedded Third-Party Trackers ({t_count}):{COLOR_RESET}")
            for trk in t_data.get("detected_trackers", [])[:5]:
                print(
                    f"     • {COLOR_BOLD}{trk['name']}{COLOR_RESET} ({trk['category']}) - {COLOR_DIM}{trk.get('signature')}{COLOR_RESET}"
                )
        else:
            print(
                f"  {COLOR_GREEN}[+] Embedded Trackers: None detected in DEX bytecode.{COLOR_RESET}"
            )

        # Network endpoints
        n_data = static_data.get("network", {})
        insecure_cnt = n_data.get("insecure_http_count", 0)
        raw_ips = n_data.get("raw_public_ips", [])
        print(
            f"  {COLOR_BOLD}Network Extraction:{COLOR_RESET}         {n_data.get('total_urls', 0)} URLs discovered in string pool"
        )
        if insecure_cnt > 0:
            print(
                f"     {COLOR_RED}[!] Insecure Cleartext HTTP:{COLOR_RESET} {insecure_cnt} endpoint(s) found"
            )
        if raw_ips:
            print(
                f"     {COLOR_RED}[!] Raw Public IP Targets:{COLOR_RESET}   {', '.join(raw_ips[:3])}"
            )

        # Security & Bytecode
        s_data = static_data.get("security", {})
        sec_findings = s_data.get("findings", [])
        if sec_findings:
            print(f"  {COLOR_YELLOW}[!] Security Warnings & Bytecode Signals:{COLOR_RESET}")
            for sf in sec_findings[:3]:
                print(f"     • {sf}")

        # Reachability
        r_data = static_data.get("reachability", {})
        if r_data.get("has_leakage_path"):
            p_count = r_data.get("leakage_paths_count", 0)
            print(
                f"  {COLOR_RED}[ALERT] Privacy Data Egress Reachability Paths ({p_count}):{COLOR_RESET}"
            )
            for p in r_data.get("paths", [])[:3]:
                print(
                    f"     • {COLOR_BOLD}{p.get('source')}{COLOR_RESET} --> [{COLOR_CYAN}{p.get('sink')}{COLOR_RESET}] ({p.get('confidence')})"
                )
        else:
            print(
                f"  {COLOR_GREEN}[+] Reachability: No direct source-to-sink egress pathways identified.{COLOR_RESET}"
            )

    # Final Risk Verdict Box
    section_num = "[6]" if static_data else ("[5]" if ml_data else "[4]")
    print(f"\n{COLOR_BOLD}{section_num} PRIVACY RISK VERDICT & AGGREGATION{COLOR_RESET}")
    print("=" * 80)
    print(
        f"  {COLOR_BOLD}Raw Penalty Points:{COLOR_RESET}    {fusion_data.get('raw_penalty', 0)} pts"
    )
    print(
        f"  {COLOR_BOLD}Normalized Risk Score:{COLOR_RESET} [{v_color}{COLOR_BOLD} {score} / 100 {COLOR_RESET}]"
    )
    print(
        f"  {COLOR_BOLD}Risk Verdict Level:{COLOR_RESET}    {v_color}{COLOR_BOLD}* {verdict.upper()} RISK *{COLOR_RESET}"
    )

    sb = fusion_data.get("score_breakdown", {})
    if sb:
        print("-" * 80)
        print(f"  {COLOR_DIM}Component Contribution Breakdown:{COLOR_RESET}")
        print(
            f"    • Contextual Heuristics ({int(sb.get('heuristic_weight', 0.5) * 100)}% wt):  {sb.get('heuristic_component', 0)}% risk -> {sb.get('heuristic_contribution', 0)} pts"
        )
        print(
            f"    • Machine Learning ({int(sb.get('ml_weight', 0.35) * 100)}% wt):        {sb.get('ml_component', 0)}% risk -> {sb.get('ml_contribution', 0)} pts"
        )
        print(
            f"    • Attack Surface ({int(sb.get('surface_weight', 0.15) * 100)}% wt):          {sb.get('surface_component', 0)}% risk -> {sb.get('surface_contribution', 0)} pts"
        )
        if sb.get("threat_intel_override"):
            print(
                f"    {COLOR_RED}{COLOR_BOLD}[!] Threat Intel Critical Override Applied: Normalized to {score}/100{COLOR_RESET}"
            )
    print("=" * 80)

    print(f"\n{COLOR_BOLD}Key Privacy Findings:{COLOR_RESET}")
    for finding in fusion_data.get("findings", []):
        print(f"  * {finding}")

    print(f"\n{COLOR_BOLD}Actionable Recommendations:{COLOR_RESET}")
    for rec in fusion_data.get("recommendations", []):
        print(f"  -> {rec}")
    print("=" * 80 + "\n")


def print_history_table(records: list[Dict[str, Any]]) -> None:
    """Print an aesthetically formatted table of past scan records from history.db."""
    print_banner()
    print(f"\n{COLOR_BOLD}HISTORICAL AUDIT LOG (SQLite Database: data/history.db){COLOR_RESET}")
    print("=" * 95)
    if not records:
        print(f"  {COLOR_DIM}No prior analysis records found in audit database.{COLOR_RESET}\n")
        return

    hdr = f"  {COLOR_BOLD}{'ID':<5} {'Timestamp (UTC)':<22} {'Package Name':<30} {'Category':<14} {'Score':<8} {'Verdict':<10}{COLOR_RESET}"
    print(hdr)
    print("  " + "-" * 91)
    for r in records:
        v_col = get_verdict_color(r["verdict"])
        print(
            f"  {r['id']:<5} {r['timestamp'][:19]:<22} {r['package_name'][:28]:<30} "
            f"{r['category'][:12]:<14} {r['score']:<8} {v_col}{r['verdict']:<10}{COLOR_RESET}"
        )
    print("=" * 95 + "\n")


def print_compare_diff(diff: Dict[str, Any]) -> None:
    """Print comparative differential audit between two historical scans."""
    print_banner()
    r1 = diff["record_1"]
    r2 = diff["record_2"]
    cmp = diff["comparison"]

    print(
        f"\n{COLOR_BOLD}COMPARATIVE DIFFERENTIAL AUDIT: Scan #{r1['id']} vs Scan #{r2['id']}{COLOR_RESET}"
    )
    print("=" * 80)
    print(
        f"  {COLOR_BOLD}Baseline (Build 1):{COLOR_RESET}   #{r1['id']} [{r1['timestamp'][:19]}] - {r1['package_name']} (v{r1['version_name'] or 'N/A'})"
    )
    print(
        f"  {COLOR_BOLD}Comparison (Build 2):{COLOR_RESET} #{r2['id']} [{r2['timestamp'][:19]}] - {r2['package_name']} (v{r2['version_name'] or 'N/A'})"
    )
    print("-" * 80)

    delta = cmp["score_delta"]
    d_sign = f"+{delta}" if delta > 0 else str(delta)
    v1_col = get_verdict_color(r1["verdict"])
    v2_col = get_verdict_color(r2["verdict"])
    delta_col = COLOR_RED if delta > 0 else (COLOR_GREEN if delta < 0 else COLOR_CYAN)

    print(
        f"  {COLOR_BOLD}Risk Score Drift:{COLOR_RESET}     {r1['score']}/100 ➔ {r2['score']}/100 [{delta_col}{COLOR_BOLD}{d_sign} pts{COLOR_RESET}]"
    )
    print(
        f"  {COLOR_BOLD}Verdict Shift:{COLOR_RESET}        {v1_col}{r1['verdict']}{COLOR_RESET} ➔ {v2_col}{r2['verdict']}{COLOR_RESET}"
    )
    print(
        f"  {COLOR_BOLD}Audit Trajectory:{COLOR_RESET}     {delta_col}{COLOR_BOLD}{cmp['trajectory']}{COLOR_RESET} ({cmp['summary']})"
    )
    print(
        f"  {COLOR_BOLD}ML Risk Drift:{COLOR_RESET}        {cmp['ml_delta']:+.1f}% probability shift"
    )
    print("-" * 80)

    added_perms = cmp.get("permissions_added", [])
    if added_perms:
        print(f"  {COLOR_RED}[+] Newly Introduced Permissions ({len(added_perms)}):{COLOR_RESET}")
        for p in added_perms:
            print(f"     - {COLOR_RED}{p}{COLOR_RESET}")
    else:
        print(f"  {COLOR_GREEN}[✓] No new permissions added.{COLOR_RESET}")

    removed_perms = cmp.get("permissions_removed", [])
    if removed_perms:
        print(
            f"\n  {COLOR_CYAN}[-] Revoked / Removed Permissions ({len(removed_perms)}):{COLOR_RESET}"
        )
        for p in removed_perms:
            print(f"     - {COLOR_CYAN}{p}{COLOR_RESET}")

    added_trk = cmp.get("trackers_added", [])
    if added_trk:
        print(f"\n  {COLOR_RED}[!] Newly Embedded Trackers ({len(added_trk)}):{COLOR_RESET}")
        for t in added_trk:
            print(f"     • {COLOR_RED}{t}{COLOR_RESET}")

    removed_trk = cmp.get("trackers_removed", [])
    if removed_trk:
        print(f"\n  {COLOR_GREEN}[✓] Removed Trackers ({len(removed_trk)}):{COLOR_RESET}")
        for t in removed_trk:
            print(f"     • {COLOR_GREEN}{t}{COLOR_RESET}")
    print("=" * 80 + "\n")


def analyze_app(
    apk_path: str,
    category: Optional[str] = None,
    rules_path: Optional[str] = None,
    vt_key: Optional[str] = None,
    no_vt: bool = False,
    no_history: bool = False,
) -> Dict[str, Any]:
    """Compatibility wrapper around unified analyze_apk with VirusTotal options."""
    active_key = None if no_vt else (vt_key or settings.virustotal_api_key)
    pipeline = PrivacyAnalysisPipeline(rules_path=rules_path, vt_api_key=active_key)
    options = {"skip_history": no_history}
    return pipeline.analyze(apk_path, category=category, options=options)


def main() -> None:
    """CLI driver routine."""
    setup_logging()

    parser = argparse.ArgumentParser(
        description="CAPRA - Context-Aware Mobile App Privacy Risk Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "apk_path",
        nargs="?",
        type=str,
        default=None,
        help="Path to the Android APK file to inspect (positional shortcut for --apk).",
    )
    parser.add_argument(
        "--apk",
        type=str,
        help="Path to the Android APK file to inspect.",
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Target functional category of the app (e.g. Calculator, Flashlight, Navigation). If omitted, automatically detected.",
    )
    parser.add_argument(
        "--rules",
        type=str,
        default=None,
        help="Path to custom context_rules.json file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output complete analysis report as JSON to stdout.",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List all supported categories in the active rule configuration.",
    )
    parser.add_argument(
        "--demo",
        choices=["benign_calculator", "malicious_flashlight", "benign_navigation"],
        help="Run a synthetic demo scenario (useful for presentation benchmarks without an external APK).",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the interactive desktop Graphical User Interface.",
    )
    parser.add_argument(
        "--plot",
        action="store_true",
        help="Generate and export the Machine Learning feature-importance chart to data/feature_importance.png.",
    )
    parser.add_argument(
        "--vt-key",
        type=str,
        default=None,
        help="Optional VirusTotal v3 API key override (defaults to VIRUSTOTAL_API_KEY environment variable).",
    )
    parser.add_argument(
        "--no-vt",
        action="store_true",
        help="Disable online VirusTotal threat reputation lookups and operate in offline-only mode.",
    )
    parser.add_argument(
        "--report-md",
        nargs="?",
        const="",
        default=None,
        help="Export a comprehensive Markdown audit report. If no path is provided, writes to reports/ directory.",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show recent scan history from the SQLite audit database (data/history.db).",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        type=int,
        metavar=("ID1", "ID2"),
        help="Compare two past scans by ID (e.g. --compare 1 2) to evaluate risk delta.",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Do not save this scan to the SQLite audit database.",
    )

    args = parser.parse_args()

    # Resolve APK path: --apk flag takes precedence, positional argument as fallback
    if not args.apk and args.apk_path:
        args.apk = args.apk_path

    if args.vt_key:
        print(
            f"{COLOR_YELLOW}Warning: --vt-key exposes the API key in shell history and process lists. "
            f"Prefer the VIRUSTOTAL_API_KEY environment variable.{COLOR_RESET}",
            file=sys.stderr,
        )

    # History Mode
    if args.history:
        try:
            hm = HistoryManager()
            records = hm.get_history(limit=50)
            if args.json:
                print(json.dumps(records, indent=2))
            else:
                print_history_table(records)
            sys.exit(0)
        except Exception as e:
            print(f"Error accessing history database: {e}", file=sys.stderr)
            sys.exit(1)

    # Comparative Differential Mode
    if args.compare:
        try:
            id1, id2 = args.compare
            hm = HistoryManager()
            diff_data = hm.compare_analyses(id1, id2)
            if args.json:
                print(json.dumps(diff_data, indent=2))
            else:
                print_compare_diff(diff_data)
            sys.exit(0)
        except Exception as e:
            print(f"Error comparing scans: {e}", file=sys.stderr)
            sys.exit(1)

    # GUI Mode (Samriddhi's Module)
    if args.gui:
        try:
            from src.gui import launch_gui

            launch_gui()
            sys.exit(0)
        except Exception as e:
            print(f"Failed to launch GUI: {e}", file=sys.stderr)
            sys.exit(1)

    # Feature Importance Plot generation (Ishan's Module)
    if args.plot:
        try:
            ml_pipe = PermissionMLPipeline()
            out = ml_pipe.export_feature_importance_plot()
            print(f"Feature importance plot exported successfully to: {out}")
            sys.exit(0)
        except Exception as e:
            print(f"Error generating plot: {e}", file=sys.stderr)
            sys.exit(1)

    # Category listing mode
    if args.list_categories:
        try:
            ce = ContextEngine(args.rules)
            print_banner()
            print("\nSupported Application Categories:")
            for cat in ce.get_supported_categories():
                desc = ce.categories[cat].get("description", "")
                print(f"  * {COLOR_BOLD}{cat}{COLOR_RESET}: {desc}")
            print()
            sys.exit(0)
        except Exception as e:
            print(f"Error loading categories: {e}", file=sys.stderr)
            sys.exit(1)

    # Demo mode
    if args.demo:
        if not args.json:
            print_banner()
        demo_category = args.category or (
            "Calculator"
            if "calculator" in args.demo
            else ("Navigation" if "navigation" in args.demo else "Flashlight")
        )
        results = run_synthetic_demo(args.demo, category=demo_category)

        # Save to history unless disabled
        if not args.no_history:
            try:
                hm = HistoryManager()
                rec_id = hm.save_analysis(results)
                results["history_id"] = rec_id
            except Exception as e:
                logger.warning(f"Failed to save demo to history: {e}")

        # Optional Markdown export
        if args.report_md is not None:
            out_target = None if args.report_md == "" else args.report_md
            md_path = generate_markdown_report(results, output_path=out_target)
            if not args.json:
                print(f"{COLOR_GREEN}[✓] Markdown report exported: {md_path}{COLOR_RESET}")

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            format_report_terminal(
                results["manifest"],
                results["context"],
                results["fusion"],
                results.get("threat"),
                results.get("ml"),
                results.get("category_detection"),
                results.get("static_analysis"),
            )
        sys.exit(0)

    # Standard APK Analysis mode
    if not args.apk:
        parser.print_help()
        print(
            f"\n{COLOR_RED}Error: an APK path is required for analysis (e.g. 'python main.py app.apk'; or use --apk, --demo for simulation, --gui for desktop app).{COLOR_RESET}"
        )
        sys.exit(1)

    if not args.json:
        print_banner()

    try:
        results = analyze_app(
            args.apk,
            args.category,
            args.rules,
            vt_key=args.vt_key,
            no_vt=args.no_vt,
            no_history=args.no_history,
        )

        # Optional Markdown export
        if args.report_md is not None:
            out_target = None if args.report_md == "" else args.report_md
            md_path = generate_markdown_report(results, output_path=out_target)
            if not args.json:
                print(f"{COLOR_GREEN}[✓] Markdown report exported: {md_path}{COLOR_RESET}")

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            format_report_terminal(
                results["manifest"],
                results["context"],
                results["fusion"],
                results.get("threat"),
                results.get("ml"),
                results.get("category_detection"),
                results.get("static_analysis"),
            )
    except APKNotFoundError as e:
        print(f"\n{COLOR_RED}File Error: {e}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)
    except APKCorruptedError as e:
        print(f"\n{COLOR_RED}APK Archive Corrupted / Invalid: {e}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)
    except APKExtractionError as e:
        # APKTooLargeError / APKSecurityError / APKParseTimeoutError land here
        print(f"\n{COLOR_RED}APK Safety Check Failed: {e}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)
    except ContextRuleError as e:
        print(f"\n{COLOR_RED}Context Rule Error: {e}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n{COLOR_RED}Analysis Pipeline Error: {e}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
