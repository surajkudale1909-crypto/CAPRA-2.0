"""Report Generation Module for CAPRA v2.

Generates publication-ready Markdown reports and structured JSON audit trails
from completed privacy risk analyses.
Designed for cybersecurity college presentation, academic audits, and automated CI/CD.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.config import settings

logger = logging.getLogger(__name__)


def generate_markdown_report(
    analysis_result: Dict[str, Any],
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """Generate a clean, structured, publication-grade Markdown audit report.

    Args:
        analysis_result: Structured analysis dictionary from pipeline.
        output_path: Optional target file path. If None, generated automatically
                     in `reports/privacy_audit_<package>_<timestamp>.md`.

    Returns:
        The complete markdown text as a string.
    """
    manifest = analysis_result.get("manifest", {})
    context = analysis_result.get("context", {})
    fusion = analysis_result.get("fusion", {})
    threat = analysis_result.get("threat", {})
    ml = analysis_result.get("ml", {})
    static_sec = analysis_result.get("static_analysis", {})

    app_name = manifest.get("app_name") or "Unknown Application"
    pkg_name = manifest.get("package_name") or "unknown.package"
    ver_name = manifest.get("version_name") or "N/A"
    ver_code = manifest.get("version_code") or "N/A"
    target_sdk = manifest.get("target_sdk_version") or "N/A"
    min_sdk = manifest.get("min_sdk_version") or "N/A"
    apk_path = analysis_result.get("file_path", manifest.get("file_path", "unknown"))

    category = analysis_result.get("category") or context.get("category") or "General"
    cat_desc = context.get("category_description") or ""

    score = fusion.get("score", 0)
    verdict = fusion.get("verdict", "UNKNOWN")
    raw_penalty = fusion.get("raw_penalty", 0)

    # Determine verdict emoji and color indicator
    verdict_badge = {
        "Safe": "🟢 SAFE",
        "Low": "🔵 LOW RISK",
        "Medium": "🟡 MEDIUM RISK",
        "High": "🟠 HIGH RISK",
        "Critical": "🔴 CRITICAL RISK",
    }.get(verdict, f"⚪ {verdict.upper()}")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = []

    # Title & Header
    lines.append("# CAPRA 2.0 - Privacy Risk Audit Report")
    lines.append("**Project:** Context-Aware Mobile App Privacy Risk Analyzer (CAPRA)  ")
    lines.append(
        "**Institution:** Vishwakarma Institute of Technology, Pune (CS-AI Dept, Group 8)  "
    )
    lines.append(f"**Audit Timestamp:** `{now_str}`  ")
    lines.append("---")
    lines.append("")

    # Executive Summary Card
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Application Name** | **{app_name}** |")
    lines.append(f"| **Package Identifier** | `{pkg_name}` |")
    lines.append(f"| **Risk Verdict** | **{verdict_badge}** |")
    lines.append(f"| **Composite Privacy Risk Score** | **`{score} / 100`** |")
    lines.append(
        f"| **Raw Penalty Points** | `{raw_penalty}` pts (Ceiling: {settings.raw_score_ceiling}) |"
    )
    lines.append(f"| **Functional Category** | `{category}` ({cat_desc}) |")
    lines.append("")

    # Score Breakdown Weights
    sb = fusion.get("score_breakdown", {})
    if sb:
        lines.append("### Composite Risk Score Attribution")
        lines.append("")
        lines.append("| Component | Weight | Raw Risk % | Contribution |")
        lines.append("| :--- | :---: | :---: | :---: |")
        lines.append(
            f"| **Contextual Heuristics** | {int(sb.get('heuristic_weight', 0.5) * 100)}% | "
            f"{sb.get('heuristic_component', 0)}% | +{sb.get('heuristic_contribution', 0)} pts |"
        )
        lines.append(
            f"| **Machine Learning** | {int(sb.get('ml_weight', 0.35) * 100)}% | "
            f"{sb.get('ml_component', 0)}% | +{sb.get('ml_contribution', 0)} pts |"
        )
        lines.append(
            f"| **Attack Surface & Static** | {int(sb.get('surface_weight', 0.15) * 100)}% | "
            f"{sb.get('surface_component', 0)}% | +{sb.get('surface_contribution', 0)} pts |"
        )
        if sb.get("threat_intel_override"):
            lines.append(
                "| **Threat Intel Critical Override** | Override | 100% | **Normalized to High/Critical** |"
            )
        lines.append("")

    # Application Metadata & Cryptographic Hashes
    lines.append("## 2. Application Identity & Cryptographic Hashes")
    lines.append("")
    comps = manifest.get("components", {})
    exported = comps.get("exported", {})
    h = threat.get("hashes", {}) if threat else {}

    lines.append(f"- **File Path:** `{apk_path}`")
    lines.append(f"- **Version:** {ver_name} (Code: `{ver_code}`)")
    lines.append(f"- **API Targets:** Target SDK `{target_sdk}` | Min SDK `{min_sdk}`")
    lines.append(
        f"- **Components Registered:** {comps.get('activities_count', 0)} Activities, "
        f"{comps.get('services_count', 0)} Services, {comps.get('receivers_count', 0)} Receivers, "
        f"{comps.get('providers_count', 0)} Providers"
    )
    lines.append(
        f"- **Exported Attack Surface:** `{exported.get('total_exported', 0)}` total exported "
        f"(`{exported.get('unprotected_exported', 0)}` unprotected)"
    )
    lines.append(f"- **SHA-256:** `{h.get('sha256', 'N/A')}`")
    lines.append(f"- **SHA-1:** `{h.get('sha1', 'N/A')}`")
    lines.append(f"- **MD5:** `{h.get('md5', 'N/A')}`")
    lines.append("")

    # Threat Intelligence & VirusTotal Live
    lines.append("## 3. Threat Intelligence & Reputation")
    lines.append("")
    if threat:
        status = threat.get("status", "UNKNOWN")
        source = threat.get("source", "LOCAL_DATABASE")
        reputation = threat.get("reputation", "No threat data available.")
        vt_stats = threat.get("vt_stats")

        lines.append(f"- **Threat Status:** `{status}` [{source}]")
        lines.append(f"- **Reputation Summary:** {reputation}")

        if vt_stats:
            lines.append(
                f"- **VirusTotal Live Detection:** **{vt_stats.get('malicious', 0)} / "
                f"{vt_stats.get('total_engines', 0)}** security vendors flagged this hash"
            )
            if vt_stats.get("suggested_threat_label"):
                lines.append(
                    f"- **Suggested Threat Label:** `{vt_stats.get('suggested_threat_label')}`"
                )
            if vt_stats.get("permalink"):
                lines.append(
                    f"- **VirusTotal Analysis URL:** [{vt_stats.get('permalink')}]({vt_stats.get('permalink')})"
                )

        if threat.get("threat_details"):
            td = threat["threat_details"]
            lines.append(f"- **Malware Family:** `{td.get('family')}` ({td.get('threat_type')})")
            lines.append(f"- **Severity:** `{td.get('severity')}`")
    else:
        lines.append("Threat intelligence engine was bypassed or offline for this audit.")
    lines.append("")

    # Contextual Heuristic Analysis
    lines.append("## 4. Contextual Permission Evaluation (Context Engine)")
    lines.append("")
    lines.append(f"**Baseline Evaluation against Category: `{category}`**")
    lines.append("")

    # Suspicious Mismatches
    suspicious = context.get("suspicious_permissions", [])
    if suspicious:
        lines.append("### ⚠️ Suspicious Permissions / Category Mismatches")
        lines.append("")
        lines.append("| Permission | Penalty | Risk Rationale | Real-World Baseline |")
        lines.append("| :--- | :---: | :--- | :--- |")
        for s in suspicious:
            p_name = s.get("permission", "").replace("android.permission.", "")
            emp_note = s.get("empirical_note", "")
            lines.append(
                f"| `{p_name}` | +{s.get('penalty', 0)} pts | {s.get('reason', '')} | {emp_note} |"
            )
        lines.append("")

    # Dangerous Combinations
    combinations = context.get("triggered_combinations", [])
    if combinations:
        lines.append("### 🚨 Dangerous Permission Combinations (Collusion / Exfiltration)")
        lines.append("")
        for comb in combinations:
            matched = [
                p.replace("android.permission.", "") for p in comb.get("matched_permissions", [])
            ]
            lines.append(
                f"- **{comb.get('name')}** (`{comb.get('risk_type')}`, +{comb.get('penalty')} pts)"
            )
            lines.append(f"  - **Co-occurring Permissions:** `{' + '.join(matched)}`")
            lines.append(f"  - **Security Impact:** {comb.get('description')}")
        lines.append("")
    else:
        lines.append("✅ **No dangerous collusion or exfiltration combinations triggered.**")
        lines.append("")

    # Contextual exemptions (combinations that are expected functionality)
    exemptions = context.get("contextual_exemptions", [])
    if exemptions:
        lines.append("### ℹ️ Expected Functionality Combinations (not penalized)")
        lines.append("")
        for comb in exemptions:
            matched = [
                p.replace("android.permission.", "") for p in comb.get("matched_permissions", [])
            ]
            lines.append(
                f"- **{comb.get('name')}** (`{' + '.join(matched)}`) — {comb.get('exempt_reason', '')}"
            )
        lines.append("")

    # Real-world category baseline notes (informational enrichment)
    empirical = context.get("empirical_context", {})
    if empirical.get("available"):
        store_list = ", ".join(empirical.get("store_categories", []))
        lines.append(
            f"### 📊 Real-World Category Baselines (sample: {empirical.get('sample_size', 0)} apps)"
        )
        lines.append("")
        lines.append(
            f"Derived from `data/empirical_baselines.json` (store categories: {store_list})."
        )
        lines.append("")
        notes = empirical.get("category_norm_notes", [])
        if notes:
            for note in notes:
                lines.append(f"- {note}")
        else:
            lines.append("- No unusually rare permissions relative to this category's norms.")
        lines.append("")

    # Baseline Acceptable
    acceptable = context.get("acceptable_permissions", [])
    if acceptable:
        lines.append(f"### Standard Expected Baseline Permissions ({len(acceptable)})")
        lines.append("")
        acc_names = [
            f"`{a.get('permission', '').replace('android.permission.', '')}`" for a in acceptable
        ]
        lines.append(", ".join(acc_names))
        lines.append("")

    # Machine Learning Estimation
    lines.append("## 5. Machine Learning Permission Risk Estimation (ML Pipeline)")
    lines.append("")
    if ml:
        ml_prob = ml.get("risk_percentage", 0.0)
        ml_verdict = ml.get("ml_verdict", "N/A")
        model_name = ml.get("model_type", "Random Forest Classifier")
        is_syn = ml.get("is_synthetic", False)
        src_tag = (
            "Synthetic Fallback Dataset" if is_syn else ml.get("data_source", "Drebin / CIC-AndMal")
        )

        lines.append(f"- **Trained Model:** `{model_name}` ({src_tag})")
        lines.append(f"- **Inference Risk Probability:** **`{ml_prob}%`** (`{ml_verdict}`)")

        prov = ml.get("model_provenance", {})
        if prov:
            lines.append("")
            lines.append("### Model Provenance")
            lines.append("")
            lines.append(
                f"- **Dataset:** {', '.join(f'`{f}`' for f in prov.get('dataset_files', [])) or 'n/a'} "
                f"({prov.get('n_samples', 'n/a')} samples, "
                f"{prov.get('class_balance', {}).get('malware', '?')} malware / "
                f"{prov.get('class_balance', {}).get('benign', '?')} benign, "
                f"{prov.get('feature_count', '?')} features)"
            )
            for fname, sha in (prov.get("dataset_sha256") or {}).items():
                lines.append(f"- **SHA-256 `{fname}`:** `{sha}`")
            lines.append(
                f"- **Training Environment:** scikit-learn {prov.get('sklearn_version', '?')}, "
                f"trained at {prov.get('trained_at', '?')}"
            )

        top_contrib = ml.get("top_contributing_permissions", [])
        if top_contrib:
            lines.append("")
            lines.append("### Active Permission Feature Attribution")
            lines.append("")
            lines.append("| Permission Feature | Gini Importance | Relative Contribution |")
            lines.append("| :--- | :---: | :---: |")
            for c in top_contrib:
                lines.append(
                    f"| `{c.get('short_name')}` | {c.get('importance_score', 0):.4f} | +{c.get('risk_contribution_pct', 0)}% |"
                )
            lines.append("")
    else:
        lines.append("Machine learning inference was skipped or unavailable.")
    lines.append("")

    # Advanced Static Bytecode Analysis
    lines.append("## 6. Advanced Static Analysis & Attack Surface")
    lines.append("")
    if static_sec:
        # Trackers
        t_data = static_sec.get("trackers", {})
        t_count = t_data.get("tracker_count", 0)
        lines.append(f"### Embedded Third-Party Trackers ({t_count} Detected)")
        lines.append("")
        if t_count > 0:
            lines.append("| Tracker Name | Category | Signature Namespace |")
            lines.append("| :--- | :--- | :--- |")
            for trk in t_data.get("detected_trackers", []):
                lines.append(
                    f"| **{trk.get('name')}** | {trk.get('category')} | `{trk.get('signature')}` |"
                )
            lines.append("")
        else:
            lines.append(
                "✅ No known tracking, advertising, or profiling SDK signatures identified in DEX bytecode."
            )
            lines.append("")

        # Network
        n_data = static_sec.get("network", {})
        lines.append("### Network Surface & String Pool Inspection")
        lines.append("")
        lines.append(f"- **Total URLs Extracted:** `{n_data.get('total_urls', 0)}`")
        lines.append(
            f"- **Cleartext Insecure HTTP Endpoints:** `{n_data.get('insecure_http_count', 0)}`"
        )
        raw_ips = n_data.get("raw_public_ips", [])
        if raw_ips:
            lines.append(f"- **Hardcoded Public IPs:** `{', '.join(raw_ips)}`")
        for nf in n_data.get("findings", []):
            lines.append(f"  - ⚠️ {nf}")
        lines.append("")

        # Security Findings
        s_data = static_sec.get("security", {})
        sec_findings = s_data.get("findings", [])
        if sec_findings:
            lines.append("### Bytecode Security Signals")
            lines.append("")
            for sf in sec_findings:
                lines.append(f"- ⚠️ {sf}")
            lines.append("")

        # Hardcoded secrets / credentials
        secrets = s_data.get("secrets_detected", []) or s_data.get("bytecode_security", {}).get(
            "secrets_detected", []
        )
        if secrets:
            lines.append("### 🔑 Hardcoded Secrets & Embedded Credentials")
            lines.append("")
            lines.append("| Secret Type | Occurrences | Redacted Samples |")
            lines.append("| :--- | :---: | :--- |")
            for sec in secrets:
                samples = ", ".join(f"`{s}`" for s in sec.get("samples", []))
                lines.append(f"| **{sec.get('type')}** | {sec.get('occurrences', 0)} | {samples} |")
            lines.append("")
            lines.append(
                "> Samples are redacted by CAPRA; full secret values are never written to reports."
            )
            lines.append("")

        # Reachability
        r_data = static_sec.get("reachability", {})
        if r_data.get("has_leakage_path"):
            lines.append("### 🚨 Privacy Egress Reachability Pathways")
            lines.append("")
            lines.append(
                f"Identified `{r_data.get('leakage_paths_count', 0)}` source-to-sink reachability "
                f"pathway(s) connecting sensitive device hardware or telemetry to network egress sinks."
            )
            lines.append("")
            for p in r_data.get("paths", []):
                lines.append(
                    f"- **Source:** `{p.get('source')}` ➔ **Sink:** `{p.get('sink')}` "
                    f"({p.get('type')}, {p.get('confidence')})"
                )
                lines.append(f"  - **Path:** `{p.get('caller_method')}`")
                if p.get("description"):
                    lines.append(f"  - {p.get('description')}")
            lines.append("")
            if r_data.get("limitations_disclaimer"):
                lines.append(f"> {r_data['limitations_disclaimer']}")
                lines.append("")

        # Exported component / deep-link attack surface
        exp = manifest.get("components", {}).get("exported", {})
        if exp.get("total_exported"):
            lines.append("### 🌐 Exported Component & Deep-Link Surface")
            lines.append("")
            lines.append(
                f"- **Exported components:** {exp.get('total_exported', 0)} "
                f"({exp.get('unprotected_exported', 0)} without permission protection)"
            )
            deep = exp.get("deeplinks", [])
            if deep:
                lines.append(f"- **Registered deep links:** `{', '.join(sorted(set(deep)))}`")
            if exp.get("browsable_unprotected"):
                lines.append(
                    f"- ⚠️ **{exp.get('browsable_unprotected')} unprotected BROWSABLE component(s)** "
                    "reachable from external apps/web links — classic deep-link hijack surface."
                )
            lines.append("")
    else:
        lines.append("Advanced static bytecode inspection was not executed.")
        lines.append("")

    # Key Privacy Findings & Recommendations
    lines.append("## 7. Key Findings & Actionable Recommendations")
    lines.append("")
    lines.append("### Primary Risk Findings")
    for f in fusion.get("findings", []):
        lines.append(f"- {f}")
    lines.append("")

    lines.append("### Actionable Hardening Recommendations")
    for r in fusion.get("recommendations", []):
        lines.append(f"1. {r}")
    lines.append("")

    # Footer
    lines.append("---")
    lines.append(
        "*Generated by CAPRA v2.0 (Context-Aware Mobile App Privacy Risk Analyzer) | VIT Pune CS-AI Group 8*"
    )

    content = "\n".join(lines)

    # Resolve target output path
    if output_path is None:
        safe_pkg = re.sub(r"[^a-zA-Z0-9_\.]", "_", pkg_name)
        ts_clean = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_dir = Path(settings.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        target_file = reports_dir / f"privacy_audit_{safe_pkg}_{ts_clean}.md"
    else:
        target_file = Path(output_path)
        target_file.parent.mkdir(parents=True, exist_ok=True)

    with open(target_file, "w", encoding="utf-8") as f:
        f.write(content)

    logger.info(f"Markdown audit report written to: {target_file}")
    return str(target_file)


def export_json_report(
    analysis_result: Dict[str, Any],
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """Export complete analysis result as structured JSON.

    Args:
        analysis_result: Structured analysis dictionary from pipeline.
        output_path: Optional destination path.

    Returns:
        String path of exported JSON file.
    """
    manifest = analysis_result.get("manifest", {})
    pkg_name = manifest.get("package_name") or "unknown.package"

    if output_path is None:
        safe_pkg = re.sub(r"[^a-zA-Z0-9_\.]", "_", pkg_name)
        ts_clean = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_dir = Path(settings.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        target_file = reports_dir / f"privacy_audit_{safe_pkg}_{ts_clean}.json"
    else:
        target_file = Path(output_path)
        target_file.parent.mkdir(parents=True, exist_ok=True)

    with open(target_file, "w", encoding="utf-8") as f:
        json.dump(analysis_result, f, indent=2)

    logger.info(f"JSON audit report exported to: {target_file}")
    return str(target_file)
