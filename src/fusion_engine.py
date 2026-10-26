"""Fusion Engine Module.

Aggregates contextual penalties, component exposure, and sensitive permission counts
into a normalized 0-100 privacy risk score with categorical verdicts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class RiskVerdict:
    SAFE = "Safe"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class FusionEngine:
    """Aggregates and normalizes risk signals into a unified privacy risk verdict."""

    def __init__(
        self,
        raw_ceiling: int = 160,
        weights: Optional[Dict[str, float]] = None,
    ):
        """Initialize FusionEngine with raw score ceiling and tunable component weights.

        Args:
            raw_ceiling: Raw penalty points threshold that maps to a 100 score.
            weights: Dictionary with weights for 'heuristic' (default 0.50),
                     'ml' (default 0.35), and 'surface' (default 0.15).
        """
        self.raw_ceiling = raw_ceiling
        self.weights = weights or {"heuristic": 0.50, "ml": 0.35, "surface": 0.15}

    def calculate_score(self, raw_penalty: int, ceiling: Optional[int] = None) -> int:
        """Normalize raw penalty points to a 0-100 integer score.

        Args:
            raw_penalty: Raw accumulated penalty points.
            ceiling: Optional per-call ceiling override; defaults to self.raw_ceiling.
        """
        if raw_penalty <= 0:
            return 0
        effective_ceiling = ceiling if ceiling is not None else self.raw_ceiling
        normalized = (raw_penalty / effective_ceiling) * 100
        return min(100, max(0, int(round(normalized))))

    def get_verdict(self, score: int) -> str:
        """Assign categorical verdict based on score thresholds."""
        if score <= 20:
            return RiskVerdict.SAFE
        elif score <= 45:
            return RiskVerdict.LOW
        elif score <= 70:
            return RiskVerdict.MEDIUM
        elif score <= 89:
            return RiskVerdict.HIGH
        else:
            return RiskVerdict.CRITICAL

    def _generate_findings(
        self,
        context_result: Dict[str, Any],
        manifest_data: Optional[Dict[str, Any]] = None,
        threat_data: Optional[Dict[str, Any]] = None,
        ml_data: Optional[Dict[str, Any]] = None,
        static_data: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Generate human-readable summary bullet points explaining the score."""
        findings: List[str] = []

        # Threat intelligence alerts
        if threat_data:
            if threat_data.get("is_flagged"):
                td = threat_data.get("threat_details", {})
                vt_stats = threat_data.get("vt_stats")
                if vt_stats:
                    findings.append(
                        f"CRITICAL THREAT (VirusTotal): {vt_stats.get('malicious')}/{vt_stats.get('total_engines')} "
                        f"AV engines flagged sample as '{td.get('family', 'Malware')}'. "
                        f"(Permalink: {vt_stats.get('permalink')})"
                    )
                else:
                    findings.append(
                        f"CRITICAL THREAT: Matched known malware family '{td.get('family')}' ({td.get('threat_type')})."
                    )
            elif threat_data.get("is_verified_benign"):
                findings.append(f"Threat Intel: SHA-256 matched verified signature ({threat_data.get('reputation')}).")
            elif threat_data.get("status") == "SUSPICIOUS":
                findings.append(f"Threat Intel Warning: {threat_data.get('reputation')}.")


        # Machine learning alerts
        if ml_data:
            prob = ml_data.get("risk_percentage", 0.0)
            data_src = ml_data.get("data_source", "Unknown")
            if prob >= 70.0:
                findings.append(
                    f"Machine Learning Alert: High-risk anomaly detected by {ml_data.get('model_type', 'model')} "
                    f"({prob}% probability, source: {data_src})."
                )
        category = context_result.get("category", "General")
        breakdown = context_result.get("breakdown", {})
        suspicious = context_result.get("suspicious_permissions", [])
        combinations = context_result.get("triggered_combinations", [])
        unexpected = context_result.get("unexpected_dangerous_permissions", [])

        if breakdown.get("acceptable_count", 0) > 0 and len(suspicious) == 0 and len(combinations) == 0:
            findings.append(
                f"All requested permissions align with standard baseline requirements for {category} applications."
            )

        if suspicious:
            perm_names = [s["permission"].replace("android.permission.", "") for s in suspicious]
            findings.append(
                f"Requested {len(suspicious)} suspicious permission(s) anomalous for {category}: {', '.join(perm_names)}."
            )

        if unexpected:
            unexp_names = [u["permission"].replace("android.permission.", "") for u in unexpected]
            findings.append(
                f"Declared {len(unexpected)} unlisted AOSP runtime dangerous permission(s): {', '.join(unexp_names)}."
            )

        if combinations:
            for c in combinations:
                findings.append(f"Exfiltration Hazard: {c['name']} - {c['description']}")

        if manifest_data:
            exported_info = manifest_data.get("components", {}).get("exported", {})
            unprotected = exported_info.get("unprotected_exported", 0)
            if unprotected > 0:
                findings.append(
                    f"Attack Surface Exposure: {unprotected} exported component(s) have no permission guards."
                )

            target_sdk = manifest_data.get("target_sdk_version")
            if target_sdk and target_sdk < 28:
                findings.append(
                    f"Outdated Target SDK ({target_sdk}): Application bypasses modern runtime permission safeguards."
                )

        # Advanced static analysis findings (Phase 4)
        if static_data:
            trackers_info = static_data.get("trackers", {})
            if trackers_info.get("has_trackers"):
                t_count = trackers_info.get("tracker_count", 0)
                t_names = [t.get("name") for t in trackers_info.get("detected_trackers", [])[:3]]
                findings.append(
                    f"Third-Party Trackers: Detected {t_count} tracking/ad SDK(s) "
                    f"({', '.join(t_names)}{'...' if t_count > 3 else ''})."
                )

            net_info = static_data.get("network", {})
            for nf in net_info.get("findings", []):
                findings.append(f"Network Exposure: {nf}")

            sec_info = static_data.get("security", {})
            for sf in sec_info.get("findings", []):
                findings.append(f"Security Configuration: {sf}")

            reach_info = static_data.get("reachability", {})
            for rf in reach_info.get("findings", []):
                findings.append(f"Reachability & Taint: {rf}")

        if not findings:
            findings.append("No significant privacy or privilege anomalies detected.")

        return findings

    def _generate_recommendations(
        self,
        verdict: str,
        context_result: Dict[str, Any],
        threat_data: Optional[Dict[str, Any]] = None,
        static_data: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Generate actionable recommendations for auditors and end-users."""
        recs: List[str] = []
        combinations = context_result.get("triggered_combinations", [])

        if threat_data and threat_data.get("is_flagged"):
            recs.append("CRITICAL: Immediate quarantine required. Known malware hash signature detected.")
            recs.append("Isolate device from network and check for unauthorized data exfiltration.")
            return recs

        if verdict in (RiskVerdict.CRITICAL, RiskVerdict.HIGH):
            recs.append("DO NOT INSTALL or immediately quarantine this application in enterprise environments.")
            recs.append("Conduct deep dynamic taint analysis (e.g. FlowDroid) to verify data sinks.")
        elif verdict == RiskVerdict.MEDIUM:
            recs.append("Review in-app runtime permission prompts carefully before granting access.")
            recs.append("Disable background data access and revoke unused permissions via Android settings.")
        else:
            recs.append("Application exhibits normal permission footprint; safe for standard use.")

        for c in combinations:
            if "STORAGE" in c["id"] or "MEDIA" in c["id"]:
                recs.append("Enforce Scoped Storage (Storage Access Framework) to prevent arbitrary file access.")
            if "SMS" in c["id"]:
                recs.append("Verify if SMS Retriever API can replace full READ_SMS permissions for OTP verification.")
            if "CONTACTS" in c["id"]:
                recs.append("Replace direct contact reading with system Intent picker to preserve user privacy.")

        if static_data:
            net_info = static_data.get("network", {})
            if net_info.get("insecure_http_count", 0) > 0:
                recs.append("Enforce HTTPS across all network operations; declare android:usesCleartextTraffic='false'.")

            trackers_info = static_data.get("trackers", {})
            if trackers_info.get("tracker_count", 0) > 2:
                recs.append("Audit and consolidate embedded ad/tracking SDKs to minimize third-party data collection.")

            sec_info = static_data.get("security", {})
            bytecode_sec = sec_info.get("bytecode_security", {})
            if bytecode_sec.get("has_dcl"):
                recs.append("Avoid Dynamic Code Loading (DCL); load all required code statically within the verified package.")

            reach_info = static_data.get("reachability", {})
            if reach_info.get("has_leakage_path"):
                recs.append("Decouple sensitive device queries from network transmission paths using local anonymization.")

        return recs

    def fuse(
        self,
        context_result: Dict[str, Any],
        manifest_data: Optional[Dict[str, Any]] = None,
        threat_data: Optional[Dict[str, Any]] = None,
        ml_data: Optional[Dict[str, Any]] = None,
        static_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Fuse contextual evaluation, manifest metadata, threat intel, ML, and static analysis into a final risk assessment.

        Blends:
        - Contextual Heuristics (50%)
        - Machine Learning Risk Probability (35%)
        - Attack Surface Exposure (15%)
        Overridden to Critical (98-100) if threat intelligence signature flags malware.

        Returns:
            Dictionary with final score, verdict, score breakdown, findings, and recommendations.
        """
        penalties = context_result.get("penalties", {})
        raw_penalty = penalties.get("total_raw_penalty", 0)

        # Allow dynamic ceiling from rules if defined (without mutating shared state)
        weights = context_result.get("scoring_weights", {})
        ceiling = weights.get("max_raw_score_ceiling", self.raw_ceiling)

        heuristic_score = self.calculate_score(raw_penalty, ceiling=ceiling)

        if ml_data is not None:
            ml_prob = ml_data.get("risk_probability", 0.0)
            ml_score = min(100, max(0, ml_prob * 100))

            # Surface exposure component (unprotected exported components & outdated target SDK)
            surface_penalty = penalties.get("exported_component_penalty", 0)
            if manifest_data:
                target_sdk = manifest_data.get("target_sdk_version")
                if target_sdk and target_sdk < 28:
                    surface_penalty += 15

            # Incorporate static analysis exposure into surface score if available
            if static_data:
                t_score = static_data.get("trackers", {}).get("risk_score", 0.0)
                n_score = static_data.get("network", {}).get("network_risk_score", 0.0)
                s_score = static_data.get("security", {}).get("security_risk_score", 0.0)
                r_score = static_data.get("reachability", {}).get("leak_risk_score", 0.0)
                static_avg = (t_score * 0.2 + n_score * 0.3 + s_score * 0.25 + r_score * 0.25)
                surface_penalty += int(static_avg * 0.3)

            surface_score = min(100, (surface_penalty / 30.0) * 100)

            w_h = self.weights.get("heuristic", 0.50)
            w_m = self.weights.get("ml", 0.35)
            w_s = self.weights.get("surface", 0.15)
            total_w = w_h + w_m + w_s
            w_h, w_m, w_s = w_h / total_w, w_m / total_w, w_s / total_w

            blended = (w_h * heuristic_score) + (w_m * ml_score) + (w_s * surface_score)
            score = int(round(blended))
            score = max(0, min(100, score))
        else:
            score = heuristic_score
            ml_score = 0.0
            surface_score = 0.0
            w_h, w_m, w_s = 1.0, 0.0, 0.0

        # Threat Intel signature match overrides to Critical (98-100)
        is_threat_override = False
        if threat_data and threat_data.get("is_flagged"):
            score = max(score, 98)
            is_threat_override = True

        verdict = self.get_verdict(score)
        findings = self._generate_findings(context_result, manifest_data, threat_data, ml_data, static_data)
        recommendations = self._generate_recommendations(verdict, context_result, threat_data, static_data)

        score_breakdown = {
            "heuristic_component": round(heuristic_score, 1),
            "heuristic_weight": round(w_h, 2),
            "heuristic_contribution": round(heuristic_score * w_h, 1),
            "ml_component": round(ml_score, 1),
            "ml_weight": round(w_m, 2),
            "ml_contribution": round(ml_score * w_m, 1),
            "surface_component": round(surface_score, 1),
            "surface_weight": round(w_s, 2),
            "surface_contribution": round(surface_score * w_s, 1),
            "threat_intel_override": is_threat_override,
            "composite_score": score,
        }

        return {
            "score": score,
            "verdict": verdict,
            "raw_penalty": raw_penalty,
            "penalty_breakdown": penalties,
            "score_breakdown": score_breakdown,
            "findings": findings,
            "recommendations": recommendations,
        }

