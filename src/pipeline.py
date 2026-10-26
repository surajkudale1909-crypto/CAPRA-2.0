"""Unified Privacy Risk Analysis Pipeline Module for CAPRA.

Core Orchestration Engine (CAPRA v2)
Harmonizes and sequences:
- Threat Intelligence & Reputation Lookup (Suraj's Module)
- Static Manifest & Component Extraction (Androguard Parser)
- Context-Aware Permission Rule Evaluation (Omraj's Module)
- Machine Learning Permission Risk Inference (Ishan's Module)
- Composite Risk Score Fusion & Explainability (Fusion Engine)

Provides a clean, reusable interface `analyze_apk()` consumable by CLI,
Tkinter Desktop GUI (Samriddhi's Module), and future Web/API backends.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from src.category_detector import detect_app_category
from src.config import settings
from src.context_engine import ContextEngine, ContextRuleError
from src.extractor import (
    APKCorruptedError,
    APKExtractionError,
    APKNotFoundError,
    extract_manifest_info,
    run_with_timeout,
)
from src.fusion_engine import FusionEngine, RiskVerdict
from src.history_manager import HistoryManager
from src.ml_pipeline import PermissionMLPipeline
from src.network_detector import NetworkDetector
from src.reachability import ReachabilityAnalyzer
from src.report_generator import export_json_report, generate_markdown_report
from src.security_analyzer import SecurityAnalyzer
from src.threat_intel import ThreatIntelEngine
from src.tracker_detector import TrackerDetector

logger = logging.getLogger(__name__)


class PrivacyAnalysisPipeline:
    """Reusable pipeline orchestrator managing engine lifecycles."""

    def __init__(
        self,
        rules_path: Optional[str] = None,
        threat_db_path: Optional[str] = None,
        model_path: Optional[str] = None,
        raw_ceiling: Optional[int] = None,
        vt_api_key: Optional[str] = None,
        history_db_path: Optional[str] = None,
    ) -> None:
        """Initialize pipeline with optional path configurations."""
        self.rules_path = str(rules_path or settings.rules_path)
        self.threat_db_path = str(threat_db_path or settings.hashes_path)
        self.model_path = str(model_path or settings.model_path)
        self.raw_ceiling = raw_ceiling or settings.raw_score_ceiling
        self.vt_api_key = vt_api_key if vt_api_key is not None else settings.virustotal_api_key
        self.history_db_path = str(history_db_path or settings.history_db_path)

        # Core engines
        self.threat_engine = ThreatIntelEngine(self.threat_db_path, api_key=self.vt_api_key)
        self.context_engine = ContextEngine(self.rules_path)
        self.ml_pipeline = PermissionMLPipeline(self.model_path)
        self.fusion_engine = FusionEngine(raw_ceiling=self.raw_ceiling)
        self.history_manager = HistoryManager(self.history_db_path)


        # Advanced static analysis detectors (Phase 4)
        self.tracker_detector = TrackerDetector()
        self.network_detector = NetworkDetector()
        self.security_analyzer = SecurityAnalyzer()
        self.reachability_analyzer = ReachabilityAnalyzer()


    def analyze(
        self,
        apk_path: str,
        category: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute full 5-stage privacy risk analysis on an APK.

        Args:
            apk_path: Path to target Android APK file.
            category: Optional app category (e.g. 'Calculator'). If None, default
                      or detected category is used.
            options: Optional configuration overrides (e.g. skip_ml, skip_threat).

        Returns:
            Dictionary containing threat intel, manifest data, context heuristics,
            ML risk prediction, and final fused verdict with recommendations.
        """
        opts = options or {}

        if not os.path.isfile(apk_path):
            raise APKNotFoundError(f"Target APK file does not exist: {apk_path}")

        logger.info(f"Starting privacy risk analysis for: {apk_path}")

        # Stage 1: Threat Intelligence Hash Lookup (Suraj's Module)
        threat_result: Optional[Dict[str, Any]] = None
        if not opts.get("skip_threat", False):
            try:
                threat_result = self.threat_engine.lookup_apk(apk_path)
            except Exception as e:
                logger.warning(f"Threat intelligence lookup encountered an issue: {e}")
                threat_result = {
                    "file_path": os.path.abspath(apk_path),
                    "hashes": {},
                    "status": "LOOKUP_ERROR",
                    "is_flagged": False,
                    "is_verified_benign": False,
                    "reputation": f"Error: {e}",
                    "threat_details": None,
                    "benign_details": None,
                }

        # Stage 2: Manifest & Component Extraction
        manifest_data = extract_manifest_info(apk_path)

        # Stage 3: Category Resolution & Auto-Detection (Omraj's Module)
        detection_res = detect_app_category(
            package_name=manifest_data.get("package_name", ""),
            app_name=manifest_data.get("app_name", ""),
            declared_permissions=manifest_data.get("declared_permissions", []),
            components=manifest_data.get("components"),
            override_category=category,
        )
        target_category = detection_res.category
        logger.info(
            f"Category resolved: '{target_category}' "
            f"(Confidence: {detection_res.confidence * 100:.1f}%, Method: {detection_res.method})"
        )

        # Stage 4: Contextual Permission Heuristics (Omraj's Module)
        exported_info = manifest_data.get("components", {}).get("exported", {})
        context_result = self.context_engine.evaluate_permissions(
            requested_permissions=manifest_data.get("declared_permissions", []),
            category=target_category,
            exported_components_info=exported_info,
        )

        # Stage 5: Machine Learning Permission Risk Inference (Ishan's Module)
        ml_result: Optional[Dict[str, Any]] = None
        if not opts.get("skip_ml", False):
            try:
                ml_result = self.ml_pipeline.predict_risk(manifest_data.get("declared_permissions", []))
            except Exception as e:
                logger.warning(f"ML risk prediction encountered an issue: {e}")
                ml_result = {
                    "risk_probability": 0.0,
                    "risk_percentage": 0.0,
                    "predicted_class": 0,
                    "ml_verdict": f"Unavailable ({e})",
                    "active_feature_count": 0,
                    "top_contributing_permissions": [],
                }

        # Stage 6: Advanced Static Analysis (Trackers, Network, Security, Reachability)
        # Runs under a hard time budget: DEX parsing of malicious/pathological APKs
        # must never hang the pipeline (see src/extractor.py hardening).
        static_result: Optional[Dict[str, Any]] = None
        if not opts.get("skip_static", False):
            try:
                from loguru import logger as _loguru_logger
                _loguru_logger.disable("androguard")
                from androguard.core.apk import APK

                def _static_stage() -> Dict[str, Any]:
                    apk_obj = APK(apk_path)
                    trackers_res = self.tracker_detector.detect_from_apk(apk_obj)
                    network_res = self.network_detector.analyze_apk(apk_obj)
                    security_res = self.security_analyzer.analyze_apk(apk_obj)
                    reachability_res = self.reachability_analyzer.analyze_apk(apk_obj)
                    return {
                        "trackers": trackers_res,
                        "network": network_res,
                        "security": security_res,
                        "reachability": reachability_res,
                    }

                static_result = run_with_timeout(
                    _static_stage,
                    timeout_seconds=settings.static_analysis_timeout_seconds,
                )
            except Exception as e:
                logger.warning(f"Advanced static bytecode analysis failed: {e}")
                static_result = {
                    "trackers": {"tracker_count": 0, "has_trackers": False, "detected_trackers": []},
                    "network": {"total_urls": 0, "insecure_http_count": 0, "findings": []},
                    "security": {"findings": []},
                    "reachability": {"has_leakage_path": False, "findings": []},
                    "error": str(e),
                }

        # Stage 7: Multi-Signal Risk Score Fusion (Fusion Engine)
        fusion_result = self.fusion_engine.fuse(
            context_result=context_result,
            manifest_data=manifest_data,
            threat_data=threat_result,
            ml_data=ml_result,
            static_data=static_result,
        )

        logger.info(
            f"Analysis complete for {manifest_data.get('package_name')}: "
            f"Score={fusion_result.get('score')}/100, Verdict={fusion_result.get('verdict')}"
        )

        analysis_dict = {
            "file_path": os.path.abspath(apk_path),
            "category": target_category,
            "category_detection": detection_res.to_dict(),
            "threat": threat_result,
            "manifest": manifest_data,
            "context": context_result,
            "ml": ml_result,
            "static_analysis": static_result,
            "fusion": fusion_result,
        }

        # Stage 8: Persistent Audit History Logging
        if not opts.get("skip_history", False):
            try:
                rec_id = self.history_manager.save_analysis(analysis_dict)
                analysis_dict["history_id"] = rec_id
            except Exception as e:
                logger.warning(f"Could not record analysis in history database: {e}")
                analysis_dict["history_id"] = None

        return analysis_dict

    def export_markdown_report(
        self,
        analysis_result: Dict[str, Any],
        output_path: Optional[str] = None,
    ) -> str:
        """Generate and write a publication-grade Markdown audit report."""
        return generate_markdown_report(analysis_result, output_path=output_path)

    def export_json_report(
        self,
        analysis_result: Dict[str, Any],
        output_path: Optional[str] = None,
    ) -> str:
        """Export analysis report dictionary to a JSON file."""
        return export_json_report(analysis_result, output_path=output_path)

    def get_history(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve recent scan audit history summaries."""
        return self.history_manager.get_history(limit=limit, offset=offset)

    def compare_scans(self, id1: int, id2: int) -> Dict[str, Any]:
        """Perform a comparative differential audit between two historical scans."""
        return self.history_manager.compare_analyses(id1, id2)



# Singleton pipeline instance for shared in-process usage
_global_pipeline: Optional[PrivacyAnalysisPipeline] = None


def get_default_pipeline() -> PrivacyAnalysisPipeline:
    """Retrieve or initialize the global shared PrivacyAnalysisPipeline."""
    global _global_pipeline
    if _global_pipeline is None:
        _global_pipeline = PrivacyAnalysisPipeline()
    return _global_pipeline


def analyze_apk(
    apk_path: str,
    category: Optional[str] = None,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Single unified entrypoint for analyzing an APK.

    Used by CLI, Tkinter GUI, and future Web/API services.

    Args:
        apk_path: Path to the .apk file on disk.
        category: Functional category of the app. If None, default/auto is applied.
        options: Optional analysis flags and overrides.

    Returns:
        Structured analysis report dictionary.
    """
    pipeline = get_default_pipeline()
    return pipeline.analyze(apk_path=apk_path, category=category, options=options)


def run_synthetic_demo(scenario: str, category: Optional[str] = None) -> Dict[str, Any]:
    """Simulate analysis on synthetic permission footprints for presentation demos."""
    scenarios: Dict[str, Dict[str, Any]] = {
        "benign_calculator": {
            "app_name": "Simple Calculator FOSS",
            "package_name": "org.foss.simplecalculator",
            "category": "Calculator",
            "permissions": ["android.permission.VIBRATE"],
            "target_sdk": 34,
            "min_sdk": 26,
            "exported": {"total_exported": 1, "unprotected_exported": 0},
            "threat_status": "VERIFIED_BENIGN",
            "threat_reputation": "Trusted Open-Source FOSS",
            "sha256": "7c5443c22d6d62c67dfe80df33ea9161ff0fa440f92590bcb45d7008b57613ed",
            "static": {
                "trackers": {"tracker_count": 0, "has_trackers": False, "detected_trackers": [], "risk_score": 0.0},
                "network": {"total_urls": 1, "insecure_http_count": 0, "findings": [], "network_risk_score": 0.0},
                "security": {"findings": [], "security_risk_score": 0.0, "bytecode_security": {"has_dcl": False}},
                "reachability": {"has_leakage_path": False, "leakage_paths_count": 0, "findings": [], "leak_risk_score": 0.0},
            },
        },
        "malicious_flashlight": {
            "app_name": "Super Bright LED Flashlight",
            "package_name": "com.flashlight.bright.led",
            "category": "Flashlight",
            "permissions": [
                "android.permission.CAMERA",
                "android.permission.FLASHLIGHT",
                "android.permission.WAKE_LOCK",
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_EXTERNAL_STORAGE",
            ],
            "target_sdk": 29,
            "min_sdk": 21,
            "exported": {"total_exported": 3, "unprotected_exported": 2},
            "threat_status": "MALICIOUS",
            "threat_reputation": "Flagged Adware / Data Exfiltration Signature",
            "sha256": "b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01",
            "static": {
                "trackers": {
                    "tracker_count": 4,
                    "has_trackers": True,
                    "detected_trackers": [
                        {"name": "Google AdMob", "category": "Advertising"},
                        {"name": "InMobi", "category": "Advertising"},
                        {"name": "Flurry", "category": "Analytics"},
                        {"name": "Unity3D Ads", "category": "Advertising"},
                    ],
                    "risk_score": 35.0,
                },
                "network": {
                    "total_urls": 8,
                    "insecure_http_count": 3,
                    "raw_public_ips": ["198.51.100.42"],
                    "findings": [
                        "Identified 3 cleartext HTTP endpoint(s), exposing user traffic to MitM interception.",
                        "Hardcoded public IP addresses detected (198.51.100.42), bypassing domain name verification.",
                    ],
                    "network_risk_score": 45.0,
                },
                "security": {
                    "findings": ["Dynamic Code Loading (DCL) detected (dalvik/system/DexClassLoader). May execute uninspected external payloads."],
                    "security_risk_score": 40.0,
                    "bytecode_security": {"has_dcl": True},
                },
                "reachability": {
                    "has_leakage_path": True,
                    "leakage_paths_count": 2,
                    "findings": [
                        "Identified 2 potential data exfiltration path(s) bridging sensitive sources to network egress sinks.",
                        "Direct intra-procedural leakage detected: same method queries sensitive device data and transmits via network.",
                    ],
                    "leak_risk_score": 75.0,
                },
            },
        },
        "benign_navigation": {
            "app_name": "OpenSource Map Guide",
            "package_name": "org.osm.navigator",
            "category": "Navigation",
            "permissions": [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.WAKE_LOCK",
            ],
            "target_sdk": 34,
            "min_sdk": 28,
            "exported": {"total_exported": 1, "unprotected_exported": 0},
            "threat_status": "UNKNOWN",
            "threat_reputation": "Clean / Not In Database",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "static": {
                "trackers": {"tracker_count": 0, "has_trackers": False, "detected_trackers": [], "risk_score": 0.0},
                "network": {"total_urls": 3, "insecure_http_count": 0, "findings": [], "network_risk_score": 0.0},
                "security": {"findings": [], "security_risk_score": 0.0, "bytecode_security": {"has_dcl": False}},
                "reachability": {"has_leakage_path": False, "leakage_paths_count": 0, "findings": [], "leak_risk_score": 0.0},
            },
        },
    }

    selected = scenarios.get(scenario, scenarios["malicious_flashlight"])
    chosen_cat = category or selected["category"]

    mock_manifest = {
        "file_path": f"synthetic://demo/{scenario}.apk",
        "file_size_bytes": 4500000,
        "package_name": selected["package_name"],
        "app_name": selected["app_name"],
        "target_sdk_version": selected["target_sdk"],
        "min_sdk_version": selected["min_sdk"],
        "version_name": "1.0.0-demo",
        "version_code": "1",
        "declared_permissions": selected["permissions"],
        "custom_permissions": [],
        "total_permissions_count": len(selected["permissions"]),
        "components": {
            "activities_count": 2,
            "services_count": 1,
            "receivers_count": 1,
            "providers_count": 0,
            "exported": selected["exported"],
        },
    }

    pipeline = get_default_pipeline()
    context_result = pipeline.context_engine.evaluate_permissions(
        requested_permissions=selected["permissions"],
        category=chosen_cat,
        exported_components_info=selected["exported"],
    )

    vt_stats = None
    if selected["threat_status"] == "MALICIOUS":
        vt_stats = {
            "malicious": 48,
            "suspicious": 2,
            "undetected": 15,
            "harmless": 0,
            "total_engines": 65,
            "suggested_threat_label": "Trojan.AndroidOS.Joker",
            "popular_category": "TollFraud / Adware",
            "permalink": f"https://www.virustotal.com/gui/file/{selected['sha256']}",
        }
    elif selected["threat_status"] == "VERIFIED_BENIGN":
        vt_stats = {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 68,
            "harmless": 2,
            "total_engines": 70,
            "suggested_threat_label": "Clean",
            "popular_category": "",
            "permalink": f"https://www.virustotal.com/gui/file/{selected['sha256']}",
        }

    threat_result = {
        "file_path": mock_manifest["file_path"],
        "hashes": {"sha256": selected["sha256"], "sha1": "N/A", "md5": "N/A"},
        "status": selected["threat_status"],
        "is_flagged": selected["threat_status"] == "MALICIOUS",
        "is_verified_benign": selected["threat_status"] == "VERIFIED_BENIGN",
        "reputation": selected["threat_reputation"],
        "source": "VIRUSTOTAL_API" if vt_stats else "LOCAL_DATABASE",
        "vt_stats": vt_stats,
        "threat_details": (
            {
                "family": "Joker (Bread)",
                "threat_type": "Billing Fraud / Toll Adware",
                "severity": "High",
                "positives": 48,
                "total_engines": 65,
            }
            if selected["threat_status"] == "MALICIOUS"
            else None
        ),
        "benign_details": None,
    }


    ml_result = pipeline.ml_pipeline.predict_risk(selected["permissions"])

    mock_static = selected.get("static", {})

    fusion_result = pipeline.fusion_engine.fuse(
        context_result=context_result,
        manifest_data=mock_manifest,
        threat_data=threat_result,
        ml_data=ml_result,
        static_data=mock_static,
    )

    return {
        "manifest": mock_manifest,
        "context": context_result,
        "fusion": fusion_result,
        "threat": threat_result,
        "ml": ml_result,
        "static_analysis": mock_static,
    }

