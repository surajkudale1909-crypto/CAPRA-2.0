# ==============================================================================
# File: src/reachability.py
# Owner: Omraj (Context Engine & Reachability Analysis)
# Description: Static call-graph reachability engine connecting sensitive API
#              sources (location, device ID, contacts) to network egress sinks.
# ==============================================================================

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CAPRA.Reachability")

# Curated Sensitive Permission Sources
SENSITIVE_SOURCES = {
    "Location": [
        ("Landroid/location/LocationManager;", "getLastKnownLocation"),
        ("Landroid/location/LocationManager;", "requestLocationUpdates"),
        ("Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation")
    ],
    "Device Identifier / Telephony": [
        ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
        ("Landroid/telephony/TelephonyManager;", "getImei"),
        ("Landroid/telephony/TelephonyManager;", "getSubscriberId"),
        ("Landroid/telephony/TelephonyManager;", "getSimSerialNumber"),
        ("Landroid/telephony/TelephonyManager;", "getLine1Number")
    ],
    "Contacts & Accounts": [
        ("Landroid/accounts/AccountManager;", "getAccounts"),
        ("Landroid/accounts/AccountManager;", "getAccountsByType"),
        ("Landroid/provider/ContactsContract;", "Contacts")
    ],
    "Microphone & Audio": [
        ("Landroid/media/MediaRecorder;", "start"),
        ("Landroid/media/AudioRecord;", "startRecording")
    ],
    "Camera": [
        ("Landroid/hardware/Camera;", "takePicture"),
        ("Landroid/hardware/camera2/CameraDevice;", "createCaptureSession")
    ],
    "Clipboard": [
        ("Landroid/content/ClipboardManager;", "getPrimaryClip"),
        ("Landroid/content/ClipboardManager;", "getText")
    ]
}

# Curated Network Egress Sinks
NETWORK_SINKS = {
    "HttpURLConnection": ("Ljava/net/HttpURLConnection;", ["connect", "getOutputStream", "getInputStream"]),
    "URL.openConnection": ("Ljava/net/URL;", ["openConnection"]),
    "Raw Socket": ("Ljava/net/Socket;", ["getOutputStream", "connect"]),
    "OkHttp": ("Lokhttp3/OkHttpClient;", ["newCall"]),
    "Apache HttpClient": ("Lorg/apache/http/client/HttpClient;", ["execute"]),
    "WebView Egress": ("Landroid/webkit/WebView;", ["loadUrl", "postUrl"])
}

LIMITATIONS_DISCLAIMER = (
    "Methodology Note: CAPRA static reachability uses intra-class and call-graph xref path traversal "
    "to identify connectivity between sensitive privacy sources and network egress sinks. "
    "Unlike full-scale taint analysis tools (such as FlowDroid or IccTA), it does not perform field-sensitive "
    "points-to alias tracking or solve inter-procedural finite distributive subset (IFDS) systems. "
    "It provides a fast, static-only heuristic of potential exfiltration pathways."
)


class ReachabilityAnalyzer:
    """Analyzes call-graph connectivity from privacy-sensitive sources to network sinks."""

    def __init__(self):
        pass

    def analyze_mock_graph(
        self,
        methods_map: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyzes a synthetic dictionary mapping method names to their sources and sinks invoked.

        Format:
            {
               "com.example.MainActivity.sendData": {
                   "class": "com.example.MainActivity",
                   "sources": ["getLastKnownLocation"],
                   "sinks": ["openConnection"]
               }
            }
        """
        paths = []
        class_sources: Dict[str, Set[str]] = {}
        class_sinks: Dict[str, Set[str]] = {}

        for m_name, info in methods_map.items():
            cls = info.get("class", "UnknownClass")
            sources = info.get("sources", [])
            sinks = info.get("sinks", [])

            if sources:
                class_sources.setdefault(cls, set()).update(sources)
            if sinks:
                class_sinks.setdefault(cls, set()).update(sinks)

            # Direct intra-procedural path (same method calls both source and sink)
            if sources and sinks:
                for src in sources:
                    for snk in sinks:
                        paths.append({
                            "type": "intra-method",
                            "confidence": "High (Direct Call)",
                            "confidence_score": 0.90,
                            "caller_class": cls,
                            "caller_method": m_name,
                            "source": src,
                            "sink": snk,
                            "description": f"Method {m_name} directly invokes sensitive source '{src}' and network sink '{snk}'."
                        })

        # Intra-class paths (same class accesses source in one method and sink in another)
        for cls, srcs in class_sources.items():
            if cls in class_sinks:
                snks = class_sinks[cls]
                # Only add if not already covered as intra-method
                existing_pairs = {(p["source"], p["sink"]) for p in paths if p["caller_class"] == cls}
                for src in srcs:
                    for snk in snks:
                        if (src, snk) not in existing_pairs:
                            paths.append({
                                "type": "intra-class",
                                "confidence": "Medium (Co-located in Class)",
                                "confidence_score": 0.65,
                                "caller_class": cls,
                                "caller_method": f"{cls}.*",
                                "source": src,
                                "sink": snk,
                                "description": f"Class {cls} encapsulates both sensitive source '{src}' and network sink '{snk}'."
                            })

        leak_risk_score = 0.0
        findings = []

        if paths:
            # Score based on highest confidence and number of paths
            max_conf = max(p["confidence_score"] for p in paths)
            count = len(paths)
            leak_risk_score = min(100.0, max_conf * 60.0 + min(40.0, count * 10.0))
            findings.append(f"Identified {count} potential data exfiltration path(s) bridging sensitive sources to network egress sinks.")
            if any(p["type"] == "intra-method" for p in paths):
                findings.append("Direct intra-procedural leakage detected: same method queries sensitive device data and transmits via network.")

        return {
            "has_leakage_path": len(paths) > 0,
            "leakage_paths_count": len(paths),
            "paths": paths,
            "leak_risk_score": round(leak_risk_score, 1),
            "findings": findings,
            "limitations_disclaimer": LIMITATIONS_DISCLAIMER
        }

    def analyze_apk(self, apk_obj: Any, dx: Optional[Any] = None) -> Dict[str, Any]:
        """Performs static call-graph reachability analysis on an Androguard APK.

        If dx (Analysis) is not provided, builds xrefs with loguru disabled for fast processing.
        """
        try:
            from loguru import logger as _loguru_logger
            _loguru_logger.disable("androguard")
        except Exception:
            pass

        try:
            if dx is None:
                from androguard.core.analysis.analysis import Analysis
                from androguard.core.dex import DEX
                dx = Analysis()
                for dex_bytes in apk_obj.get_all_dex():
                    d = DEX(dex_bytes)
                    dx.add(d)
                dx.create_xref()

            # Map method callers
            source_callers: Dict[str, List[Tuple[str, str]]] = {}  # (class, method) -> [source_names]
            sink_callers: Dict[str, List[Tuple[str, str]]] = {}    # (class, method) -> [sink_names]

            # 1. Search sensitive sources
            for category, sources in SENSITIVE_SOURCES.items():
                for cls_name, method_name in sources:
                    found_methods = dx.find_methods(classname=cls_name, methodname=method_name)
                    for m in found_methods:
                        for xref_class, xref_method, _ in m.get_xref_to():
                            caller_c = xref_class.get_vm_class().get_name()
                            caller_m = xref_method.get_name()
                            src_label = f"{category} ({method_name})"
                            source_callers.setdefault((caller_c, caller_m), []).append(src_label)

            # 2. Search network sinks
            for sink_label, (cls_name, method_names) in NETWORK_SINKS.items():
                for m_name in method_names:
                    found_methods = dx.find_methods(classname=cls_name, methodname=m_name)
                    for m in found_methods:
                        for xref_class, xref_method, _ in m.get_xref_to():
                            caller_c = xref_class.get_vm_class().get_name()
                            caller_m = xref_method.get_name()
                            snk_label = f"{sink_label} ({m_name})"
                            sink_callers.setdefault((caller_c, caller_m), []).append(snk_label)

            # Build mock graph representation from discovered xref callers
            methods_map: Dict[str, Dict[str, Any]] = {}
            all_keys = set(source_callers.keys()).union(set(sink_callers.keys()))

            for caller_c, caller_m in all_keys:
                # Filter out standard Android framework internal classes
                if caller_c.startswith("Landroid/") or caller_c.startswith("Landroidx/") or caller_c.startswith("Ljava/"):
                    continue

                full_m = f"{caller_c}->{caller_m}"
                methods_map[full_m] = {
                    "class": caller_c,
                    "sources": source_callers.get((caller_c, caller_m), []),
                    "sinks": sink_callers.get((caller_c, caller_m), [])
                }

            return self.analyze_mock_graph(methods_map)

        except Exception as e:
            logger.warning("Call-graph reachability analysis failed or timed out: %s", e)
            return {
                "has_leakage_path": False,
                "leakage_paths_count": 0,
                "paths": [],
                "leak_risk_score": 0.0,
                "findings": [],
                "limitations_disclaimer": LIMITATIONS_DISCLAIMER,
                "error": str(e)
            }
