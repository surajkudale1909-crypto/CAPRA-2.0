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
        ("Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation"),
    ],
    "Device Identifier / Telephony": [
        ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
        ("Landroid/telephony/TelephonyManager;", "getImei"),
        ("Landroid/telephony/TelephonyManager;", "getSubscriberId"),
        ("Landroid/telephony/TelephonyManager;", "getSimSerialNumber"),
        ("Landroid/telephony/TelephonyManager;", "getLine1Number"),
    ],
    "Contacts & Accounts": [
        ("Landroid/accounts/AccountManager;", "getAccounts"),
        ("Landroid/accounts/AccountManager;", "getAccountsByType"),
        ("Landroid/provider/ContactsContract;", "Contacts"),
    ],
    "Microphone & Audio": [
        ("Landroid/media/MediaRecorder;", "start"),
        ("Landroid/media/AudioRecord;", "startRecording"),
    ],
    "Camera": [
        ("Landroid/hardware/Camera;", "takePicture"),
        ("Landroid/hardware/camera2/CameraDevice;", "createCaptureSession"),
    ],
    "Clipboard": [
        ("Landroid/content/ClipboardManager;", "getPrimaryClip"),
        ("Landroid/content/ClipboardManager;", "getText"),
    ],
}

# Curated Network Egress Sinks
NETWORK_SINKS = {
    "HttpURLConnection": (
        "Ljava/net/HttpURLConnection;",
        ["connect", "getOutputStream", "getInputStream"],
    ),
    "URL.openConnection": ("Ljava/net/URL;", ["openConnection"]),
    "Raw Socket": ("Ljava/net/Socket;", ["getOutputStream", "connect"]),
    "OkHttp": ("Lokhttp3/OkHttpClient;", ["newCall"]),
    "Apache HttpClient": ("Lorg/apache/http/client/HttpClient;", ["execute"]),
    "WebView Egress": ("Landroid/webkit/WebView;", ["loadUrl", "postUrl"]),
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

    @staticmethod
    def _app_callers(method_analysis: Any) -> List[Tuple[str, str]]:
        """Return (class, method) pairs of app-side methods calling the given API.

        Uses get_xref_from() (incoming edges). get_xref_to() lists *callees* and is
        always empty for framework APIs — using it here silently hides all callers.
        """
        callers: List[Tuple[str, str]] = []
        for xref_class, xref_method, _ in method_analysis.get_xref_from():
            try:
                vm_class = xref_class.get_vm_class()
                caller_c = vm_class.get_name() if vm_class is not None else ""
            except Exception:
                continue
            if caller_c:
                callers.append((caller_c, xref_method.name))
        return callers

    def analyze_mock_graph(
        self,
        methods_map: Dict[str, Dict[str, Any]],
        call_edges: Optional[List[Tuple[str, str]]] = None,
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

        Args:
            methods_map: method key -> {class, sources, sinks}.
            call_edges: optional list of (caller_key, callee_key) call-graph
                edges between method keys, enabling inter-method path detection.
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
                        paths.append(
                            {
                                "type": "intra-method",
                                "confidence": "High (Direct Call)",
                                "confidence_score": 0.90,
                                "caller_class": cls,
                                "caller_method": m_name,
                                "source": src,
                                "sink": snk,
                                "description": f"Method {m_name} directly invokes sensitive source '{src}' and network sink '{snk}'.",
                            }
                        )

        # Intra-class paths (same class accesses source in one method and sink in another)
        for cls, srcs in class_sources.items():
            if cls in class_sinks:
                snks = class_sinks[cls]
                # Only add if not already covered as intra-method
                existing_pairs = {
                    (p["source"], p["sink"]) for p in paths if p["caller_class"] == cls
                }
                for src in srcs:
                    for snk in snks:
                        if (src, snk) not in existing_pairs:
                            paths.append(
                                {
                                    "type": "intra-class",
                                    "confidence": "Medium (Co-located in Class)",
                                    "confidence_score": 0.65,
                                    "caller_class": cls,
                                    "caller_method": f"{cls}.*",
                                    "source": src,
                                    "sink": snk,
                                    "description": f"Class {cls} encapsulates both sensitive source '{src}' and network sink '{snk}'.",
                                }
                            )

        # Inter-method paths: source and sink in different methods connected by
        # an actual call-graph edge (caller invokes the other side).
        if call_edges:
            src_methods = {m for m, i in methods_map.items() if i.get("sources")}
            sink_methods = {m for m, i in methods_map.items() if i.get("sinks")}
            seen_inter = {(p["caller_method"], p["source"], p["sink"]) for p in paths}
            for u, v in call_edges:
                pairs = []
                if u in src_methods and v in sink_methods:
                    pairs.append((u, v, "calls"))
                if v in src_methods and u in sink_methods:
                    pairs.append((v, u, "called by"))
                for src_m, snk_m, rel in pairs:
                    for src_label in methods_map[src_m]["sources"]:
                        for snk_label in methods_map[snk_m]["sinks"]:
                            key = (f"{src_m} -> {snk_m}", src_label, snk_label)
                            if key in seen_inter:
                                continue
                            seen_inter.add(key)
                            if rel == "calls":
                                desc = (
                                    f"Method {src_m} invokes {snk_m}: sensitive source "
                                    f"'{src_label}' can flow across the call graph into "
                                    f"network sink '{snk_label}'."
                                )
                            else:
                                desc = (
                                    f"Method {snk_m} invokes {src_m} to obtain "
                                    f"'{src_label}' and transmits via network sink "
                                    f"'{snk_label}'."
                                )
                            paths.append(
                                {
                                    "type": "inter-method",
                                    "confidence": "Medium (Call-Graph Path)",
                                    "confidence_score": 0.75,
                                    "caller_class": methods_map[src_m]["class"],
                                    "caller_method": f"{src_m} -> {snk_m}",
                                    "source": src_label,
                                    "sink": snk_label,
                                    "description": desc,
                                }
                            )

        # Rank by confidence and bound path explosion on large apps
        paths.sort(key=lambda p: (-p["confidence_score"], p["type"], p["source"], p["sink"]))
        paths = paths[:25]

        leak_risk_score = 0.0
        findings = []

        if paths:
            # Score based on highest confidence and number of paths
            max_conf = max(p["confidence_score"] for p in paths)
            count = len(paths)
            leak_risk_score = min(100.0, max_conf * 60.0 + min(40.0, count * 10.0))
            findings.append(
                f"Identified {count} potential data exfiltration path(s) bridging sensitive sources to network egress sinks."
            )
            if any(p["type"] == "intra-method" for p in paths):
                findings.append(
                    "Direct intra-procedural leakage detected: same method queries sensitive device data and transmits via network."
                )
            if any(p["type"] == "inter-method" for p in paths):
                findings.append(
                    "Call-graph-mediated leakage detected: sensitive data acquisition and network transmission occur in different methods linked by a direct call edge."
                )

        return {
            "has_leakage_path": len(paths) > 0,
            "leakage_paths_count": len(paths),
            "paths": paths,
            "leak_risk_score": round(leak_risk_score, 1),
            "findings": findings,
            "limitations_disclaimer": LIMITATIONS_DISCLAIMER,
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

            # Map method callers.
            # NOTE: xref direction matters — get_xref_from() returns the methods
            # that CALL this API (its callers); get_xref_to() lists callees (always
            # empty for framework APIs). We want the app-side callers.
            source_callers: Dict[
                str, List[Tuple[str, str]]
            ] = {}  # (class, method) -> [source_names]
            sink_callers: Dict[str, List[Tuple[str, str]]] = {}  # (class, method) -> [sink_names]

            # 1. Search sensitive sources
            for category, sources in SENSITIVE_SOURCES.items():
                for cls_name, method_name in sources:
                    found_methods = dx.find_methods(classname=cls_name, methodname=method_name)
                    for m in found_methods:
                        for caller_c, caller_m in self._app_callers(m):
                            src_label = f"{category} ({method_name})"
                            source_callers.setdefault((caller_c, caller_m), []).append(src_label)

            # 2. Search network sinks
            for sink_label, (cls_name, method_names) in NETWORK_SINKS.items():
                for m_name in method_names:
                    found_methods = dx.find_methods(classname=cls_name, methodname=m_name)
                    for m in found_methods:
                        for caller_c, caller_m in self._app_callers(m):
                            snk_label = f"{sink_label} ({m_name})"
                            sink_callers.setdefault((caller_c, caller_m), []).append(snk_label)

            # Build mock graph representation from discovered callers
            methods_map: Dict[str, Dict[str, Any]] = {}
            all_keys = set(source_callers.keys()).union(set(sink_callers.keys()))

            for caller_c, caller_m in all_keys:
                # Filter out standard Android framework internal classes
                if (
                    caller_c.startswith("Landroid/")
                    or caller_c.startswith("Landroidx/")
                    or caller_c.startswith("Ljava/")
                ):
                    continue

                full_m = f"{caller_c}->{caller_m}"
                methods_map[full_m] = {
                    "class": caller_c,
                    "sources": source_callers.get((caller_c, caller_m), []),
                    "sinks": sink_callers.get((caller_c, caller_m), []),
                }

            # 3. Call-graph edges among the involved app methods (inter-method depth).
            #    For each source/sink-calling method, its direct callees and callers
            #    that are also involved become one-hop exfiltration candidates.
            involved_keys = set(methods_map.keys())
            key_by_pair = {pair: f"{pair[0]}->{pair[1]}" for pair in all_keys}
            call_edges: List[Tuple[str, str]] = []
            seen_edges: Set[Tuple[str, str]] = set()

            for caller_c, caller_m in all_keys:
                u_key = key_by_pair[(caller_c, caller_m)]
                if u_key not in involved_keys:
                    continue
                for ma in dx.find_methods(classname=caller_c, methodname=caller_m):
                    # Outgoing: methods this app method calls
                    for xref_class, xref_method, _ in ma.get_xref_to():
                        try:
                            vm_class = xref_class.get_vm_class()
                            callee_c = vm_class.get_name() if vm_class is not None else ""
                        except Exception:
                            continue
                        v_key = key_by_pair.get((callee_c, xref_method.name))
                        if v_key and v_key != u_key and (u_key, v_key) not in seen_edges:
                            seen_edges.add((u_key, v_key))
                            call_edges.append((u_key, v_key))
                    # Incoming: app methods that call this method
                    for caller2_c, caller2_m in self._app_callers(ma):
                        v_key = key_by_pair.get((caller2_c, caller2_m))
                        if v_key and v_key != u_key and (v_key, u_key) not in seen_edges:
                            seen_edges.add((v_key, u_key))
                            call_edges.append((v_key, u_key))

            return self.analyze_mock_graph(methods_map, call_edges=call_edges)

        except Exception as e:
            logger.warning("Call-graph reachability analysis failed or timed out: %s", e)
            return {
                "has_leakage_path": False,
                "leakage_paths_count": 0,
                "paths": [],
                "leak_risk_score": 0.0,
                "findings": [],
                "limitations_disclaimer": LIMITATIONS_DISCLAIMER,
                "error": str(e),
            }
