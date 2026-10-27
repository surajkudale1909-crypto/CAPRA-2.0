# ==============================================================================
# File: src/security_analyzer.py
# Owner: Suraj (Threat Intel & Static Security Analysis)
# Description: Static APK security checks: certificate validation, Dynamic Code
#              Loading (DCL), reflection APIs, native code (.so), and obfuscation.
# ==============================================================================

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CAPRA.SecurityAnalyzer")

DCL_CLASSES = {
    "dalvik/system/DexClassLoader",
    "dalvik/system/PathClassLoader",
    "dalvik/system/InMemoryDexClassLoader",
    "dalvik/system/DelegateLastClassLoader",
}

REFLECTION_PATTERNS = [
    "Ljava/lang/reflect/Method;",
    "Ljava/lang/reflect/Field;",
    "getDeclaredMethod",
    "getMethod",
    "Class.forName",
]

# Precise hardcoded-credential signatures (deliberately low false-positive).
SECRET_PATTERNS = [
    (
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        30.0,
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        25.0,
    ),
    (
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}\b"),
        25.0,
    ),
    (
        "Embedded Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
        35.0,
    ),
    (
        "Hardcoded Credential Assignment",
        re.compile(
            r"(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|client[_-]?secret)"
            r"\s*[=:]\s*[\"'][A-Za-z0-9_\-/+=]{16,}[\"']"
        ),
        15.0,
    ),
]


def redact_secret(sample: str) -> str:
    """Return a safely redacted preview of a detected secret (never log full values)."""
    if len(sample) <= 10:
        return sample[:2] + "…" if sample else ""
    return f"{sample[:6]}…{sample[-2:]} (len={len(sample)})"


class SecurityAnalyzer:
    """Performs static security analysis on Android APKs:

    - Signing certificate validation (debug, self-signed, expired, weak hash)
    - Dynamic Code Loading (DCL) detection
    - Reflection API usage
    - Native code (.so) presence
    - Obfuscation heuristics (ProGuard / R8 / short identifiers)
    """

    def __init__(self):
        pass

    def detect_hardcoded_secrets(self, strings: List[str]) -> Dict[str, Any]:
        """Scan DEX string pool for embedded credentials and API keys.

        Returns redacted samples only — full secret values never leave this method.
        """
        findings: List[str] = []
        detections: List[Dict[str, Any]] = []
        score = 0.0

        for label, pattern, weight in SECRET_PATTERNS:
            hits = []
            for s in strings:
                m = pattern.search(s)
                if m:
                    hits.append(m.group(0))
            if not hits:
                continue
            unique_hits = sorted(set(hits))
            detections.append(
                {
                    "type": label,
                    "occurrences": len(hits),
                    "samples": [redact_secret(h) for h in unique_hits[:3]],
                }
            )
            score += weight
            findings.append(
                f"Hardcoded {label} embedded in the bytecode string pool "
                f"({len(hits)} occurrence(s)). Extractable secrets enable credential "
                "theft, quota abuse, or backend impersonation."
            )

        return {
            "secrets_detected": detections,
            "secrets_count": sum(d["occurrences"] for d in detections),
            "secret_risk_score": round(min(100.0, score), 1),
            "findings": findings,
        }

    def analyze_certificate(self, apk_obj: Any) -> Dict[str, Any]:
        """Inspects APK X.509 certificate(s) for security vulnerabilities."""
        cert_info = {
            "has_certificate": False,
            "is_debug_cert": False,
            "is_self_signed": False,
            "is_expired": False,
            "signature_algo": "Unknown",
            "is_weak_algorithm": False,
            "issuer": "Unknown",
            "subject": "Unknown",
            "findings": [],
            "cert_risk_score": 0.0,
        }

        try:
            certs = list(apk_obj.get_certificates())
            if not certs:
                cert_info["findings"].append("No signing certificates found or APK is unsigned.")
                cert_info["cert_risk_score"] = 40.0
                return cert_info

            cert = certs[0]
            cert_info["has_certificate"] = True

            # Extract subject / issuer
            subject_str = str(cert.subject)
            issuer_str = str(cert.issuer)
            cert_info["subject"] = subject_str
            cert_info["issuer"] = issuer_str

            # Check self-signed
            is_self_signed = getattr(cert, "self_signed", False) or (subject_str == issuer_str)
            cert_info["is_self_signed"] = bool(is_self_signed)

            # Check debug cert
            sub_upper = subject_str.upper()
            if "ANDROID DEBUG" in sub_upper or "CN=DEBUG" in sub_upper:
                cert_info["is_debug_cert"] = True
                cert_info["findings"].append(
                    "APK signed with an Android Debug key. Insecure for production distribution."
                )

            # Check algorithm
            sig_algo = getattr(cert, "signature_algo", "Unknown")
            cert_info["signature_algo"] = sig_algo
            sig_upper = str(sig_algo).upper()
            if "MD5" in sig_upper or "SHA1" in sig_upper:
                cert_info["is_weak_algorithm"] = True
                cert_info["findings"].append(
                    f"Weak certificate signature algorithm detected ({sig_algo}). Vulnerable to collision attacks."
                )

            # Check expiration
            not_after = getattr(cert, "not_valid_after", None)
            if not_after:
                # Normalize timezone
                now = datetime.now(timezone.utc)
                if hasattr(not_after, "tzinfo") and not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                if not_after < now:
                    cert_info["is_expired"] = True
                    cert_info["findings"].append(
                        f"Signing certificate expired on {not_after.strftime('%Y-%m-%d')}."
                    )

            # Compute cert penalty
            penalty = 0.0
            if cert_info["is_debug_cert"]:
                penalty += 35.0
            if cert_info["is_weak_algorithm"]:
                penalty += 25.0
            if cert_info["is_expired"]:
                penalty += 20.0
            if cert_info["is_self_signed"] and not cert_info["is_debug_cert"]:
                # Most Android apps are self-signed by design, but note it
                pass

            cert_info["cert_risk_score"] = min(100.0, penalty)
            return cert_info
        except Exception as e:
            logger.warning("Error inspecting APK certificate: %s", e)
            cert_info["error"] = str(e)
            return cert_info

    def analyze_bytecode_features(
        self, class_names: List[str], strings: List[str], files_list: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Analyzes bytecode artifacts for DCL, reflection, native libraries, and obfuscation."""
        # 1. Native binaries (.so files)
        native_libs = []
        if files_list:
            for f in files_list:
                if f.startswith("lib/") and f.endswith(".so"):
                    native_libs.append(f)

        # 2. Dynamic Code Loading (DCL)
        dcl_detected = []
        norm_classes = [c.strip().lstrip("L").rstrip(";").replace(".", "/") for c in class_names]
        norm_classes_set = set(norm_classes)

        for dcl in DCL_CLASSES:
            if dcl in norm_classes_set:
                dcl_detected.append(dcl)
            else:
                for s in strings:
                    if dcl.replace("/", ".") in s:
                        dcl_detected.append(dcl)
                        break

        # 3. Reflection usage
        reflection_count = 0
        for s in strings:
            for pattern in REFLECTION_PATTERNS:
                if pattern in s:
                    reflection_count += 1
                    break

        # 4. Obfuscation heuristics
        # Count classes where the class name itself is short (<= 2 chars) e.g., 'a', 'b', 'aa'
        short_named_classes = 0
        total_classes = len(class_names)
        for c in class_names:
            norm_c = c.strip().lstrip("L").rstrip(";").replace(".", "/")
            simple_name = norm_c.split("/")[-1]
            if simple_name.startswith("$"):
                simple_name = simple_name[1:]
            if len(simple_name) <= 2 and simple_name.isalpha():
                short_named_classes += 1

        obfuscation_ratio = (
            round((short_named_classes / total_classes), 3) if total_classes > 10 else 0.0
        )

        is_obfuscated = obfuscation_ratio > 0.20

        # Findings & Security Score
        findings = []
        score = 0.0

        if dcl_detected:
            score += 40.0
            findings.append(
                f"Dynamic Code Loading (DCL) detected ({', '.join(set(dcl_detected))}). May execute uninspected external payloads."
            )

        if reflection_count > 15:
            score += 20.0
            findings.append(
                f"Heavy reflection API usage ({reflection_count} references), potentially concealing hidden method invocations."
            )
        elif reflection_count > 0:
            score += 5.0

        if native_libs:
            score += 15.0
            findings.append(
                f"Bundles {len(native_libs)} native .so binary libraries, executing code outside Dalvik/ART runtime."
            )

        if is_obfuscated:
            findings.append(
                f"High identifier minification detected ({round(obfuscation_ratio * 100, 1)}% short classes), indicative of ProGuard/R8 or packer obfuscation."
            )

        # 5. Hardcoded secrets / credentials in the string pool
        secrets_res = self.detect_hardcoded_secrets(strings)
        if secrets_res["secrets_detected"]:
            score += secrets_res["secret_risk_score"]
            findings.extend(secrets_res["findings"])

        score = min(100.0, score)

        return {
            "has_native_code": len(native_libs) > 0,
            "native_libraries_count": len(native_libs),
            "native_libraries_sample": sorted(native_libs)[:5],
            "dcl_detected": sorted(list(set(dcl_detected))),
            "has_dcl": len(dcl_detected) > 0,
            "reflection_references": reflection_count,
            "is_obfuscated": is_obfuscated,
            "obfuscation_ratio": obfuscation_ratio,
            "secrets_detected": secrets_res["secrets_detected"],
            "secrets_count": secrets_res["secrets_count"],
            "security_risk_score": round(score, 1),
            "findings": findings,
        }

    def analyze_apk(self, apk_obj: Any) -> Dict[str, Any]:
        """Comprehensive static security scan on an Androguard APK instance."""
        cert_res = self.analyze_certificate(apk_obj)

        try:
            from androguard.core.dex import DEX

            classes = []
            strings = []
            for dex_bytes in apk_obj.get_all_dex():
                d = DEX(dex_bytes)
                for c in d.get_classes():
                    classes.append(c.get_name())
                for s in d.get_strings():
                    strings.append(s)

            files_list = apk_obj.get_files()
            bytecode_res = self.analyze_bytecode_features(classes, strings, files_list)
        except Exception as e:
            logger.warning("Failed bytecode security inspection: %s", e)
            bytecode_res = self.analyze_bytecode_features([], [], [])
            bytecode_res["error"] = str(e)

        combined_findings = cert_res.get("findings", []) + bytecode_res.get("findings", [])
        combined_score = round(
            min(
                100.0,
                cert_res.get("cert_risk_score", 0.0) * 0.4
                + bytecode_res.get("security_risk_score", 0.0) * 0.6,
            ),
            1,
        )

        return {
            "certificate": cert_res,
            "bytecode_security": bytecode_res,
            "secrets_detected": bytecode_res.get("secrets_detected", []),
            "secrets_count": bytecode_res.get("secrets_count", 0),
            "security_risk_score": combined_score,
            "findings": combined_findings,
        }
