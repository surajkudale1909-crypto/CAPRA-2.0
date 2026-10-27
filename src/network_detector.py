# ==============================================================================
# File: src/network_detector.py
# Owner: Suraj (Threat Intel & Network Exposure)
# Description: Static network footprint extractor. Scans DEX string pools for
#              hardcoded URLs, plaintext HTTP endpoints, and raw public IP addresses.
# ==============================================================================

import ipaddress
import logging
import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

logger = logging.getLogger("CAPRA.NetworkDetector")

# Regex patterns for URL and IP extraction
URL_REGEX = re.compile(
    r'(https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s"\'<>{}|\^~`\[\]]*)?)', re.IGNORECASE
)
IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Common development / local / schema namespaces to filter out false positives
IGNORED_DOMAINS = {
    "schemas.android.com",
    "android.com",
    "www.w3.org",
    "schemas.xmlsoap.org",
    "apache.org",
    "github.com",
    "schema.org",
    "goo.gl",
    "play.google.com",
}

SUSPICIOUS_TLDS = {".top", ".xyz", ".onion", ".cc", ".tk", ".ru", ".buzz"}
DYNAMIC_DNS_DOMAINS = {"ngrok.io", "duckdns.org", "no-ip.com", "ddns.net", "serveo.net"}


class NetworkDetector:
    """Extracts and analyzes hardcoded URLs, network endpoints, and raw IP addresses

    from DEX string pools.
    """

    def __init__(self):
        pass

    def _is_public_ip(self, ip_str: str) -> bool:
        """Checks if an IPv4 address string is a valid non-local/non-private LAN IP (not loopback/RFC1918/link-local)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version != 4:
                return False
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                return False
            # Check standard RFC 1918 private subnets
            for net in [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            ]:
                if ip in net:
                    return False
            return not ip_str.startswith("0.")
        except ValueError:
            return False

    def analyze_strings(self, strings: List[str]) -> Dict[str, Any]:
        """Analyzes a collection of strings extracted from DEX bytecodes or manifest."""
        found_urls: Set[str] = set()
        found_ips: Set[str] = set()

        for s in strings:
            if not s or len(s) < 7:
                continue

            for match in URL_REGEX.findall(s):
                cleaned = match.strip().rstrip(".)\",';")
                found_urls.add(cleaned)

            for ip_match in IP_REGEX.findall(s):
                if self._is_public_ip(ip_match):
                    found_ips.add(ip_match)

        insecure_http: List[str] = []
        suspicious_endpoints: List[str] = []
        parsed_domains: Set[str] = set()

        for url in found_urls:
            try:
                parsed = urlparse(url)
                domain = parsed.hostname or ""
                domain_lower = domain.lower()

                # Filter ignored system schemas
                if any(ignored in domain_lower for ignored in IGNORED_DOMAINS):
                    continue

                if domain_lower:
                    parsed_domains.add(domain_lower)

                if parsed.scheme.lower() == "http":
                    insecure_http.append(url)

                if any(domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    suspicious_endpoints.append(url)
                elif any(dyn in domain_lower for dyn in DYNAMIC_DNS_DOMAINS):
                    suspicious_endpoints.append(url)
            except Exception:
                continue

        # Score calculation
        # Plaintext HTTP incurs penalty
        # Raw public IPs incur higher penalty (often C2 or non-standard infrastructure)
        # Suspicious TLDs / dynamic DNS add risk
        risk_score = 0.0
        findings = []

        if insecure_http:
            count = len(insecure_http)
            penalty = min(30.0, count * 5.0)
            risk_score += penalty
            findings.append(
                f"Identified {count} cleartext HTTP endpoint(s), exposing user traffic to MitM interception."
            )

        if found_ips:
            count = len(found_ips)
            penalty = min(40.0, count * 15.0)
            risk_score += penalty
            findings.append(
                f"Hardcoded public IP addresses detected ({', '.join(sorted(list(found_ips))[:3])}), bypassing domain name verification."
            )

        if suspicious_endpoints:
            risk_score += min(30.0, len(suspicious_endpoints) * 10.0)
            findings.append(
                f"Identified {len(suspicious_endpoints)} suspicious external domain/TLD references."
            )

        risk_score = min(100.0, risk_score)

        return {
            "total_urls": len(found_urls),
            "insecure_http_count": len(insecure_http),
            "insecure_http_urls": sorted(insecure_http)[:10],  # Sample top 10
            "raw_public_ips": sorted(list(found_ips)),
            "suspicious_endpoints": sorted(suspicious_endpoints),
            "unique_domains": sorted(list(parsed_domains)),
            "network_risk_score": round(risk_score, 1),
            "findings": findings,
        }

    def analyze_apk(self, apk_obj: Any) -> Dict[str, Any]:
        """Extracts all strings from all DEX files of an Androguard APK and analyzes them."""
        try:
            from androguard.core.dex import DEX

            extracted_strings = []
            dex_files = apk_obj.get_all_dex()
            for dex_bytes in dex_files:
                d = DEX(dex_bytes)
                for s in d.get_strings():
                    extracted_strings.append(s)
            return self.analyze_strings(extracted_strings)
        except Exception as e:
            logger.warning("Failed to extract DEX strings for network analysis: %s", e)
            return {
                "total_urls": 0,
                "insecure_http_count": 0,
                "insecure_http_urls": [],
                "raw_public_ips": [],
                "suspicious_endpoints": [],
                "unique_domains": [],
                "network_risk_score": 0.0,
                "findings": [],
                "error": str(e),
            }
