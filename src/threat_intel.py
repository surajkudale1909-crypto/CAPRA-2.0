# ==============================================================================
# File: src/threat_intel.py
# Owner: Suraj (Threat Intelligence & Network Security)
# Description: Threat Intelligence engine with VirusTotal v3 REST API integration,
#              local persistent caching, rate-limit backoff, offline signature fallback,
#              and cryptographic hash calculations.
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Dict, Optional, Tuple
import urllib.error
import urllib.request

from src.config import DATA_DIR, settings

logger = logging.getLogger("CAPRA.ThreatIntel")

DEFAULT_INTEL_DB_PATH = DATA_DIR / "known_malware_hashes.json"
DEFAULT_CACHE_PATH = DATA_DIR / "vt_cache.json"
VT_API_BASE_URL = "https://www.virustotal.com/api/v3/files/"


class ThreatIntelError(Exception):
    """Base exception for threat intelligence operations."""


def compute_file_hashes(file_path: str, chunk_size: int = 65536) -> Dict[str, str]:
    """Compute SHA-256, SHA-1, and MD5 hashes in streaming chunks.

    Args:
        file_path: Path to the target file.
        chunk_size: Size of byte chunks read into memory (default 64KB).

    Returns:
        Dictionary containing 'sha256', 'sha1', and 'md5' hexadecimal strings.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found for hashing: {file_path}")

    h_sha256 = hashlib.sha256()
    h_sha1 = hashlib.sha1()
    h_md5 = hashlib.md5()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h_sha256.update(chunk)
            h_sha1.update(chunk)
            h_md5.update(chunk)

    return {
        "sha256": h_sha256.hexdigest().lower(),
        "sha1": h_sha1.hexdigest().lower(),
        "md5": h_md5.hexdigest().lower(),
    }


class ThreatIntelEngine:
    """Reputation evaluation engine checking APK hashes against VirusTotal v3

    and a local threat intelligence database with persistent disk caching.
    """

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        api_key: Optional[str] = None,
        cache_path: Optional[str | Path] = None,
        timeout: float = 5.0,
    ):
        """Initialize ThreatIntelEngine with database, API key, and cache paths."""
        self.db_path = Path(db_path or DEFAULT_INTEL_DB_PATH)
        self.api_key = api_key if api_key is not None else settings.virustotal_api_key
        self.cache_path = Path(cache_path or DEFAULT_CACHE_PATH)
        self.timeout = timeout

        self.db: Dict[str, Any] = self._load_database()
        self.malware_signatures: Dict[str, Any] = self.db.get("malware_signatures", {})
        self.benign_signatures: Dict[str, Any] = self.db.get("verified_benign_signatures", {})

        self.cache: Dict[str, Any] = self._load_cache()

    def _load_database(self) -> Dict[str, Any]:
        """Load JSON hash database."""
        if not self.db_path.exists():
            logger.warning("Threat intel database not found at %s; using empty database.", self.db_path)
            return {"malware_signatures": {}, "verified_benign_signatures": {}}

        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error("Failed to parse threat intel database at %s: %s", self.db_path, e)
            return {"malware_signatures": {}, "verified_benign_signatures": {}}

    def _load_cache(self) -> Dict[str, Any]:
        """Load persistent VirusTotal response cache from disk."""
        if not self.cache_path.exists() or self.cache_path.stat().st_size == 0:
            return {}

        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception as e:
            logger.warning("Failed to read VirusTotal cache at %s: %s", self.cache_path, e)
            return {}


    def _save_cache(self) -> None:
        """Flush in-memory VirusTotal response cache to disk."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save VirusTotal cache to %s: %s", self.cache_path, e)

    def _fetch_from_virustotal(self, sha256: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Query VirusTotal v3 Files API for a given SHA-256 hash.

        Returns:
            Tuple of (parsed_json_or_None, status_string).
        """
        if not self.api_key:
            return None, "NO_API_KEY"

        url = f"{VT_API_BASE_URL}{sha256}"
        headers = {
            "x-apikey": self.api_key.strip(),
            "Accept": "application/json",
            "User-Agent": "CAPRA-ThreatIntel/2.0 (VIT Pune)",
        }

        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    return data, "OK"
                return None, f"HTTP_{response.status}"
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, "NOT_FOUND"
            elif e.code == 429:
                logger.warning("VirusTotal API quota or rate limit exceeded (HTTP 429).")
                return None, "RATE_LIMIT"
            elif e.code in (401, 403):
                logger.warning("VirusTotal API authentication rejected (HTTP %d). Check API key.", e.code)
                return None, "AUTH_ERROR"
            else:
                logger.warning("VirusTotal API returned HTTP %d: %s", e.code, e.reason)
                return None, f"HTTP_{e.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.info("VirusTotal network lookup failed (%s). Falling back offline.", e)
            return None, "NETWORK_ERROR"
        except Exception as e:
            logger.warning("Unexpected error during VirusTotal API call: %s", e)
            return None, "UNKNOWN_ERROR"

    def _parse_vt_attributes(self, vt_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key metrics from VirusTotal v3 JSON attributes."""
        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless

        # Popular threat classification label
        pop_class = attrs.get("popular_threat_classification", {})
        suggested_label = pop_class.get("suggested_threat_label", "")
        popular_category = ""
        cat_list = pop_class.get("popular_threat_category", [])
        if cat_list and isinstance(cat_list, list):
            popular_category = cat_list[0].get("value", "")

        names = attrs.get("names", [])
        sample_name = names[0] if names else "Android Package"

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": harmless,
            "total_engines": total,
            "suggested_threat_label": suggested_label,
            "popular_category": popular_category,
            "sample_name": sample_name,
            "permalink": f"https://www.virustotal.com/gui/file/{attrs.get('sha256', '')}",
        }

    def lookup_hash(self, sha256: str, apk_path: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate reputation for a SHA-256 hash across cache, VirusTotal API,

        and local signature database.
        """
        sha256_lower = sha256.strip().lower()

        # 1. Check local threat signatures first for known malware family match
        if sha256_lower in self.malware_signatures:
            match = self.malware_signatures[sha256_lower]
            return {
                "file_path": os.path.abspath(apk_path) if apk_path else None,
                "hashes": {"sha256": sha256_lower},
                "status": "MALICIOUS",
                "is_flagged": True,
                "is_verified_benign": False,
                "reputation": f"Known Malware Signature ({match.get('family', 'Malware')})",
                "source": "LOCAL_DATABASE",
                "vt_stats": None,
                "threat_details": {
                    "family": match.get("family", "Unknown Malware"),
                    "threat_type": match.get("threat_type", "Malware"),
                    "severity": match.get("severity", "Critical"),
                    "aliases": match.get("aliases", []),
                    "description": match.get("description", ""),
                    "positives": None,
                    "total_engines": None,
                },
                "benign_details": None,
                "recommendation": f"CRITICAL HAZARD: Matched known threat family '{match.get('family')}'. Immediately delete and block from device.",
            }

        # 2. Check local verified benign whitelist
        if sha256_lower in self.benign_signatures:
            benign_match = self.benign_signatures[sha256_lower]
            return {
                "file_path": os.path.abspath(apk_path) if apk_path else None,
                "hashes": {"sha256": sha256_lower},
                "status": "VERIFIED_BENIGN",
                "is_flagged": False,
                "is_verified_benign": True,
                "reputation": f"Verified Benign Baseline ({benign_match.get('app_name', 'FOSS')})",
                "source": "LOCAL_DATABASE",
                "vt_stats": None,
                "threat_details": None,
                "benign_details": benign_match,
                "recommendation": "Signature matched verified open-source/trusted baseline.",
            }

        # 3. Check persistent VirusTotal cache
        cached_entry = self.cache.get(sha256_lower)
        vt_raw = None
        source = "LOCAL_DATABASE"

        if cached_entry:
            vt_raw = cached_entry.get("response")
            source = "VIRUSTOTAL_CACHE"
            logger.debug("VirusTotal cache hit for hash %s", sha256_lower)
        elif self.api_key:
            # 4. Query live VirusTotal v3 API
            vt_raw, vt_status = self._fetch_from_virustotal(sha256_lower)
            if vt_raw:
                source = "VIRUSTOTAL_API"
                self.cache[sha256_lower] = {
                    "cached_at": datetime.now(timezone.utc).isoformat(),
                    "response": vt_raw,
                }
                self._save_cache()
            else:
                source = f"OFFLINE_FALLBACK ({vt_status})"

        # 5. Evaluate VirusTotal response if available
        if vt_raw and "data" in vt_raw:
            vt_metrics = self._parse_vt_attributes(vt_raw)
            malicious = vt_metrics["malicious"]
            total = vt_metrics["total_engines"]
            suggested_label = vt_metrics["suggested_threat_label"] or "Adware/Malware"

            if malicious >= 3:
                return {
                    "file_path": os.path.abspath(apk_path) if apk_path else None,
                    "hashes": {"sha256": sha256_lower},
                    "status": "MALICIOUS",
                    "is_flagged": True,
                    "is_verified_benign": False,
                    "reputation": f"Malicious ({malicious}/{total} AV engines flagged)",
                    "source": source,
                    "vt_stats": vt_metrics,
                    "threat_details": {
                        "family": suggested_label,
                        "threat_type": vt_metrics["popular_category"] or "Malware",
                        "severity": "Critical" if malicious >= 10 else "High",
                        "aliases": [],
                        "description": f"VirusTotal detection score: {malicious}/{total} security vendors flagged this file.",
                        "positives": malicious,
                        "total_engines": total,
                    },
                    "benign_details": None,
                    "recommendation": f"CRITICAL HAZARD: {malicious} antivirus vendors flag this APK as malicious ({suggested_label}). Quarantine immediately.",
                }
            elif malicious == 0 and total >= 20:
                return {
                    "file_path": os.path.abspath(apk_path) if apk_path else None,
                    "hashes": {"sha256": sha256_lower},
                    "status": "VERIFIED_BENIGN",
                    "is_flagged": False,
                    "is_verified_benign": True,
                    "reputation": f"Clean (0/{total} AV engines flagged)",
                    "source": source,
                    "vt_stats": vt_metrics,
                    "threat_details": None,
                    "benign_details": {"av_scans": total, "clean": True},
                    "recommendation": f"VirusTotal analysis confirms clean file hash across {total} security engines.",
                }
            elif malicious > 0:
                return {
                    "file_path": os.path.abspath(apk_path) if apk_path else None,
                    "hashes": {"sha256": sha256_lower},
                    "status": "SUSPICIOUS",
                    "is_flagged": False,
                    "is_verified_benign": False,
                    "reputation": f"Low Detection ({malicious}/{total} AV engines flagged)",
                    "source": source,
                    "vt_stats": vt_metrics,
                    "threat_details": {
                        "family": suggested_label,
                        "threat_type": "Suspicious / Unclassified",
                        "severity": "Medium",
                        "positives": malicious,
                        "total_engines": total,
                    },
                    "benign_details": None,
                    "recommendation": f"Notice: {malicious} engine(s) flagged this sample. Examine permissions and network reachability closely.",
                }

        # 6. Unknown hash (not in local signatures and clean/not found in VT)
        return {
            "file_path": os.path.abspath(apk_path) if apk_path else None,
            "hashes": {"sha256": sha256_lower},
            "status": "UNKNOWN",
            "is_flagged": False,
            "is_verified_benign": False,
            "reputation": "Unknown Hash (Not in Local Threat DB)",
            "source": source,
            "vt_stats": None,
            "threat_details": None,
            "benign_details": None,
            "recommendation": "No signature match found in threat database. Rely on Context Heuristics, ML risk, and Static Bytecode analysis.",
        }

    def lookup_apk(self, apk_path: str) -> Dict[str, Any]:
        """Compute cryptographic hashes and check reputation in VirusTotal

        and the local threat intelligence base.
        """
        hashes = compute_file_hashes(apk_path)
        sha256 = hashes["sha256"]

        result = self.lookup_hash(sha256, apk_path=apk_path)
        result["hashes"] = hashes
        result["file_path"] = os.path.abspath(apk_path)
        return result

    def get_database_stats(self) -> Dict[str, Any]:
        """Return counts of signatures and cached entries indexed in threat intel engine."""
        return {
            "malware_signatures_count": len(self.malware_signatures),
            "benign_signatures_count": len(self.benign_signatures),
            "cached_virustotal_lookups": len(self.cache),
            "total_local_signatures": len(self.malware_signatures) + len(self.benign_signatures),
            "vt_api_configured": bool(self.api_key),
        }
