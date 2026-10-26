# ==============================================================================
# File: src/tracker_detector.py
# Owner: Omraj (Context Engine & Tracker Detection)
# Description: Detects embedded third-party ad networks, telemetry trackers, and
#              profiling libraries by scanning DEX class signatures against
#              an Exodus-style tracker signature database.
# ==============================================================================

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from src.config import DATA_DIR

logger = logging.getLogger("CAPRA.TrackerDetector")

DEFAULT_TRACKERS_FILE = DATA_DIR / "trackers.json"


class TrackerDetector:
    """Detects embedded tracking and ad SDKs inside Android DEX bytecode.

    Compares class package names and descriptors against known tracking
    signatures (Exodus Privacy taxonomy).
    """

    def __init__(self, signatures_path: Optional[Path] = None):
        self.signatures_path = signatures_path or DEFAULT_TRACKERS_FILE
        self.trackers_db: List[Dict[str, str]] = []
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Loads signature database from JSON file."""
        if not self.signatures_path.exists():
            logger.warning(
                "Tracker signatures file not found at %s. Using fallback rules.",
                self.signatures_path,
            )
            self.trackers_db = []
            return

        try:
            with open(self.signatures_path, encoding="utf-8") as f:
                data = json.load(f)
                self.trackers_db = data.get("trackers", [])
                logger.debug("Loaded %d tracker signatures.", len(self.trackers_db))
        except Exception as e:
            logger.error("Failed to parse tracker signatures at %s: %s", self.signatures_path, e)
            self.trackers_db = []

    def detect_from_classes(self, class_names: List[str]) -> Dict[str, Any]:
        """Scans a list of class names or Dalvik type descriptors (e.g., 'Lcom/google/ads/...')

        for tracker matches.
        """
        normalized_classes: Set[str] = set()
        for c in class_names:
            norm = c.strip().lstrip("L").rstrip(";").replace("/", ".")
            normalized_classes.add(norm)

        matched_trackers: List[Dict[str, str]] = []
        categories_found: Set[str] = set()

        for tracker in self.trackers_db:
            sig = tracker.get("code_signature", "")
            if not sig:
                continue

            for c in normalized_classes:
                if c.startswith(sig):
                    matched_trackers.append(
                        {
                            "name": tracker.get("name", "Unknown"),
                            "category": tracker.get("category", "General"),
                            "signature": sig,
                            "website": tracker.get("website", ""),
                            "sample_class": c,
                        }
                    )
                    categories_found.add(tracker.get("category", "General"))
                    break

        count = len(matched_trackers)
        if count == 0:
            risk_level = "None"
            risk_score = 0.0
        elif count <= 2:
            risk_level = "Low"
            risk_score = 15.0
        elif count <= 5:
            risk_level = "Medium"
            risk_score = 35.0
        else:
            risk_level = "High"
            risk_score = 55.0

        return {
            "tracker_count": count,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "categories": sorted(list(categories_found)),
            "detected_trackers": matched_trackers,
            "has_trackers": count > 0,
        }

    def detect_from_apk(self, apk_obj: Any) -> Dict[str, Any]:
        """Extracts all classes from DEX files in an Androguard APK instance and scans them."""
        try:
            from androguard.core.dex import DEX

            classes = []
            dex_files = apk_obj.get_all_dex()
            for dex_bytes in dex_files:
                d = DEX(dex_bytes)
                for cls in d.get_classes():
                    classes.append(cls.get_name())
            return self.detect_from_classes(classes)
        except Exception as e:
            logger.warning("Failed to extract DEX classes from APK for tracker detection: %s", e)
            return {
                "tracker_count": 0,
                "risk_level": "None",
                "risk_score": 0.0,
                "categories": [],
                "detected_trackers": [],
                "has_trackers": False,
                "error": str(e),
            }
