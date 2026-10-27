"""Configuration and Settings Module for CAPRA v2.

Centralizes file paths, environment variables (API keys), operational thresholds,
and structured logging configuration.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Try loading .env file if python-dotenv is installed or read manually
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    # Minimal fallback parser for .env if python-dotenv is not installed
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.is_file():
        try:
            with open(env_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip("'\""))
        except Exception:
            pass


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = DATA_DIR / "models"
APKS_DIR = DATA_DIR / "apks"
REPORTS_DIR = BASE_DIR / "reports"


def _load_virustotal_api_key() -> Optional[str]:
    """Resolve the VirusTotal key: env var / .env first, then the GUI's
    persisted settings file (~/.capra/gui_settings.json, written by the
    desktop app's Settings dialog)."""
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if key and key.strip():
        return key.strip()
    try:
        import json

        gui_settings = Path.home() / ".capra" / "gui_settings.json"
        if gui_settings.is_file():
            with open(gui_settings, encoding="utf-8") as f:
                data = json.load(f)
            stored = data.get("vt_api_key") if isinstance(data, dict) else None
            if isinstance(stored, str) and stored.strip():
                return stored.strip()
    except Exception:
        pass
    return None


@dataclass
class Settings:
    """Application-wide configuration settings."""

    # Project Information
    PROJECT_NAME: str = "CAPRA"
    VERSION: str = "2.0.0"
    GROUP: str = "VIT Pune CS-AI Group 8"

    # Core Directories
    base_dir: Path = BASE_DIR
    data_dir: Path = DATA_DIR
    models_dir: Path = MODELS_DIR
    apks_dir: Path = APKS_DIR
    reports_dir: Path = REPORTS_DIR

    # Core File Paths
    rules_path: Path = DATA_DIR / "context_rules.json"
    hashes_path: Path = DATA_DIR / "known_malware_hashes.json"
    trackers_path: Path = DATA_DIR / "trackers.json"
    model_path: Path = MODELS_DIR / "permission_model.joblib"
    history_db_path: Path = DATA_DIR / "history.db"
    threat_cache_path: Path = DATA_DIR / "threat_cache.db"

    # API Keys & Threat Intel (Loaded via Environment Variables)
    virustotal_api_key: Optional[str] = field(default_factory=_load_virustotal_api_key)
    malwarebazaar_api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("MALWAREBAZAAR_API_KEY")
    )

    # Risk Fusion Settings
    raw_score_ceiling: int = 160
    log_level: str = field(default_factory=lambda: os.getenv("CAPRA_LOG_LEVEL", "INFO").upper())

    # APK Input Hardening (untrusted-input safety limits, all env-overridable)
    max_apk_size_mb: int = field(
        default_factory=lambda: int(os.getenv("CAPRA_MAX_APK_SIZE_MB", "500"))
    )
    max_zip_entries: int = field(
        default_factory=lambda: int(os.getenv("CAPRA_MAX_ZIP_ENTRIES", "100000"))
    )
    max_uncompressed_mb: int = field(
        default_factory=lambda: int(os.getenv("CAPRA_MAX_UNCOMPRESSED_MB", "4000"))
    )
    max_compression_ratio: float = field(
        default_factory=lambda: float(os.getenv("CAPRA_MAX_COMPRESSION_RATIO", "200"))
    )
    apk_parse_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("CAPRA_APK_PARSE_TIMEOUT", "120"))
    )
    static_analysis_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("CAPRA_STATIC_ANALYSIS_TIMEOUT", "300"))
    )

    def ensure_directories(self) -> None:
        """Create necessary directories if they do not exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.apks_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


# Global singleton instance
settings = Settings()
settings.ensure_directories()


def setup_logging(level: Optional[str] = None) -> logging.Logger:
    """Configure structured logging for CAPRA across console and modules.

    Args:
        level: Optional log level override (DEBUG, INFO, WARNING, ERROR).

    Returns:
        Root CAPRA logger.
    """
    log_level_str = level or settings.log_level
    numeric_level = getattr(logging, log_level_str, logging.INFO)

    logger = logging.getLogger("capra")
    logger.setLevel(numeric_level)

    # Prevent duplicate handlers on re-initialization
    if not logger.handlers:
        # Logs go to stderr so stdout stays clean for machine-readable output (--json)
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d) - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
