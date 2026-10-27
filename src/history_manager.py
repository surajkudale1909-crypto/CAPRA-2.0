"""Audit History Management Module for CAPRA v2.

Suraj's Module (Threat Intel & Audit Persistence) & Group 8 Integration.
Manages an embedded SQLite database (`data/history.db`) recording historical
APK privacy analyses, metadata snapshots, risk score trajectories, and
enabling scan-to-scan comparative differential audits.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.config import settings

logger = logging.getLogger(__name__)


class HistoryManager:
    """Manages persistent SQLite storage of APK privacy scan audits."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize database connection and ensure schema existence."""
        self.db_path = Path(db_path or settings.history_db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextlib.contextmanager
    def _get_connection(self):
        """Create a connection with row factory configured and guarantee closure."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Create the analyses table and required indices if not present."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    apk_path TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    app_name TEXT,
                    version_name TEXT,
                    version_code TEXT,
                    category TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    threat_status TEXT,
                    ml_score REAL,
                    tracker_count INTEGER DEFAULT 0,
                    sha256 TEXT,
                    report_json TEXT NOT NULL
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_pkg ON analyses(package_name)")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_analyses_time ON analyses(timestamp DESC)"
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_sha ON analyses(sha256)")
            conn.commit()

    def save_analysis(self, analysis_result: Dict[str, Any]) -> int:
        """Save a completed analysis report to the history database.

        Args:
            analysis_result: Structured analysis dictionary from pipeline.

        Returns:
            The primary key ID of the newly inserted record.
        """
        manifest = analysis_result.get("manifest", {})
        fusion = analysis_result.get("fusion", {})
        threat = analysis_result.get("threat", {})
        ml = analysis_result.get("ml", {})
        static_analysis = analysis_result.get("static_analysis", {})

        tracker_count = 0
        if static_analysis and isinstance(static_analysis, dict):
            trackers_info = static_analysis.get("trackers", {})
            if isinstance(trackers_info, dict):
                tracker_count = trackers_info.get("tracker_count", 0)

        sha256_hash = ""
        if threat and isinstance(threat, dict):
            sha256_hash = threat.get("hashes", {}).get("sha256", "")

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        apk_path = str(analysis_result.get("file_path", manifest.get("file_path", "unknown")))
        pkg_name = str(manifest.get("package_name") or "unknown.package")
        app_name = str(manifest.get("app_name") or "")
        ver_name = str(manifest.get("version_name") or "")
        ver_code = str(manifest.get("version_code") or "")
        category = str(analysis_result.get("category", "General"))
        score = int(fusion.get("score", 0))
        verdict = str(fusion.get("verdict", "UNKNOWN"))
        threat_status = str(threat.get("status", "UNKNOWN")) if threat else "UNKNOWN"
        ml_score = float(ml.get("risk_percentage", 0.0)) if ml else 0.0

        # Serialize complete report to JSON string
        try:
            report_str = json.dumps(analysis_result)
        except (TypeError, ValueError) as e:
            logger.warning(f"Could not cleanly serialize report_json, using fallback: {e}")
            report_str = json.dumps(
                {"error": f"Serialization error: {e}", "score": score, "verdict": verdict}
            )

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO analyses (
                    timestamp, apk_path, package_name, app_name, version_name,
                    version_code, category, score, verdict, threat_status,
                    ml_score, tracker_count, sha256, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    apk_path,
                    pkg_name,
                    app_name,
                    ver_name,
                    ver_code,
                    category,
                    score,
                    verdict,
                    threat_status,
                    ml_score,
                    tracker_count,
                    sha256_hash,
                    report_str,
                ),
            )
            conn.commit()
            record_id = cursor.lastrowid or 0

        logger.info(f"Saved analysis record #{record_id} for {pkg_name} (Score: {score})")
        return record_id

    def get_analysis(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single analysis record by its database primary key.

        Args:
            analysis_id: Integer primary key.

        Returns:
            Dictionary record with parsed `report_json`, or None if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
            row = cursor.fetchone()
            if not row:
                return None

            data = dict(row)
            try:
                data["report"] = json.loads(data["report_json"])
            except Exception:
                data["report"] = {}
            return data

    def get_history(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve recent scan records in reverse chronological order.

        Args:
            limit: Maximum number of rows to return.
            offset: Pagination offset.

        Returns:
            List of summary records (without the heavy report_json field).
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, apk_path, package_name, app_name,
                       version_name, version_code, category, score, verdict,
                       threat_status, ml_score, tracker_count, sha256
                FROM analyses
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def search_by_package(self, package_name: str) -> List[Dict[str, Any]]:
        """Find historical analyses for a given package name.

        Args:
            package_name: Package name or substring.

        Returns:
            List of matching records ordered from latest to earliest.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, apk_path, package_name, app_name,
                       version_name, version_code, category, score, verdict,
                       threat_status, ml_score, tracker_count, sha256
                FROM analyses
                WHERE package_name LIKE ?
                ORDER BY id DESC
                """,
                (f"%{package_name}%",),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def delete_analysis(self, analysis_id: int) -> bool:
        """Delete an analysis record by its ID.

        Args:
            analysis_id: Target ID.

        Returns:
            True if a record was deleted, False otherwise.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
            conn.commit()
            return cursor.rowcount > 0

    def clear_history(self) -> int:
        """Purge all scan records from the database.

        Returns:
            Count of rows deleted.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM analyses")
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    def compare_analyses(self, id1: int, id2: int) -> Dict[str, Any]:
        """Perform a detailed comparative diff between two analysis records.

        Calculates score drift, permission changes, new trackers, and verdict shift.
        Typically id1 represents an earlier build and id2 represents a newer build.

        Args:
            id1: Baseline / older analysis ID.
            id2: Comparison / newer analysis ID.

        Returns:
            Comparative differential dictionary.
        """
        rec1 = self.get_analysis(id1)
        rec2 = self.get_analysis(id2)

        if not rec1:
            raise ValueError(f"Analysis record #{id1} does not exist.")
        if not rec2:
            raise ValueError(f"Analysis record #{id2} does not exist.")

        rep1 = rec1.get("report", {})
        rep2 = rec2.get("report", {})

        manifest1 = rep1.get("manifest", {})
        manifest2 = rep2.get("manifest", {})

        perms1 = set(manifest1.get("declared_permissions", []))
        perms2 = set(manifest2.get("declared_permissions", []))

        added_perms = sorted(list(perms2 - perms1))
        removed_perms = sorted(list(perms1 - perms2))
        unchanged_perms = sorted(list(perms1 & perms2))

        # Trackers diff
        def _get_tracker_names(rep: Dict[str, Any]) -> set[str]:
            static_sec = rep.get("static_analysis", {})
            if isinstance(static_sec, dict):
                trk = static_sec.get("trackers", {})
                if isinstance(trk, dict):
                    return {
                        t.get("name") for t in trk.get("detected_trackers", []) if t.get("name")
                    }
            return set()

        trackers1 = _get_tracker_names(rep1)
        trackers2 = _get_tracker_names(rep2)
        added_trackers = sorted(list(trackers2 - trackers1))
        removed_trackers = sorted(list(trackers1 - trackers2))

        # Score calculations
        score1 = rec1["score"]
        score2 = rec2["score"]
        score_delta = score2 - score1

        ml1 = rec1.get("ml_score", 0.0)
        ml2 = rec2.get("ml_score", 0.0)
        ml_delta = round(ml2 - ml1, 2)

        verdict1 = rec1["verdict"]
        verdict2 = rec2["verdict"]

        # Trajectory classification
        if score_delta > 5:
            trajectory = "REGRESSION"
            trajectory_summary = (
                f"Privacy risk increased by +{score_delta} points ({verdict1} -> {verdict2})"
            )
        elif score_delta < -5:
            trajectory = "IMPROVEMENT"
            trajectory_summary = (
                f"Privacy risk decreased by {abs(score_delta)} points ({verdict1} -> {verdict2})"
            )
        else:
            trajectory = "STABLE"
            trajectory_summary = f"Privacy risk posture is stable ({verdict1} -> {verdict2})"

        return {
            "record_1": {
                "id": rec1["id"],
                "timestamp": rec1["timestamp"],
                "package_name": rec1["package_name"],
                "version_name": rec1["version_name"],
                "score": score1,
                "verdict": verdict1,
                "threat_status": rec1["threat_status"],
                "tracker_count": rec1["tracker_count"],
            },
            "record_2": {
                "id": rec2["id"],
                "timestamp": rec2["timestamp"],
                "package_name": rec2["package_name"],
                "version_name": rec2["version_name"],
                "score": score2,
                "verdict": verdict2,
                "threat_status": rec2["threat_status"],
                "tracker_count": rec2["tracker_count"],
            },
            "comparison": {
                "score_delta": score_delta,
                "ml_delta": ml_delta,
                "verdict_shift": f"{verdict1} -> {verdict2}",
                "trajectory": trajectory,
                "summary": trajectory_summary,
                "permissions_added": added_perms,
                "permissions_removed": removed_perms,
                "permissions_common_count": len(unchanged_perms),
                "trackers_added": added_trackers,
                "trackers_removed": removed_trackers,
            },
        }
