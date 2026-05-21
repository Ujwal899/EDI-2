from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import SCAN_HISTORY_DB_PATH


class ScanHistoryService:
    def __init__(self, db_path: Path = SCAN_HISTORY_DB_PATH) -> None:
        self.db_path = db_path
        self._initialized = False

    def init_db(self) -> None:
        if self._initialized:
            return

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    input_type TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    sender TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL DEFAULT '',
                    url TEXT NOT NULL DEFAULT '',
                    label TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reasons_json TEXT NOT NULL,
                    user_verdict TEXT NOT NULL DEFAULT '',
                    feedback_note TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_results_created_at ON scan_results(created_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_results_label ON scan_results(label)"
            )
        self._initialized = True

    def record_scan(
        self,
        *,
        source: str,
        input_type: str,
        result: dict[str, Any],
        subject: str = "",
        sender: str = "",
        body: str = "",
        url: str = "",
    ) -> int:
        self.init_db()
        created_at = datetime.now(timezone.utc).isoformat()
        reasons = result.get("reasons", [])
        if not isinstance(reasons, list):
            reasons = [str(reasons)]

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_results (
                    created_at, source, input_type, subject, sender, body, url,
                    label, risk_level, confidence, reasons_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    source,
                    input_type,
                    subject or "",
                    sender or "",
                    body or "",
                    url or "",
                    str(result.get("label", "SAFE")),
                    str(result.get("risk_level", "LOW")),
                    float(result.get("confidence", 0.0)),
                    json.dumps([str(reason) for reason in reasons]),
                ),
            )
            return int(cursor.lastrowid)

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        self.init_db()
        max_results = max(1, min(int(limit), 200))
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT id, created_at, source, input_type, subject, sender, url,
                       label, risk_level, confidence, reasons_json,
                       user_verdict, feedback_note
                FROM scan_results
                ORDER BY id DESC
                LIMIT ?
                """,
                (max_results,),
            ).fetchall()

        return [self._row_to_dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        self.init_db()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT label, COUNT(*) AS count, AVG(confidence) AS avg_confidence
                FROM scan_results
                GROUP BY label
                """
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
            feedback_total = conn.execute(
                "SELECT COUNT(*) FROM scan_results WHERE user_verdict != ''"
            ).fetchone()[0]

        counts = {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0}
        weighted_confidence = 0.0
        for row in rows:
            label = str(row["label"]).upper()
            count = int(row["count"])
            avg_conf = float(row["avg_confidence"] or 0.0)
            if label in counts:
                counts[label] = count
            weighted_confidence += avg_conf * count

        return {
            "total": int(total),
            "safe": counts["SAFE"],
            "suspicious": counts["SUSPICIOUS"],
            "phishing": counts["PHISHING"],
            "avg_confidence": weighted_confidence / total if total else 0.0,
            "feedback_total": int(feedback_total),
        }

    def save_feedback(self, scan_id: int, verdict: str, note: str = "") -> bool:
        self.init_db()
        normalized = verdict.upper().strip()
        if normalized not in {"SAFE", "SUSPICIOUS", "PHISHING"}:
            raise ValueError("verdict must be SAFE, SUSPICIOUS, or PHISHING")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE scan_results
                SET user_verdict = ?, feedback_note = ?
                WHERE id = ?
                """,
                (normalized, note or "", int(scan_id)),
            )
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        try:
            reasons = json.loads(str(row["reasons_json"] or "[]"))
        except json.JSONDecodeError:
            reasons = []

        return {
            "id": int(row["id"]),
            "created_at": str(row["created_at"]),
            "source": str(row["source"]),
            "input_type": str(row["input_type"]),
            "subject": str(row["subject"]),
            "sender": str(row["sender"]),
            "url": str(row["url"]),
            "label": str(row["label"]),
            "risk_level": str(row["risk_level"]),
            "confidence": float(row["confidence"]),
            "reasons": [str(reason) for reason in reasons],
            "user_verdict": str(row["user_verdict"] or ""),
            "feedback_note": str(row["feedback_note"] or ""),
        }


scan_history_service = ScanHistoryService()
