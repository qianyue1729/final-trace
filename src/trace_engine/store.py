"""调查会话持久化 — SQLite（WAL），进程内线程安全。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL,            -- queued | running | completed | error
    alert_json  TEXT NOT NULL,
    scenario_id TEXT,
    report_json TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inv_created ON investigations(created_at DESC);
"""


class InvestigationStore:
    def __init__(self, db_path: str | Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def create(self, alert: dict[str, Any], scenario_id: Optional[str]) -> str:
        inv_id = f"inv-{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO investigations "
                "(id, status, alert_json, scenario_id, created_at, updated_at) "
                "VALUES (?, 'queued', ?, ?, ?, ?)",
                (inv_id, json.dumps(alert, ensure_ascii=False), scenario_id, now, now),
            )
            self._conn.commit()
        return inv_id

    def set_status(self, inv_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE investigations SET status=?, updated_at=? WHERE id=?",
                (status, time.time(), inv_id),
            )
            self._conn.commit()

    def set_report(self, inv_id: str, report: dict[str, Any]) -> None:
        status = "completed" if report.get("status") == "completed" else "error"
        with self._lock:
            self._conn.execute(
                "UPDATE investigations SET status=?, report_json=?, updated_at=? "
                "WHERE id=?",
                (status, json.dumps(report, ensure_ascii=False, default=str),
                 time.time(), inv_id),
            )
            self._conn.commit()

    def get(self, inv_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, status, alert_json, scenario_id, report_json, "
                "created_at, updated_at FROM investigations WHERE id=?",
                (inv_id,),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, status, alert_json, scenario_id, report_json, "
                "created_at, updated_at FROM investigations "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for row in rows:
            d = self._row_to_dict(row)
            d.pop("report", None)   # 列表页不带全量报告
            out.append(d)
        return out

    def purge_older_than(self, days: int) -> int:
        cutoff = time.time() - days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM investigations WHERE created_at < ?", (cutoff,),
            )
            self._conn.commit()
        return cur.rowcount

    @staticmethod
    def _row_to_dict(row) -> dict[str, Any]:
        return {
            "id": row[0],
            "status": row[1],
            "alert": json.loads(row[2]),
            "scenario_id": row[3],
            "report": json.loads(row[4]) if row[4] else None,
            "created_at": row[5],
            "updated_at": row[6],
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
