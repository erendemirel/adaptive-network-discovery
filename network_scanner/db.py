from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class ScanStore:
    """SQLite-backed session log and optional result cache (target + action fingerprint)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ts REAL NOT NULL,
                    phase TEXT,
                    action TEXT,
                    decision_json TEXT,
                    result_json TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );
                CREATE TABLE IF NOT EXISTS result_cache (
                    key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    stored REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
                CREATE TABLE IF NOT EXISTS checkpoints (
                    session_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated REAL NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );
                """
            )

    def new_session(self, session_id: str, target: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO sessions (id, target, created) VALUES (?,?,?)",
                (session_id, target, time.time()),
            )

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT id, target, created FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        if not row:
            return None
        return {"id": row["id"], "target": row["target"], "created": row["created"]}

    def save_checkpoint(self, session_id: str, payload: dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO checkpoints (session_id, payload_json, updated)
                   VALUES (?,?,?)""",
                (session_id, json.dumps(payload), time.time()),
            )

    def load_checkpoint(self, session_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT payload_json FROM checkpoints WHERE session_id = ?", (session_id,)
            ).fetchone()
        if not row:
            return None
        return json.loads(row["payload_json"])

    def append_event(
        self,
        session_id: str,
        phase: str | None,
        action: str | None,
        decision: dict[str, Any] | None,
        result: dict[str, Any] | None,
    ) -> None:
        with self._conn() as c:
            c.execute(
                """INSERT INTO events (session_id, ts, phase, action, decision_json, result_json)
                   VALUES (?,?,?,?,?,?)""",
                (
                    session_id,
                    time.time(),
                    phase,
                    action,
                    json.dumps(decision) if decision else None,
                    json.dumps(result) if result else None,
                ),
            )

    def cache_get(self, key: str, max_age_s: float | None = None) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT payload_json, stored FROM result_cache WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        if max_age_s is not None and time.time() - row["stored"] > max_age_s:
            return None
        return json.loads(row["payload_json"])

    def cache_set(self, key: str, payload: dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO result_cache (key, payload_json, stored)
                   VALUES (?,?,?)""",
                (key, json.dumps(payload), time.time()),
            )
