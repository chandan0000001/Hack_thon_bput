"""Response store: stdlib sqlite3 (WAL) record of every gateway attempt.

Every ship attempt — success, HTTP error, or transport failure — is appended
here. The API key never passes through this module: callers supply the
request payload only, and tests assert no key material ever lands in the db.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS gateway_calls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    action        TEXT NOT NULL,
    request_json  TEXT NOT NULL,
    status        TEXT NOT NULL,
    response_json TEXT,
    latency_ms    INTEGER,
    error         TEXT
)
"""

# Status value used for attempts that never got an HTTP response.
TRANSPORT_ERROR = "transport_error"


class ResponseStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def append(
        self,
        action: str,
        request: Any,
        status: str,
        response: Any = None,
        latency_ms: int | None = None,
        error: str | None = None,
    ) -> int:
        """Record one attempt; returns the row id."""
        cur = self._conn.execute(
            "INSERT INTO gateway_calls (ts, action, request_json, status, response_json, latency_ms, error) "
            "VALUES (datetime('now'), ?, ?, ?, ?, ?, ?)",
            (
                action,
                _dump(request),
                str(status),
                _dump(response) if response is not None else None,
                latency_ms,
                error,
            ),
        )
        return int(cur.lastrowid)

    def query(
        self,
        limit: int = 20,
        action: str | None = None,
        min_status: int | None = None,
    ) -> list[dict[str, Any]]:
        """Most recent calls first; optional action filter and numeric
        minimum HTTP status (transport_error rows have no numeric status
        and are excluded when min_status is given)."""
        clauses: list[str] = []
        params: list[Any] = []
        if action:
            clauses.append("action = ?")
            params.append(action)
        if min_status is not None:
            clauses.append("status GLOB '[0-9]*' AND CAST(status AS INTEGER) >= ?")
            params.append(min_status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM gateway_calls {where} ORDER BY id DESC LIMIT ?", params
        ).fetchall()
        return [dict(r) for r in rows]

    def counts(self) -> dict[str, int]:
        """status -> attempt count, plus 'total'."""
        rows = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM gateway_calls GROUP BY status"
        ).fetchall()
        out = {r["status"]: r["n"] for r in rows}
        out["total"] = sum(out.values())
        return out


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
