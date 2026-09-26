"""Real-time metrics computed from the response store in SQL (no caching).

All aggregates are over a sliding window (default: last hour). by_severity
parses gateway response_json via SQLite's json_extract; latency percentiles
use ORDER BY + OFFSET (no extension dependencies).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .store import TRANSPORT_ERROR, ResponseStore

DEFAULT_WINDOW_MINUTES = 60


def compute(
    store: ResponseStore,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> dict[str, Any]:
    """Metrics over the last `window_minutes`, straight from the store.
    Holds the store lock for the whole snapshot so aggregates are consistent
    while the traffic generator appends concurrently."""
    with store.lock:
        return _compute_locked(store._conn, window_minutes)


def _compute_locked(conn: sqlite3.Connection, window_minutes: int) -> dict[str, Any]:
    since = f"-{int(window_minutes)} minutes"

    total = conn.execute(
        "SELECT COUNT(*) FROM gateway_calls WHERE ts >= datetime('now', ?)", (since,)
    ).fetchone()[0]

    ok_200 = conn.execute(
        "SELECT COUNT(*) FROM gateway_calls WHERE ts >= datetime('now', ?) "
        "AND status = '200'",
        (since,),
    ).fetchone()[0]

    by_action = {
        r["action"]: r["n"]
        for r in conn.execute(
            "SELECT action, COUNT(*) AS n FROM gateway_calls "
            "WHERE ts >= datetime('now', ?) GROUP BY action",
            (since,),
        ).fetchall()
    }

    by_status: dict[str, int] = {"200": 0, "4xx": 0, "5xx": 0, TRANSPORT_ERROR: 0}
    for r in conn.execute(
        "SELECT status, COUNT(*) AS n FROM gateway_calls "
        "WHERE ts >= datetime('now', ?) GROUP BY status",
        (since,),
    ).fetchall():
        status = r["status"]
        if status == "200":
            by_status["200"] += r["n"]
        elif status == TRANSPORT_ERROR:
            by_status[TRANSPORT_ERROR] += r["n"]
        elif status.isdigit():
            bucket = f"{status[0]}xx"
            by_status[bucket] = by_status.get(bucket, 0) + r["n"]
        else:
            by_status[status] = by_status.get(status, 0) + r["n"]

    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    try:
        for r in conn.execute(
            "SELECT json_extract(response_json, '$.severity') AS sev, COUNT(*) AS n "
            "FROM gateway_calls WHERE ts >= datetime('now', ?) AND status = '200' "
            "GROUP BY sev",
            (since,),
        ).fetchall():
            sev = (r["sev"] or "").strip().lower()
            if sev:
                by_severity[sev] = by_severity.get(sev, 0) + r["n"]
    except sqlite3.OperationalError:
        # JSON1 unavailable: bucket severities in Python
        for (resp_json,) in conn.execute(
            "SELECT response_json FROM gateway_calls "
            "WHERE ts >= datetime('now', ?) AND status = '200' AND response_json IS NOT NULL",
            (since,),
        ).fetchall():
            try:
                import json

                sev = str((json.loads(resp_json) or {}).get("severity", "")).strip().lower()
            except (ValueError, AttributeError):
                continue
            if sev:
                by_severity[sev] = by_severity.get(sev, 0) + 1

    latencies = [
        r[0]
        for r in conn.execute(
            "SELECT latency_ms FROM gateway_calls "
            "WHERE ts >= datetime('now', ?) AND latency_ms IS NOT NULL ORDER BY latency_ms",
            (since,),
        ).fetchall()
    ]
    p50 = _percentile(latencies, 50)
    p95 = _percentile(latencies, 95)

    return {
        "window": f"last_{int(window_minutes)}m",
        "total": total,
        "success_rate": round(ok_200 / total, 4) if total else 0.0,
        "by_action": by_action,
        "by_status": by_status,
        "by_severity": by_severity,
        "latency_ms": {"p50": p50, "p95": p95},
    }


def _percentile(sorted_values: list[int], pct: int) -> float | None:
    """Nearest-rank percentile over an already-sorted list."""
    if not sorted_values:
        return None
    idx = max(0, min(len(sorted_values) - 1, (len(sorted_values) * pct + 99) // 100 - 1))
    return float(sorted_values[idx])
