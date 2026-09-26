"""Replay: re-ship stored successful gateway calls in a time window.

Reads store rows in [from_ts, to_ts] (only status=200 rows are replayed —
replaying 4xx/transport failures would just recreate errors), re-ships
each via the shipper. Each replay attempt becomes a NEW store row and the
gateway issues a NEW event_id.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .shipper import GatewayShipper
from .store import ResponseStore


class ReplayError(ValueError):
    pass


def normalize_ts(raw: str, boundary: str) -> str:
    """Normalize user ISO input to the store's sqlite UTC ts format
    ('YYYY-MM-DD HH:MM:SS'). Naive input is treated as UTC."""
    if not raw or not raw.strip():
        raise ReplayError(f"replay {boundary} timestamp is required")
    text = raw.strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError as exc:
        raise ReplayError(
            f"replay {boundary} timestamp {raw!r} is not ISO (e.g. 2026-09-26T00:00)"
        ) from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def replay(
    shipper: GatewayShipper,
    store: ResponseStore,
    from_ts: str,
    to_ts: str,
    max_rows: int = 1000,
) -> dict[str, Any]:
    """Re-ship every successful call in the window. Returns replay stats."""
    lo = normalize_ts(from_ts, "from")
    hi = normalize_ts(to_ts, "to")
    if lo > hi:
        raise ReplayError(f"replay from_ts ({lo}) is after to_ts ({hi})")

    rows = store.query_window(lo, hi)
    if len(rows) > max_rows:
        raise ReplayError(
            f"window contains {len(rows)} rows (max {max_rows}); narrow the window"
        )

    replayed = 0
    succeeded = 0
    old_event_ids: list[str] = []
    new_event_ids: list[str] = []
    for row in rows:
        request = _loads(row.get("request_json")) or {}
        action = request.get("action")
        data = request.get("data")
        if not action:
            continue
        response = _loads(row.get("response_json")) or {}
        if response.get("event_id"):
            old_event_ids.append(str(response["event_id"]))
        result = shipper.ship(str(action), data)
        replayed += 1
        if result.ok:
            succeeded += 1
            if isinstance(result.response, dict) and result.response.get("event_id"):
                new_event_ids.append(str(result.response["event_id"]))

    return {
        "window": {"from": lo, "to": hi},
        "replayed": replayed,
        "succeeded": succeeded,
        "success_rate": round(succeeded / replayed, 4) if replayed else 0.0,
        "old_event_ids": old_event_ids,
        "new_event_ids": new_event_ids,
    }


def _loads(raw: Any) -> Any:
    import json

    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def utc_now_store_ts() -> str:
    """Current UTC time in the store's ts format (for 'replay last N s')."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
