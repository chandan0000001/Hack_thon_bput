"""Best-effort Supabase Realtime broadcast for org_events changes.

The realtime container in a split dev environment (app DB on a plain
Postgres, realtime bound to the Supabase stack DB) cannot deliver
postgres_changes for local writes, so the gateway also posts each
org_event change to Realtime's HTTP broadcast API on the same channel
topic the frontend subscribes to (`org-counters-{project_id}`). In hosted
mode where realtime reads the app DB directly, postgres_changes fires as
well — the frontend dedupes by event id, so double delivery is harmless.

Payload carries only counter-relevant fields (event_type, severity,
verdict) — never raw_data. Topic ids are project uuids; this is a
counter signal, not an authorization boundary (RLS governs the
postgres_changes path).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger("cyberguard.org_event_broadcaster")

BROADCAST_EVENT = "org_event_changed"


def _topic(project_id: str) -> str:
    return f"org-counters-{project_id}"


def _payload(event: Any, kind: str, previous_verdict: Optional[str]) -> dict[str, Any]:
    created_at = getattr(event, "created_at", None)
    return {
        "kind": kind,
        "event_id": str(event.id),
        "event_type": event.event_type,
        "severity": event.severity,
        "verdict": event.verdict,
        "previous_verdict": previous_verdict,
        "project_id": str(event.project_id),
        "organization_id": str(event.organization_id),
        "created_at": created_at.isoformat() if created_at is not None else None,
    }


async def broadcast_org_event(
    event: Any,
    kind: str = "insert",
    previous_verdict: Optional[str] = None,
) -> bool:
    """POST the change to Realtime's broadcast endpoint. Never raises and
    never blocks the caller's request path beyond a short timeout."""
    try:
        from app.core.config import get_settings

        settings = get_settings()
        url = (settings.SUPABASE_URL or "").rstrip("/")
        anon_key = settings.SUPABASE_ANON_KEY or ""
        if not url or not anon_key:
            return False

        endpoint = f"{url}/realtime/v1/api/broadcast"
        body = {
            "messages": [
                {
                    "topic": _topic(str(event.project_id)),
                    "event": BROADCAST_EVENT,
                    "payload": _payload(event, kind, previous_verdict),
                }
            ]
        }
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(
                endpoint,
                json=body,
                headers={"apikey": anon_key, "Authorization": f"Bearer {anon_key}"},
            )
        if resp.status_code >= 300:
            logger.warning("broadcast POST failed: %s %s", resp.status_code, resp.text[:200])
            return False
        return True
    except Exception as exc:  # noqa: BLE001 - realtime signaling is best-effort
        logger.debug("org_event broadcast skipped: %s", exc)
        return False
