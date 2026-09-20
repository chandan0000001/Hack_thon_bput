"""Org-level email notification groups (ORG-4).

Org-level, NOT the per-user ``notification_email`` of Phase 7: an
organization registers MULTIPLE addresses, each belonging to a role group
(admin | analyst | viewer), and each event type declares the MINIMUM role
group that receives it (min_role=admin → only admins; analyst → analysts +
admins; viewer → everyone). Delivery reuses the Phase 7 backend
(``_deliver``: DB-logged by default, best-effort SMTP when configured).

Event taxonomy (defaults seeded per org on first read):
- ``server_down``       — org infrastructure failure (e.g. mail server fetch
  failing while connected)
- ``mail_server_down``  — a mail server connection failed
- ``critical_log``      — critical/high finding on the log plane
- ``impersonation``     — impersonation-type indicators (lookalike domains,
  display-name spoofing) detected by the gateway

Every send is logged to ``org_notification_logs`` with per-recipient
outcomes; a disabled event type is recorded as ``skipped`` only when the
caller explicitly asks for it — by default send_event returns silently.
"""

import html
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import OrgNotificationEmail, OrgNotificationLog, OrgNotificationSetting

logger = logging.getLogger("cyberguard.org_notifications")

EVENT_TYPES = ("server_down", "mail_server_down", "critical_log", "impersonation")

ROLE_HIERARCHY = {"admin": 3, "analyst": 2, "viewer": 1}

DEFAULT_MIN_ROLES: dict[str, str] = {
    "server_down": "analyst",
    "mail_server_down": "analyst",
    "critical_log": "analyst",
    "impersonation": "admin",
}


class OrgNotificationError(Exception):
    pass


async def _ensure_settings(db: AsyncSession, organization_id: str) -> dict[str, OrgNotificationSetting]:
    """Load (seeding defaults for) the org's event-type routing rows."""
    result = await db.execute(
        select(OrgNotificationSetting).where(
            OrgNotificationSetting.organization_id == organization_id
        )
    )
    by_type = {s.event_type: s for s in result.scalars().all()}
    for event_type, min_role in DEFAULT_MIN_ROLES.items():
        if event_type not in by_type:
            setting = OrgNotificationSetting(
                organization_id=organization_id,
                event_type=event_type,
                min_role=min_role,
                is_enabled=True,
            )
            db.add(setting)
            by_type[event_type] = setting
    await db.flush()
    return by_type


async def list_settings(db: AsyncSession, organization_id: str) -> list[OrgNotificationSetting]:
    return list((await _ensure_settings(db, organization_id)).values())


async def send_event(
    db: AsyncSession,
    *,
    organization_id: str,
    event_type: str,
    subject: str,
    body_html: str,
    event_metadata: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Send one org notification to all enabled addresses in role groups at
    or above the event type's min_role. Returns per-recipient outcomes and
    persists an org_notification_logs row (status sent|failed)."""
    if event_type not in EVENT_TYPES:
        raise OrgNotificationError(f"Unknown event type: {event_type}")

    settings = await _ensure_settings(db, organization_id)
    setting = settings.get(event_type)
    if setting is None or not setting.is_enabled:
        return []

    min_level = ROLE_HIERARCHY.get(setting.min_role, 2)
    emails = (
        await db.execute(
            select(OrgNotificationEmail).where(
                OrgNotificationEmail.organization_id == organization_id,
                OrgNotificationEmail.is_enabled == True,  # noqa: E712
            )
        )
    ).scalars().all()

    recipients = [e for e in emails if ROLE_HIERARCHY.get(e.role, 0) >= min_level]
    results: list[dict[str, Any]] = []

    # Import late: delivery belongs to the Phase 7 module (db_log/SMTP).
    from app.services.notification_service import _deliver

    for recipient in recipients:
        try:
            backend, error = await _deliver(recipient.email, subject, body_html)
            results.append({
                "email": recipient.email,
                "role": recipient.role,
                "status": "sent",
                "backend": backend,
                "error_detail": error,
            })
        except Exception as exc:  # noqa: BLE001 - per-recipient isolation
            logger.warning("org notification to %s failed: %s", recipient.email, exc)
            results.append({
                "email": recipient.email,
                "role": recipient.role,
                "status": "failed",
                "backend": "db_log",
                "error_detail": str(exc),
            })

    overall = "sent" if results and all(r["status"] == "sent" for r in results) else (
        "failed" if results else "skipped"
    )
    db.add(OrgNotificationLog(
        organization_id=organization_id,
        event_type=event_type,
        recipients=results,
        subject=subject[:255],
        body_html=body_html,
        event_metadata=event_metadata or {},
        status=overall,
        error_detail=None if overall == "sent" else "; ".join(
            f"{r['email']}: {r['error_detail']}" for r in results if r.get("error_detail")
        ) or None,
    ))
    await db.commit()
    return results


# ---------------------------------------------------------------------------
# Templates (per event type)
# ---------------------------------------------------------------------------

_STYLE = (
    "font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; "
    "border: 1px solid #e4e4e7; border-radius: 8px; padding: 24px;"
)


def _base(title: str, title_color: str, rows: list[tuple[str, str]], footer: str) -> str:
    rows_html = "".join(
        f'<p style="margin:6px 0;"><strong>{html.escape(label)}:</strong> {html.escape(value)}</p>'
        for label, value in rows
    )
    return (
        f'<html><body style="background:#fafafa;padding:16px;">'
        f'<div style="{_STYLE}">'
        f'<h1 style="color:{title_color};margin:0 0 12px;">{html.escape(title)}</h1>'
        f'{rows_html}'
        f'<p style="margin-top:16px;font-size:12px;color:#71717a;">{html.escape(footer)}'
        f' Time: {datetime.now(timezone.utc).isoformat()}</p>'
        f'</div></body></html>'
    )


def server_down_email(server_name: str, error: str) -> tuple[str, str]:
    subject = f"[CRITICAL] Server Down: {server_name}"
    body = _base(
        "Server Down Alert", "#dc2626",
        [("Server", server_name), ("Error", error or "unknown")],
        "Please investigate immediately.",
    )
    return subject, body


def mail_server_down_email(server_name: str, provider: str, error: str) -> tuple[str, str]:
    subject = f"[CRITICAL] Mail Server Connection Failed: {server_name}"
    body = _base(
        "Mail Server Down", "#dc2626",
        [("Mail server", server_name), ("Provider", provider), ("Error", error or "unknown")],
        "Mail scanning for this server is interrupted; reconnect from the Mail Servers page.",
    )
    return subject, body


def critical_log_email(log_summary: str, severity: str, log_type: str = "") -> tuple[str, str]:
    subject = f"[{severity.upper()}] Critical Security Event Detected"
    body = _base(
        "Critical Security Event", "#dc2626",
        [("Severity", severity), ("Log type", log_type), ("Summary", log_summary)],
        "Please review in the organization dashboard.",
    )
    return subject, body


def impersonation_email(indicators: list[dict[str, Any]], sender: str | None) -> tuple[str, str]:
    names = ", ".join(str(i.get("type")) for i in indicators[:5]) or "impersonation"
    subject = f"[WARNING] Impersonation Indicators Detected ({names})"
    body = _base(
        "Impersonation Alert", "#d97706",
        [("Sender", sender or "unknown"), ("Indicator types", names)],
        "Review the verbose scan result in the organization dashboard.",
    )
    return subject, body


IMPERSONATION_INDICATOR_TYPES = {
    "lookalike_domain",
    "display_name_spoof",
    "impersonation",
    "reply_to_mismatch",
    "brand_impersonation",
}


# ---------------------------------------------------------------------------
# ORG-WIRE: pipeline fan-out (critical / phishing verdicts)
# ---------------------------------------------------------------------------

async def fan_out_email_verdict(
    db: AsyncSession,
    *,
    owner_user_id: str,
    email_id: str,
    verdict: str | None,
    severity: str | None,
    classification: str | None = None,
) -> bool:
    """Notify the owner's ORGANIZATION about a critical/phishing pipeline
    verdict (ORG-WIRE D3). Rules:

    - Personal org (or no org): SKIP. The Phase-7 per-user path already
      notifies the owner's ``notification_email``; fanning out to the same
      person's org groups would double the email. Personal-mode rows still
      carry the personal-org stamp — the suppression is purely about not
      re-notifying a single human twice.
    - Non-personal org: send through the existing ``send_event`` registry
      (event_type ``critical_log``, min_role routing applies) and persist an
      ``org_notification_logs`` row.

    Returns True when a fan-out was attempted; never raises — notifications
    must not break the pipeline.
    """
    is_critical = (
        severity == "critical"
        or verdict == "malicious"
        or classification == "phishing"
    )
    if not is_critical:
        return False

    from app.services.org_context import resolve_org_context

    org_id, is_personal = await resolve_org_context(db, owner_user_id)
    if not org_id or is_personal:
        return False

    summary = (
        f"Email verdict {verdict or classification or 'unknown'} "
        f"(severity {severity or 'unknown'}) on a message in a monitored mailbox."
    )
    subject, body = critical_log_email(summary, severity or verdict or "critical", "email_verdict")
    try:
        await send_event(
            db,
            organization_id=org_id,
            event_type="critical_log",
            subject=subject,
            body_html=body,
            event_metadata={
                "source": "pipeline",
                "email_id": email_id,
                "verdict": verdict,
                "severity": severity,
                "classification": classification,
            },
        )
        return True
    except Exception:  # noqa: BLE001 - notifications must not break the pipeline
        logger.exception("org fan-out failed for email %s (org %s)", email_id, org_id)
        return False
