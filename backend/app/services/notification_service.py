"""Event email notifications (Phase 7).

When a high-severity security event occurs, an alert email is rendered from a
standard template and delivered to the user's registered
``users.notification_email`` — NEVER to a connected mailbox (privacy/spam
boundary).

Delivery backends:
- ``db_log`` (default): the rendered email is persisted to
  ``cyberguard.notification_logs`` — deterministic, demo-safe, no external
  dependency.
- ``smtp`` (optional, when NOTIFICATION_SMTP_HOST is configured): attempted
  best-effort via stdlib smtplib; ANY failure falls back to DB logging with
  the real error recorded, so a live demo never crashes.
"""

import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import NotificationLog, User

logger = logging.getLogger("cyberguard.notifications")

# Event types that trigger a notification; message-scoped events additionally
# require high/critical severity.
NOTIFY_EVENT_TYPES = {
    "quarantine",
    "sender_block",
    "release",
    "delete",
    "sender_expiry",
    "sender_release",
    # EMAIL-ACTION-MATRIX MEDIUM tier: suspicious mail delivered to the
    # inbox must warn the user regardless of severity band.
    "suspicious_email",
}

_EVENT_TITLES = {
    "quarantine": "Message quarantined",
    "sender_block": "Sender blocked",
    "release": "Message released",
    "delete": "Message deleted",
    "sender_expiry": "Sender block expired",
    "sender_release": "Sender unblocked",
    "suspicious_email": "Suspicious email delivered",
}


def _wants_notification(event_type: str, severity: str | None) -> bool:
    if event_type not in NOTIFY_EVENT_TYPES:
        return False
    if event_type == "suspicious_email":
        return True
    if severity is None or severity in ("high", "critical"):
        return True
    # Non-message lifecycle events (sender_expiry) notify regardless of severity.
    return event_type in ("sender_expiry", "sender_release", "sender_block")


def build_email(event_type: str, *, sender_email: str | None, subject: str | None,
                severity: str | None, operation_detail: str | None) -> tuple[str, str]:
    """Standard alert template -> (subject, body_html)."""
    title = _EVENT_TITLES.get(event_type, event_type.replace("_", " ").title())
    mail_subject = f"CYBERGUARD Alert: {title} - {sender_email or 'unknown sender'}"
    rows = ""
    if severity:
        rows += f"<tr><td>Severity</td><td><b>{severity}</b></td></tr>"
    if subject:
        rows += f"<tr><td>Subject</td><td>{subject}</td></tr>"
    if sender_email:
        rows += f"<tr><td>Sender</td><td>{sender_email}</td></tr>"
    if operation_detail:
        rows += f"<tr><td>Details</td><td>{operation_detail}</td></tr>"
    body_html = f"""\
<html><body style="font-family:sans-serif;color:#111">
  <h2 style="color:#b91c1c">CYBERGUARD Alert: {title}</h2>
  <p>A security event occurred in your CYBERGUARD workspace.</p>
  <table cellpadding="6" style="border-collapse:collapse">
    {rows}
  </table>
  <p style="color:#666;font-size:12px">
    You are receiving this because you registered this address as the
    notification target in CYBERGUARD. Your connected mailbox is never used
    for system notifications. Review details in the CYBERGUARD Security
    History page.
  </p>
</body></html>"""
    return mail_subject, body_html


async def _deliver(recipient: str, mail_subject: str, body_html: str) -> tuple[str, str | None]:
    """Deliver the email. Returns (backend, error_detail).

    SMTP is best-effort; any failure falls back to DB logging."""
    settings = get_settings()
    if not settings.NOTIFICATION_SMTP_HOST:
        return "db_log", None
    try:
        message = EmailMessage()
        message["From"] = formataddr(("CYBERGUARD", settings.NOTIFICATION_FROM_ADDRESS))
        message["To"] = recipient
        message["Subject"] = mail_subject
        message.set_content(body_html, subtype="html")
        with smtplib.SMTP(settings.NOTIFICATION_SMTP_HOST, settings.NOTIFICATION_SMTP_PORT, timeout=10) as server:
            if settings.NOTIFICATION_SMTP_USERNAME:
                server.starttls()
                server.login(settings.NOTIFICATION_SMTP_USERNAME, settings.NOTIFICATION_SMTP_PASSWORD)
            server.send_message(message)
        return "smtp", None
    except Exception as exc:  # noqa: BLE001 - demo must never crash on SMTP
        logger.warning("SMTP delivery failed, falling back to DB log: %s", exc)
        return "db_log", f"SMTP delivery failed ({type(exc).__name__}): {exc}"


async def maybe_notify(
    db: AsyncSession,
    *,
    owner_user_id: str,
    event_type: str,
    severity: str | None = None,
    sender_email: str | None = None,
    subject: str | None = None,
    operation_status: str | None = None,
    operation_detail: str | None = None,
) -> NotificationLog | None:
    """Hook (called from record_event): render + deliver + log, or no-op."""
    if not _wants_notification(event_type, severity):
        return None

    user = (
        await db.execute(select(User).where(User.id == owner_user_id))
    ).scalar_one_or_none()
    recipient = user.notification_email if user else None
    if not recipient:
        # No registered notification address -> no notification. A connected
        # mailbox is NEVER used as a fallback (privacy boundary).
        return None

    mail_subject, body_html = build_email(
        event_type, sender_email=sender_email, subject=subject,
        severity=severity, operation_detail=operation_detail,
    )
    backend, error = await _deliver(recipient, mail_subject, body_html)

    log = NotificationLog(
        owner_user_id=owner_user_id,
        event_type=event_type,
        recipient_email=recipient,
        subject=mail_subject,
        body_html=body_html,
        status="sent" if error is None else "failed",
        error_detail=error,
        backend=backend,
    )
    db.add(log)
    try:
        await db.commit()
    except Exception:  # noqa: BLE001 - notification logging must not break operations
        await db.rollback()
        logger.exception("Failed to persist notification log")
        return None
    return log


async def list_logs(db: AsyncSession, owner_user_id: str, limit: int = 50) -> list[NotificationLog]:
    return list(
        (
            await db.execute(
                select(NotificationLog)
                .where(NotificationLog.owner_user_id == owner_user_id)
                .order_by(NotificationLog.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()
    )


def serialize_log(log: NotificationLog) -> dict:
    return {
        "id": log.id,
        "event_type": log.event_type,
        "recipient_email": log.recipient_email,
        "subject": log.subject,
        "status": log.status,
        "backend": log.backend,
        "error_detail": log.error_detail,
        "created_at": log.created_at.isoformat() if log.created_at else None,
    }
