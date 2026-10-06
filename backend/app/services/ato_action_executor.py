"""ATO-HYBRID-ACTIONS: unified action executor for account-takeover response.

One service executes every ATO response action, whether triggered
AUTOMATICALLY by the detection pipeline or MANUALLY by an analyst — both
paths call the exact same methods, so behaviour and audit records match.

Actions:
  - notify_user           warning email to the flagged account (dev mode:
                          the full email is logged to the console like the
                          invitation service; SMTP delivery intentionally
                          mocked for the demo).
  - restrict_account      account lock flag (mock: recorded in the event
                          ledger + a user-row lookup when one exists).
  - force_password_reset  session/token invalidation (mock: Supabase Auth
                          owns sessions and the demo has no service-role
                          admin key, so it is logged and recorded).

Idempotency: ``Event.raw_data['action_ledger']`` is the single source of
truth — one ledger entry per action with ``done_auto`` / ``done_manual``.
``execute()`` re-checks the ledger under the same write-back (deep-copied
reassignment, per the PortableJSON mutation trap) so an action that already
 ran is never executed twice — no duplicate emails, no double locks.
"""

import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import Event, User

logger = logging.getLogger("cyberguard.ato.actions")

ATO_ACTIONS = ("notify_user", "restrict_account", "force_password_reset")
DONE_STATUSES = ("done_auto", "done_manual")

ACTION_LABELS = {
    "notify_user": "User Notified",
    "restrict_account": "Account Restricted",
    "force_password_reset": "Password Reset Forced",
}

EMAIL_SUBJECT = "Security Alert: Unusual Activity Detected"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _combined_status(ledger: dict[str, Any]) -> str:
    """Coarse status string: restrict_* wins over notify_*, then reset_*."""
    restrict = (ledger.get("restrict_account") or {}).get("status")
    notify = (ledger.get("notify_user") or {}).get("status")
    reset = (ledger.get("force_password_reset") or {}).get("status")
    for status, name in (
        (restrict, "restricted"),
        (notify, "notified"),
        (reset, "reset"),
    ):
        if status in DONE_STATUSES:
            return f"{name}_manual" if status == "done_manual" else f"{name}_auto"
    return "pending"


class AtoActionExecutor:
    """Executes and records one ATO action against an event, idempotently."""

    def __init__(self, db: AsyncSession, event: Event):
        self.db = db
        self.event = event

    # ------------------------------------------------------------------ core
    async def execute(self, action: str, via: str, account_email: str | None = None) -> dict:
        """Run ``action`` (auto|manual) once for this event and persist it."""
        if action not in ATO_ACTIONS:
            raise ValueError(f"Unknown ATO action: {action}")
        if via not in ("auto", "manual"):
            raise ValueError(f"Execution path must be 'auto' or 'manual', got {via!r}")

        raw = deepcopy(self.event.raw_data or {})
        ledger = dict(raw.get("action_ledger") or {})
        existing = ledger.get(action) or {}
        if existing.get("status") in DONE_STATUSES:
            # Idempotency gate: the action was already executed (either path).
            logger.info(
                "ATO action %s on event %s skipped — already %s",
                action,
                self.event.id,
                existing["status"],
            )
            return {
                "executed": False,
                "already_done": True,
                "action": action,
                "status": existing["status"],
                "ledger": ledger,
            }

        account_email = account_email or raw.get("account_id")
        if action == "notify_user":
            details = await self.send_notification_email(
                account_email or "unknown@account", self._event_details(raw)
            )
        elif action == "restrict_account":
            details = await self.restrict_account(account_email)
        else:
            details = await self.force_password_reset(account_email)

        record = {
            "status": "done_auto" if via == "auto" else "done_manual",
            "via": via,
            "executed_at": _now_iso(),
            **details,
        }
        ledger[action] = record
        raw["action_ledger"] = ledger
        raw["action_status"] = _combined_status(ledger)
        if via == "manual":
            raw["manual_action"] = action

        # Deep-copied reassignment — an in-place mutation would be silently
        # skipped by the JSON change detector.
        self.event.raw_data = raw
        await self.db.commit()

        return {
            "executed": True,
            "already_done": False,
            "action": action,
            "status": record["status"],
            "ledger": ledger,
        }

    def _event_details(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": str(self.event.id),
            "account_id": raw.get("account_id"),
            "risk_score": (raw.get("enforcement") or {}).get("risk_score"),
            "tier": (raw.get("enforcement") or {}).get("tier"),
        }

    # -------------------------------------------------------------- actions
    async def send_notification_email(self, user_email: str, event_details: dict[str, Any]) -> dict:
        """Build and deliver the warning email (SMTP mocked for the demo).

        The full rendered email is always logged to the backend console
        (same dev-mode visibility as invitation emails); the ledger record
        carries subject/body so the UI and DB show exactly what was sent.
        """
        subject = EMAIL_SUBJECT
        body = (
            f"We detected unusual login activity on your account "
            f"({user_email}). Automated analysis rated this activity at "
            f"{event_details.get('risk_score') or 'elevated'} risk "
            f"(tier: {event_details.get('tier') or 'medium'}; event "
            f"{event_details.get('event_id')}). If this was not you, reset "
            f"your password immediately and contact your security team."
        )

        # Demo guarantee: the SMTP send is mocked — the email is logged and
        # recorded, never delivered. (Real delivery would mirror the
        # invitation service: smtplib in asyncio.to_thread when SMTP_HOST
        # is configured.)
        if get_settings().SMTP_HOST:
            logger.warning(
                "ATO email SMTP delivery is mocked for the demo — NOT sent to %s",
                user_email,
            )
        logger.warning(
            "EMAIL NOT SENT (mocked for demo): ATO security alert\n"
            "  to: %s\n  subject: %s\n  body: %s",
            user_email,
            subject,
            body,
        )
        return {
            "email": {"to": user_email, "subject": subject, "body": body},
            "delivery": "logged (mocked for demo)",
        }

    async def restrict_account(self, user_id: str | None) -> dict:
        """Mark the account restricted/locked (mock).

        The platform User row (when the flagged account maps to one) would
        carry the lock flag; for demo accounts the restriction is recorded
        in the event ledger — the authoritative DB status for this flow.
        """
        user_row = None
        if user_id:
            user_row = (
                await self.db.execute(select(User).where(User.email == user_id))
            ).scalar_one_or_none()
        logger.warning(
            "ATO ACCOUNT RESTRICTED (mock): account=%s platform_user=%s event=%s — "
            "login sessions would be suspended",
            user_id,
            "found" if user_row is not None else "not-found (demo account)",
            self.event.id,
        )
        return {
            "restricted": True,
            "flag": "account_restricted",
            "platform_user_found": user_row is not None,
        }

    async def force_password_reset(self, user_id: str | None) -> dict:
        """Invalidate current sessions/tokens (mock).

        Sessions live in Supabase Auth; invalidation is logged and recorded
        in the ledger (the demo stack has no service-role admin key).
        """
        logger.warning(
            "ATO FORCE PASSWORD RESET (mock): account=%s event=%s — all refresh "
            "sessions would be revoked",
            user_id,
            self.event.id,
        )
        return {"forced": True, "flag": "password_reset_forced"}
