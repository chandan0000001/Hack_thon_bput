"""Action engine (Phase 4): provider-backed enforcement on scan results.

Closes the analysis loop: when the scanner recommends quarantine and the user
has auto-enforcement enabled, this service performs the real Gmail operations
(label-based quarantine, filter-based sender blocking) and records every
outcome — success or honest failure — in the database.
"""

import logging
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    BlockedSender,
    ConnectorOperationLog,
    ConnectorSettings,
    EmailConnectorAccount,
    OrgBlockedIndicator,
    QuarantinedItem,
)
from app.schemas.email import NormalizedMessage
from app.schemas.scan_results import ScanResult
from app.services.scoring_service import ACTION_BLOCK, ACTION_NOTIFY, ACTION_PASS
from app.services.security_history_service import record_event
from app.services.audit_service import log_action
from app.services.connectors.token_manager import TokenRefreshError, get_valid_access_token
from app.services.email_providers.base import EmailProviderError
from app.services.email_providers import get_provider
from app.services.trusted_senders import TRUST_ANNOTATION, is_sender_trusted

logger = logging.getLogger("cyberguard.action_engine")


class EnforcementOutcome(Exception):
    """Raised internally to short-circuit with an honest failure result."""


def corroboration_check(scan: ScanResult) -> tuple[bool, str]:
    """Corroborated auto-enforcement gate (FP-hardening, Deliverable 2).

    Provider-backed auto-quarantine / auto sender-block executes ONLY when the
    overall verdict is critical AND at least 2 engines independently scored
    high or critical. A single-engine critical (the classic false-positive
    signature: one engine screams while the others shrug — e.g. the Medium
    digest case high/medium/safe) is downgraded to review-recommended with no
    provider write. Returns (met, human-readable reason).
    """
    if scan.overall_severity != "critical":
        return False, f"overall severity is '{scan.overall_severity}', below critical"
    strong = [
        analysis.engine
        for analysis in scan.feature_analyses
        if analysis.severity in ("high", "critical")
    ]
    if len(strong) < 2:
        engines = ", ".join(f"{a.engine}={a.severity}" for a in scan.feature_analyses)
        return False, f"only {len(strong)} engine(s) scored high+ ({engines or 'none'})"
    return True, "corroboration_met: " + ", ".join(strong)


def _sender_email(from_header: str) -> str:
    _, addr = parseaddr(from_header or "")
    return (addr or from_header or "").strip().lower()


async def _record_org_block_indicators(
    db: AsyncSession, owner_user_id: str, sender_email: str, scan: ScanResult
) -> None:
    """CRITICAL tier 'pure block' (EMAIL-ACTION-MATRIX): persist the sender's
    email and domain into the owner's org blocklist (org_blocked_indicators)
    so gateway ingestion matches them regardless of mailbox filters. Best
    effort — never fails the enforcement flow."""
    try:
        from app.services.org_context import resolve_org_id

        organization_id = await resolve_org_id(db, owner_user_id)
        if not organization_id:
            return
        rows = [{"indicator_type": "email", "indicator_value": sender_email}]
        if "@" in sender_email:
            rows.append({
                "indicator_type": "domain",
                "indicator_value": sender_email.rsplit("@", 1)[-1],
            })
        for row in rows:
            existing = await db.execute(
                select(OrgBlockedIndicator).where(
                    OrgBlockedIndicator.organization_id == organization_id,
                    OrgBlockedIndicator.indicator_type == row["indicator_type"],
                    OrgBlockedIndicator.indicator_value == row["indicator_value"],
                )
            )
            if existing.scalar_one_or_none() is None:
                db.add(
                    OrgBlockedIndicator(
                        organization_id=organization_id,
                        indicator_type=row["indicator_type"],
                        indicator_value=row["indicator_value"],
                        reason=f"Auto-blocked: {scan.overall_severity} email from {sender_email}",
                        blocked_by="action_engine",
                    )
                )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 - blocklist persistence is best effort
        await db.rollback()
        logger.warning("org_blocked_indicators persistence failed (non-fatal): %s", exc)


async def get_or_create_settings(db: AsyncSession, connector: EmailConnectorAccount) -> ConnectorSettings:
    result = await db.execute(
        select(ConnectorSettings).where(ConnectorSettings.connector_id == connector.id)
    )
    settings = result.scalar_one_or_none()
    if settings is None:
        settings = ConnectorSettings(
            owner_user_id=connector.owner_user_id,
            connector_id=connector.id,
            quarantine_expiry_hours=24,
            permanent_delete_enabled=False,
            auto_quarantine_enabled=True,
        )
        db.add(settings)
        await db.commit()
        await db.refresh(settings)
    return settings


async def _log(db: AsyncSession, connector: EmailConnectorAccount, operation: str, status: str, message: str, connector_id: str | None = None) -> None:
    db.add(
        ConnectorOperationLog(
            owner_user_id=connector.owner_user_id,
            connector_id=connector_id or connector.id,
            provider=connector.provider,
            operation=operation,
            status=status,
            message=message,
        )
    )
    await db.commit()


async def _get_token(db: AsyncSession, connector: EmailConnectorAccount) -> str:
    try:
        return await get_valid_access_token(connector, db)
    except TokenRefreshError as exc:
        raise EnforcementOutcome(exc.error_class, exc.message) from exc
    except RuntimeError as exc:  # e.g. CONNECTOR_TOKEN_KEY missing
        raise EnforcementOutcome("configuration_error", str(exc)) from exc


async def enforce_scan_result(
    db: AsyncSession, connector: EmailConnectorAccount, message: NormalizedMessage, scan: ScanResult
) -> ScanResult:
    """Execute provider-backed enforcement for one scan result.

    Mutates (and returns) the ScanResult so the API response reflects the real
    provider operation outcome instead of the Phase 3 deferral.
    """
    settings = await get_or_create_settings(db, connector)

    if scan.recommended_action in ("none", ACTION_PASS):
        scan.provider_operation_status = "no_action_required"
        scan.provider_operation_detail = "No enforcement action was recommended for this verdict."
        return scan

    if scan.recommended_action == ACTION_NOTIFY:
        # MEDIUM tier: delivered to the inbox; the user is warned (the
        # realtime worker sends the notification email). No provider write.
        scan.provider_operation_status = "notified"
        scan.provider_operation_detail = (
            "Medium-risk verdict: the message was delivered to the inbox and "
            "the user was notified about the suspicious content. No mailbox "
            "action was taken."
        )
        await record_event(
            db,
            owner_user_id=connector.owner_user_id,
            event_type="enforcement_decision",
            actor_type="system",
            connector=connector,
            provider_message_id=message.provider_message_id,
            sender_email=_sender_email(message.sender),
            subject=message.subject,
            severity=scan.overall_severity,
            score=scan.overall_score,
            action_requested=ACTION_NOTIFY,
            action_performed="none",
            operation_status="notified",
            operation_detail="action matrix MEDIUM tier: delivered + user notified, no mailbox change",
        )
        await _log(db, connector, "enforcement", "success",
                   f"Notify tier for {scan.message_id}: delivered, user warned")
        return scan

    if not settings.auto_quarantine_enabled:
        scan.provider_operation_status = "skipped_auto_enforcement_disabled"
        scan.provider_operation_detail = (
            "Auto-enforcement is disabled for this connector in Settings; the "
            "recommendation is advisory only. Nothing was changed in the mailbox."
        )
        await _log(db, connector, "enforcement", "success",
                   f"Auto-enforcement disabled; advisory only for {scan.message_id}")
        return scan

    sender = _sender_email(message.sender)

    # Trust list (Deliverable 1): scans still run and results are still shown,
    # but enforcement is recommend-only with an explicit annotation.
    if await is_sender_trusted(db, connector.owner_user_id, sender):
        scan.provider_operation_status = "skipped_trusted_sender"
        scan.provider_operation_detail = (
            f"{TRUST_ANNOTATION} Auto-quarantine was skipped; the verdict and "
            "recommended action are advisory only. Nothing was changed in the mailbox."
        )
        await record_event(
            db,
            owner_user_id=connector.owner_user_id,
            event_type="enforcement_decision",
            actor_type="system",
            connector=connector,
            provider_message_id=message.provider_message_id,
            sender_email=sender,
            subject=message.subject,
            severity=scan.overall_severity,
            score=scan.overall_score,
            action_requested=scan.recommended_action,
            action_performed="none",
            operation_status="skipped_trusted_sender",
            operation_detail="corroboration not required: sender is in your trust list — recommend-only",
        )
        await log_action(
            db, user_id=connector.owner_user_id, actor_type="system",
            action="auto_enforcement_skipped", resource=message.provider_message_id,
            details="sender is in trust list; recommend-only",
        )
        await _log(db, connector, "enforcement", "success",
                   f"Trusted sender {sender}: recommend-only for {scan.message_id}")
        return scan

    # Corroborated auto-enforcement (Deliverable 2), scoped to the BLOCK tier:
    # sender blocking still requires a critical overall AND >=2 engines at
    # high+. The QUARANTINE tier is reversible (release actions exist) and is
    # governed directly by the 4-tier score matrix, so it enforces without
    # this gate.
    if scan.recommended_action == ACTION_BLOCK:
        met, reason = corroboration_check(scan)
        if not met:
            scan.provider_operation_status = "review_recommended"
            scan.provider_operation_detail = (
                f"corroboration_missing ({reason}). Auto-enforcement withheld: the "
                "recommendation is advisory only — review it in Security History. "
                "Nothing was changed in the mailbox."
            )
            await record_event(
                db,
                owner_user_id=connector.owner_user_id,
                event_type="enforcement_decision",
                actor_type="system",
                connector=connector,
                provider_message_id=message.provider_message_id,
                sender_email=sender,
                subject=message.subject,
                severity=scan.overall_severity,
                score=scan.overall_score,
                explanation=scan.overall_explanation,
                action_requested=scan.recommended_action,
                action_performed="none",
                operation_status="corroboration_missing",
                operation_detail=f"corroboration_missing ({reason}); recommend-only",
            )
            await log_action(
                db, user_id=connector.owner_user_id, actor_type="system",
                action="auto_enforcement_skipped", resource=message.provider_message_id,
                details=f"corroboration_missing ({reason}); recommend-only",
            )
            await _log(db, connector, "enforcement", "success",
                       f"corroboration_missing for {scan.message_id}: {reason}")
            return scan

    try:
        # Phase 6: resolve the provider through the neutral contract — the
        # engine never touches Gmail-specific code.
        provider = get_provider(connector.provider)
        caps = provider.capabilities
        if not caps.get("supports_quarantine"):
            scan.provider_operation_status = "failed"
            scan.provider_operation_detail = (
                f"Provider '{connector.provider}' does not support quarantine."
            )
            await _log(db, connector, "enforcement", "unsupported",
                       f"Provider {connector.provider} lacks quarantine support")
            return scan

        token = await _get_token(db, connector)
        label_id = await provider.ensure_quarantine_label(token)

        # 1. Quarantine the message itself.
        await provider.quarantine_message(token, message.provider_message_id, label_id)

        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=settings.quarantine_expiry_hours)
            if settings.quarantine_expiry_hours
            else None
        )
        item = QuarantinedItem(
            owner_user_id=connector.owner_user_id,
            connector_id=connector.id,
            provider_message_id=message.provider_message_id,
            sender_email=sender,
            reason=f"{scan.overall_severity} verdict: {scan.recommended_action}",
            severity=scan.overall_severity,
            scan_result_json=scan.model_dump(mode="json"),
            expires_at=expires_at,
            status="quarantined",
        )
        db.add(item)
        await db.commit()
        await db.refresh(item)

        # 2. Block the sender via a provider filter (once per sender) — only
        # on the BLOCK tier (critical per the 4-tier matrix) and only if the
        # provider actually supports sender rules.
        rule_id: str | None = None
        rule_note = ""
        if scan.recommended_action == ACTION_BLOCK and caps.get("supports_sender_rules"):
            existing = await db.execute(
                select(BlockedSender).where(
                    BlockedSender.connector_id == connector.id,
                    BlockedSender.sender_email == sender,
                    BlockedSender.status == "blocked",
                )
            )
            if existing.scalar_one_or_none() is None:
                rule = await provider.create_sender_rule(token, sender, label_id)
                rule_id = str(rule.get("id", ""))
                block_row = BlockedSender(
                    owner_user_id=connector.owner_user_id,
                    connector_id=connector.id,
                    sender_email=sender,
                    provider_rule_id=rule_id,
                    reason=f"Auto-blocked: {scan.overall_severity} message",
                    expires_at=expires_at,
                    status="blocked",
                )
                db.add(block_row)
                await db.commit()
                await db.refresh(block_row)
                block_id = block_row.id
            else:
                rule_note = " Sender already blocked."

        scan.provider_operation_status = "success"
        scan.provider_operation_detail = (
            f"Message quarantined at the provider (label '{provider.quarantine_label_name}', "
            f"removed from INBOX)"
            + (f"; sender {sender} auto-blocked via filter" if rule_id else "")
            + (rule_note)
            + (
                f"; auto-release in {settings.quarantine_expiry_hours}h"
                if expires_at
                else "; manual expiry (no auto-release)"
            )
            + "."
        )
        # Keep the stored review snapshot consistent with the final outcome.
        item.scan_result_json = scan.model_dump(mode="json")
        await db.commit()

        # BLOCK tier 'pure block': record sender email + domain in the org
        # blocklist (best effort, after the provider ops succeeded).
        if scan.recommended_action == ACTION_BLOCK:
            await _record_org_block_indicators(db, connector.owner_user_id, sender, scan)

        # Security history (Phase 5): the real provider operations just performed.
        await record_event(
            db,
            owner_user_id=connector.owner_user_id,
            event_type="quarantine",
            actor_type="system",
            connector=connector,
            provider_message_id=message.provider_message_id,
            sender_email=sender,
            subject=message.subject,
            severity=scan.overall_severity,
            score=scan.overall_score,
            explanation=scan.overall_explanation,
            action_requested=scan.recommended_action,
            action_performed="quarantine",
            operation_status="success",
            operation_detail=f"corroboration_met; Label '{provider.quarantine_label_name}' applied, INBOX removed",
            quarantined_item_id=item.id,
        )
        if rule_id:
            await record_event(
                db,
                owner_user_id=connector.owner_user_id,
                event_type="sender_block",
                actor_type="system",
                connector=connector,
                provider_message_id=message.provider_message_id,
                sender_email=sender,
                subject=message.subject,
                severity=scan.overall_severity,
                action_requested="block_sender",
                action_performed="create_sender_rule",
                operation_status="success",
                operation_detail=f"Filter {rule_id} auto-quarantines future mail from {sender}",
                blocked_sender_id=block_id,
            )
        await _log(db, connector, "enforcement", "success",
                   f"Quarantined {message.provider_message_id} from {sender}", connector_id=connector.id)
        return scan

    except (EmailProviderError, EnforcementOutcome) as exc:
        error_class = getattr(exc, "error_class", "api_error")
        message_text = getattr(exc, "message", str(exc))
        await record_event(
            db,
            owner_user_id=connector.owner_user_id,
            event_type="quarantine",
            actor_type="system",
            connector=connector,
            provider_message_id=message.provider_message_id,
            sender_email=sender,
            subject=message.subject,
            severity=scan.overall_severity,
            score=scan.overall_score,
            action_requested=scan.recommended_action,
            action_performed="quarantine",
            operation_status=error_class if error_class in ("failed", "insufficient_scope", "reauth_required") else "failed",
            operation_detail=message_text,
        )
        scan.provider_operation_status = "failed"
        scan.provider_operation_detail = (
            f"Provider operation failed ({error_class}): {message_text} "
            "Nothing was changed unless a prior step had already succeeded."
        )
        await _log(db, connector, "enforcement", "failed", message_text)
        logger.warning("Enforcement failed for %s (%s): %s", message.provider_message_id, error_class, message_text)
        return scan
    except Exception as exc:  # noqa: BLE001 - never mask a real failure as success
        scan.provider_operation_status = "failed"
        scan.provider_operation_detail = f"Enforcement failed unexpectedly: {type(exc).__name__}: {exc}"
        await _log(db, connector, "enforcement", "failed", str(exc))
        logger.exception("Unexpected enforcement failure")
        return scan


async def enforce_scan_results(
    db: AsyncSession,
    connector: EmailConnectorAccount,
    pairs: list[tuple[NormalizedMessage, ScanResult]],
) -> list[ScanResult]:
    """Enforce a batch of scan results, skipping when auto-enforcement is off."""
    if not pairs:
        return [scan for _, scan in pairs]
    settings = await get_or_create_settings(db, connector)
    if not settings.auto_quarantine_enabled:
        outs = []
        for _, scan in pairs:
            if scan.recommended_action not in ("none", ACTION_PASS, ACTION_NOTIFY):
                scan.provider_operation_status = "skipped_auto_enforcement_disabled"
                scan.provider_operation_detail = (
                    "Auto-enforcement is disabled for this connector in Settings; "
                    "the recommendation is advisory only."
                )
            else:
                scan.provider_operation_status = (
                    "no_action_required"
                    if scan.recommended_action in ("none", ACTION_PASS)
                    else "notified"
                )
            outs.append(scan)
        return outs
    return [await enforce_scan_result(db, connector, message, scan) for message, scan in pairs]
