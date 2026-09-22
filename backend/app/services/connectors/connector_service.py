"""Connector account management: list, test, disconnect, safe serialization."""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_secret
from app.db.models import ConnectorOperationLog, EmailConnectorAccount
from app.services.connectors.token_manager import get_valid_access_token
from app.services.email_providers.base import ConnectorStatus
from app.services.email_providers.gmail import GOOGLE_REVOKE_URL, gmail_provider
from app.services.security_history_service import record_event

logger = logging.getLogger("cyberguard.connectors")


async def log_operation(
    db: AsyncSession,
    *,
    owner_user_id: str,
    provider: str,
    operation: str,
    status: str,
    connector_id: str | None = None,
    message: str | None = None,
    provider_error_code: str | None = None,
    provider_error_detail: str | None = None,
) -> None:
    """Write a connector operation log (owner session; RLS-scoped)."""
    try:
        db.add(
            ConnectorOperationLog(
                id=str(uuid.uuid4()),
                owner_user_id=owner_user_id,
                connector_id=connector_id,
                provider=provider,
                operation=operation,
                status=status,
                message=message,
                provider_error_code=provider_error_code,
                provider_error_detail=provider_error_detail,
            )
        )
        await db.commit()
    except Exception:  # noqa: BLE001 - logging must never break the flow
        logger.exception("Failed to write connector operation log")


def serialize_connector(connector: EmailConnectorAccount) -> dict:
    """Connector metadata for the API — never any token material."""
    return {
        "id": connector.id,
        "provider": connector.provider,
        "provider_email": connector.provider_email,
        "status": connector.status,
        "scopes": connector.scopes or [],
        "capabilities": connector.capabilities or {},
        "last_test_at": connector.last_test_at.isoformat() if connector.last_test_at else None,
        "last_sync_at": connector.last_sync_at.isoformat() if connector.last_sync_at else None,
        "last_error": connector.last_error,
        "created_at": connector.created_at.isoformat() if connector.created_at else None,
    }


async def list_connectors(db: AsyncSession, owner_user_id: str) -> list[EmailConnectorAccount]:
    result = await db.execute(
        select(EmailConnectorAccount)
        .where(EmailConnectorAccount.owner_user_id == owner_user_id)
        .order_by(EmailConnectorAccount.created_at.desc())
    )
    return list(result.scalars().all())


async def get_connector(
    db: AsyncSession, connector_id: str, owner_user_id: str
) -> EmailConnectorAccount | None:
    result = await db.execute(
        select(EmailConnectorAccount).where(
            EmailConnectorAccount.id == connector_id,
            EmailConnectorAccount.owner_user_id == owner_user_id,
        )
    )
    return result.scalar_one_or_none()


async def test_connector(
    db: AsyncSession, connector: EmailConnectorAccount
) -> dict:
    """Run a live connection test through the token manager + Gmail API."""
    try:
        access_token = await get_valid_access_token(connector, db)
        result = await gmail_provider.test_connection(access_token)
    except Exception as exc:  # noqa: BLE001
        error_class = getattr(exc, "error_class", "failed")
        message = str(exc)
        connector.last_test_at = datetime.now(timezone.utc)
        connector.last_error = message
        if error_class == "reauth_required":
            connector.status = ConnectorStatus.REAUTH_REQUIRED
        await log_operation(
            db,
            owner_user_id=connector.owner_user_id,
            provider=connector.provider,
            operation="test_connection",
            status="failed" if error_class not in ("reauth_required", "insufficient_scope") else error_class,
            connector_id=connector.id,
            message=message,
            provider_error_code=getattr(exc, "provider_code", None),
        )
        await record_event(
            db,
            owner_user_id=connector.owner_user_id,
            event_type="connector_test",
            actor_type="user",
            connector=connector,
            operation_status=error_class if error_class in ("failed", "insufficient_scope", "reauth_required") else "failed",
            operation_detail=message,
        )
        await db.commit()
        return {"ok": False, "error_class": error_class, "message": message}

    connector.last_test_at = datetime.now(timezone.utc)
    connector.last_sync_at = datetime.now(timezone.utc)
    connector.last_error = None
    if connector.status != ConnectorStatus.CONNECTED:
        connector.status = ConnectorStatus.CONNECTED
    await log_operation(
        db,
        owner_user_id=connector.owner_user_id,
        provider=connector.provider,
        operation="test_connection",
        status="success",
        connector_id=connector.id,
        message=f"Connection OK for {result.get('email_address')}",
    )
    await record_event(
        db,
        owner_user_id=connector.owner_user_id,
        event_type="connector_test",
        actor_type="user",
        connector=connector,
        operation_status="success",
        operation_detail=f"Connection test OK for {result.get('email_address')}",
    )
    await db.commit()
    return {
        "ok": True,
        "provider": connector.provider,
        "email_address": result.get("email_address"),
        "messages_total": result.get("messages_total"),
    }


async def disconnect_connector(
    db: AsyncSession, connector: EmailConnectorAccount
) -> None:
    """Revoke the connector: clear token material, best-effort Google revoke.

    The row is kept (status=revoked) for audit history; no hard delete.
    """
    # Best-effort revocation at Google; failure is logged, not fatal.
    revoke_note = None
    if connector.refresh_token_enc or connector.access_token_enc:
        token_to_revoke = None
        try:
            if connector.refresh_token_enc:
                token_to_revoke = decrypt_secret(connector.refresh_token_enc)
            elif connector.access_token_enc:
                token_to_revoke = decrypt_secret(connector.access_token_enc)
        except Exception:  # noqa: BLE001 - undecryptable tokens simply can't be revoked
            token_to_revoke = None
        if token_to_revoke:
            try:
                import httpx

                async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                    response = await client.post(GOOGLE_REVOKE_URL, data={"token": token_to_revoke})
                if response.status_code != 200:
                    revoke_note = f"Google revoke returned HTTP {response.status_code}"
            except Exception as exc:  # noqa: BLE001
                revoke_note = f"Google revoke unreachable: {type(exc).__name__}"

    connector.status = ConnectorStatus.REVOKED
    connector.access_token_enc = None
    connector.refresh_token_enc = None
    connector.access_token_expires_at = None
    connector.last_error = revoke_note  # None on a clean revoke

    if connector.provider == "gmail":
        from app.db.models import GmailAccount
        from app.services.gmail_account_service import perform_gmail_disconnect

        gm_stmt = select(GmailAccount).where(
            GmailAccount.owner_user_id == connector.owner_user_id,
            func.lower(GmailAccount.email) == connector.provider_email.lower(),
        )
        gm_acc = (await db.execute(gm_stmt)).scalar_one_or_none()
        if gm_acc is not None:
            await perform_gmail_disconnect(db, gm_acc)

    await log_operation(
        db,
        owner_user_id=connector.owner_user_id,
        provider=connector.provider,
        operation="disconnect",
        status="success" if not revoke_note else "failed",
        connector_id=connector.id,
        message=revoke_note or f"Disconnected {connector.provider_email}",
    )
    await record_event(
        db,
        owner_user_id=connector.owner_user_id,
        event_type="connector_disconnect",
        actor_type="user",
        connector=connector,
        operation_status="success" if not revoke_note else "failed",
        operation_detail=revoke_note or f"Disconnected {connector.provider_email}; tokens cleared",
    )
    await db.commit()


async def list_operations(
    db: AsyncSession, owner_user_id: str, limit: int = 50
) -> list[ConnectorOperationLog]:
    result = await db.execute(
        select(ConnectorOperationLog)
        .where(ConnectorOperationLog.owner_user_id == owner_user_id)
        .order_by(ConnectorOperationLog.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


def serialize_operation(log: ConnectorOperationLog) -> dict:
    return {
        "id": log.id,
        "connector_id": log.connector_id,
        "provider": log.provider,
        "operation": log.operation,
        "status": log.status,
        "message": log.message,
        "provider_error_code": log.provider_error_code,
        "created_at": log.created_at.isoformat() if log.created_at else None,
    }
