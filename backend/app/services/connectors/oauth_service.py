"""Gmail OAuth flow: authorization URL, state management, callback exchange."""

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.crypto import encrypt_secret
from app.db.admin import consume_connector_oauth_state, log_connector_operation_admin
from app.db.models import ConnectorOAuthState, EmailConnectorAccount
from app.services.email_providers.base import ConnectorStatus
from app.services.security_history_service import record_event
from app.services.email_providers.gmail import (
    GMAIL_SCOPE,
    GMAIL_SETTINGS_SCOPE,
    GOOGLE_AUTH_URL,
    GOOGLE_TOKEN_URL,
    gmail_provider,
)

logger = logging.getLogger("cyberguard.connectors.oauth")


class OAuthFlowError(Exception):
    """OAuth flow failure with a safe reason code for the frontend redirect."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason  # safe slug, e.g. invalid_state | token_exchange_failed
        self.message = message


async def create_gmail_authorization_url(
    db: AsyncSession,
    user_id: str,
    redirect_after: str | None = None,
    reconnect: str | None = None,
) -> str:
    """Create a single-use OAuth state row and build the Google consent URL."""
    settings = get_settings()
    if not settings.GOOGLE_GMAIL_CLIENT_ID or not settings.GOOGLE_GMAIL_CLIENT_SECRET:
        raise OAuthFlowError(
            "not_configured",
            "Gmail connector is not configured. Set GOOGLE_GMAIL_CLIENT_ID and "
            "GOOGLE_GMAIL_CLIENT_SECRET to enable it.",
        )

    raw_token = secrets.token_urlsafe(32)
    state = f"{raw_token}:rec:{reconnect}" if reconnect else secrets.token_urlsafe(48)
    db.add(
        ConnectorOAuthState(
            state=state,
            owner_user_id=user_id,
            provider="gmail",
            redirect_after=redirect_after,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=settings.CONNECTOR_OAUTH_STATE_TTL_SECONDS),
        )
    )
    await db.commit()

    params = {
        "client_id": settings.GOOGLE_GMAIL_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_GMAIL_REDIRECT_URI,
        "response_type": "code",
        "scope": f"{GMAIL_SCOPE} {GMAIL_SETTINGS_SCOPE}",
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def _exchange_code(code: str) -> dict:
    settings = get_settings()
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
        response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": settings.GOOGLE_GMAIL_CLIENT_ID,
                "client_secret": settings.GOOGLE_GMAIL_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": settings.GOOGLE_GMAIL_REDIRECT_URI,
            },
        )
    payload = {}
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        pass
    if response.status_code != 200 or not payload.get("access_token"):
        raise OAuthFlowError(
            "token_exchange_failed",
            f"Google token exchange failed (HTTP {response.status_code}): "
            + str(payload.get("error") or "unknown error"),
        )
    return payload


async def handle_gmail_callback(code: str, state: str) -> EmailConnectorAccount:
    """Consume the state, exchange the code, upsert the connector.

    Runs without a bearer token: state is consumed via the service-role
    helper and the connector row is written through it as well (owner comes
    from the state row, never from the browser).
    """
    from app.db.admin import _get_admin_session_maker

    state_data = await consume_connector_oauth_state(state)
    if state_data is None:
        raise OAuthFlowError("invalid_state", "OAuth state is invalid, expired, or already used.")
    if state_data["provider"] != "gmail":
        raise OAuthFlowError("invalid_state", "OAuth state provider mismatch.")

    owner_user_id = state_data["owner_user_id"]

    reconnect_account_id = None
    if state and ":rec:" in state:
        reconnect_account_id = state.split(":rec:")[1]

    # 1. Exchange the authorization code.
    try:
        tokens = await _exchange_code(code)
    except OAuthFlowError as exc:
        await log_connector_operation_admin(
            owner_user_id=owner_user_id,
            provider="gmail",
            operation="callback",
            status="failed",
            message=exc.message,
        )
        raise

    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token")
    expires_in = int(tokens.get("expires_in") or 3600)
    scopes = [s for s in str(tokens.get("scope") or GMAIL_SCOPE).split(" ") if s]

    # 2. Require a refresh token on first connection (access_type=offline).
    if not refresh_token:
        await log_connector_operation_admin(
            owner_user_id=owner_user_id,
            provider="gmail",
            operation="callback",
            status="failed",
            message="Google did not return a refresh token; user must reconnect with prompt=consent.",
            provider_error_code="missing_refresh_token",
        )
        raise OAuthFlowError(
            "missing_refresh_token",
            "Google did not grant offline access. Reconnect and make sure to "
            "approve the CYBERGUARD consent screen.",
        )

    # 3. Resolve the mailbox identity via the Gmail profile API.
    try:
        profile = await gmail_provider.get_profile(access_token)
    except Exception as exc:  # noqa: BLE001 - provider errors are logged honestly
        from app.services.email_providers.base import EmailProviderError

        if isinstance(exc, EmailProviderError):
            await log_connector_operation_admin(
                owner_user_id=owner_user_id,
                provider="gmail",
                operation="callback",
                status="failed",
                message=exc.message,
                provider_error_code=exc.provider_code,
                provider_error_detail=exc.provider_detail,
            )
            raise OAuthFlowError(
                "profile_failed", f"Gmail profile lookup failed: {exc.message}"
            ) from exc
        logger.exception("Unexpected Gmail profile failure")
        raise OAuthFlowError("profile_failed", "Gmail profile lookup failed.") from exc

    provider_email = profile.get("email_address")
    if not provider_email:
        await log_connector_operation_admin(
            owner_user_id=owner_user_id,
            provider="gmail",
            operation="callback",
            status="failed",
            message="Gmail profile returned no email address.",
        )
        raise OAuthFlowError("profile_failed", "Gmail profile returned no email address.")

    # 4. Upsert the connector (service-role session; owner from state row).
    from app.db.admin import _get_admin_session_maker

    async with _get_admin_session_maker()() as session:
        result = await session.execute(
            select(EmailConnectorAccount).where(
                EmailConnectorAccount.owner_user_id == owner_user_id,
                EmailConnectorAccount.provider == "gmail",
                EmailConnectorAccount.provider_email == provider_email,
            )
        )
        connector = result.scalar_one_or_none()
        if connector is None:
            connector = EmailConnectorAccount(
                id=str(uuid.uuid4()),
                owner_user_id=owner_user_id,
                provider="gmail",
                provider_email=provider_email,
            )
            session.add(connector)

        connector.status = ConnectorStatus.CONNECTED
        connector.scopes = scopes
        connector.capabilities = gmail_provider.capabilities
        connector.access_token_enc = encrypt_secret(access_token)
        connector.refresh_token_enc = encrypt_secret(refresh_token)
        connector.access_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        connector.last_sync_at = datetime.now(timezone.utc)
        connector.last_error = None
        await session.commit()
        await session.refresh(connector)
        connector_id = connector.id

        # Also register or update in GmailAccount for real-time Pub/Sub background workers
        try:
            from app.services.gmail_account_service import get_or_create_gmail_account

            gmail_acc = await get_or_create_gmail_account(
                session,
                owner_user_id=owner_user_id,
                email=provider_email,
                access_token=access_token,
                refresh_token=refresh_token,
                reconnect_account_id=reconnect_account_id,
            )
            logger.info("Mirrored Gmail connector to gmail_accounts for %s", provider_email)

            # Register push watch and record new history baseline so pre-disconnect history is NOT replayed
            from app.core.config import get_settings
            from app.services.gmail.watch_service import epoch_ms_to_datetime
            from app.services.gmail.client import GmailClient

            cfg = get_settings()
            topic = cfg.GMAIL_PUBSUB_TOPIC or "projects/test/topics/cyberguard-gmail-push"
            try:
                gclient = GmailClient()
                w_resp = await gclient.watch(access_token, topic=topic, refresh_token=refresh_token)
                if w_resp.get("historyId"):
                    gmail_acc.last_history_id = str(w_resp["historyId"])
                if w_resp.get("expiration"):
                    gmail_acc.watch_expiration = epoch_ms_to_datetime(w_resp["expiration"])
                gmail_acc.sync_status = "active"
                gmail_acc.last_error = None
                await session.commit()
                await session.refresh(gmail_acc)
                logger.info(
                    "Successfully activated Gmail push watch for %s with baseline historyId %s",
                    provider_email,
                    gmail_acc.last_history_id,
                )
            except Exception as watch_exc:
                logger.warning("Could not activate push watch on connect for %s: %s", provider_email, watch_exc)
        except Exception:
            logger.exception("Failed to mirror connector to gmail_accounts for %s", provider_email)

    await log_connector_operation_admin(
        owner_user_id=owner_user_id,
        provider="gmail",
        operation="callback",
        status="success",
        connector_id=connector_id,
        message=f"Connected {provider_email}",
    )
    from app.db.admin import _get_admin_session_maker

    async with _get_admin_session_maker()() as admin_db:
        await record_event(
            admin_db,
            owner_user_id=owner_user_id,
            event_type="connector_connect",
            actor_type="user",
            connector_id=connector_id,
            provider="gmail",
            operation_status="success",
            operation_detail=f"Gmail mailbox {provider_email} connected (scopes: {', '.join(scopes)})",
        )
    return connector


async def refresh_token(refresh_token: str) -> dict:
    """Refresh an access token using a Google OAuth refresh token."""
    from app.services.connectors.token_manager import _refresh_access_token

    return await _refresh_access_token(refresh_token)

