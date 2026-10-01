"""Token-based organization member invitations (MEMBER-INVITE-P1).

Replaced the retired stub-user flow (pre-created ``status='invited'`` rows
claimed on first login) with single-use, expiring, hashed invitations:

- The raw token (``secrets.token_urlsafe(32)``) is shown ONCE at creation;
  only its SHA-256 hash is persisted.
- ``create_invitation`` runs inside the org admin's RLS session.
- ``accept_invitation`` runs on the service role: the acceptor is by
  definition not yet a member, so ``org_members`` admin-insert RLS (and the
  admin-only invitation policies) would reject the write — the same pattern
  as project deletion.
- No user row is pre-created. The invitee signs up / signs in with the
  invited email; ``get_current_user`` JIT-provisions the local row, then the
  accept endpoint joins the org.
"""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.admin import _get_admin_session_maker, find_user_by_email
from app.db.models import OrgInvitation, OrgMember, OrgOrganization

logger = logging.getLogger("cyberguard.invitations")

INVITATION_TTL_DAYS = 7


def hash_invitation_token(token: str) -> str:
    """SHA-256 hex digest of the raw invitation token (what gets stored)."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _is_expired(invitation: OrgInvitation, now: datetime) -> bool:
    expires_at = invitation.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        # SQLite returns naive datetimes; treat as UTC.
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at is not None and expires_at <= now


async def _check_not_already_member(
    session: AsyncSession, org: OrgOrganization, email: str
) -> None:
    """Raise 400 when the invited email already belongs to the org (owner or member row)."""
    info = await find_user_by_email(email)
    if info is None:
        return
    if info["id"] == org.owner_id:
        raise HTTPException(status_code=400, detail="User is already a member of this organization")
    existing = (
        await session.execute(
            select(OrgMember).where(
                OrgMember.organization_id == org.id,
                OrgMember.user_id == info["id"],
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="User is already a member of this organization")


async def create_invitation(
    session: AsyncSession,
    org: OrgOrganization,
    email: str,
    role: str,
    invited_by: str,
) -> tuple[OrgInvitation, str, dict]:
    """Create a pending invitation for ``email``; returns (row, raw_token, email_status).

    The raw token is returned exactly once — only the hash is stored. Caller
    must run inside an admin-authorized RLS session (the insert policy is
    admin-only).

    MEMBER-INVITE-P3: after the record commits, the invitation email is sent
    (or logged in dev mode). A delivery failure NEVER rolls the invitation
    back — the admin can resend or the invitee can still redeem the token
    from the create response.
    """
    from app.services.email_service import send_invitation_email

    clean_email = _normalize_email(email)
    now = datetime.now(timezone.utc)

    await _check_not_already_member(session, org, clean_email)

    duplicate = (
        await session.execute(
            select(OrgInvitation).where(
                OrgInvitation.organization_id == org.id,
                OrgInvitation.email == clean_email,
                OrgInvitation.status == "pending",
            )
        )
    ).scalar_one_or_none()
    if duplicate is not None and not _is_expired(duplicate, now):
        raise HTTPException(status_code=409, detail="A pending invitation for this email already exists")

    raw_token = secrets.token_urlsafe(32)
    invitation = OrgInvitation(
        id=str(uuid.uuid4()),
        organization_id=org.id,
        email=clean_email,
        role=role,
        token_hash=hash_invitation_token(raw_token),
        invited_by=invited_by,
        expires_at=now + timedelta(days=INVITATION_TTL_DAYS),
        status="pending",
        created_at=now,
    )
    session.add(invitation)
    await session.commit()
    await session.refresh(invitation)
    logger.info("invitation %s created for org %s (%s as %s)", invitation.id, org.id, clean_email, role)

    accept_url = (
        f"{get_settings().FRONTEND_URL.rstrip('/')}"
        f"/auth/accept-invite?token={raw_token}"
    )
    try:
        email_status = await send_invitation_email(clean_email, org.name, role, accept_url)
    except Exception as exc:  # noqa: BLE001 - email must never roll back the invite
        logger.error("invitation email step failed for %s (invitation kept): %s", clean_email, exc)
        email_status = {"sent": False, "reason": f"email step failed: {type(exc).__name__}"}

    return invitation, raw_token, email_status


async def _load_by_token(session: AsyncSession, token: str) -> OrgInvitation:
    invitation = (
        await session.execute(
            select(OrgInvitation).where(OrgInvitation.token_hash == hash_invitation_token(token))
        )
    ).scalar_one_or_none()
    if invitation is None:
        raise HTTPException(status_code=404, detail="Invitation not found")
    return invitation


async def validate_invitation(session: AsyncSession, token: str) -> OrgInvitation:
    """Return the invitation row when it exists and is still redeemable.

    Raises 404 (unknown token), 409 (already accepted), 410 (expired or
    revoked). A pending-but-past-expiry row is lazily flipped to 'expired'.
    """
    invitation = await _load_by_token(session, token)
    now = datetime.now(timezone.utc)

    if invitation.status == "pending" and _is_expired(invitation, now):
        invitation.status = "expired"
        await session.commit()
    if invitation.status == "expired":
        raise HTTPException(status_code=410, detail="Invitation has expired")
    if invitation.status == "revoked":
        raise HTTPException(status_code=410, detail="Invitation was revoked")
    if invitation.status == "accepted":
        raise HTTPException(status_code=409, detail="Invitation has already been accepted")
    return invitation


async def accept_invitation(token: str, user_id: str, user_email: str) -> dict:
    """Redeem a pending invitation: insert the org_members row and consume the token.

    Runs entirely on the service role (see module docstring). The authenticated
    user's email must match the invited email. Returns the joined-org payload.
    """
    clean_invited_email = None
    async with _get_admin_session_maker()() as session:
        invitation = await _load_by_token(session, token)
        now = datetime.now(timezone.utc)

        if invitation.status == "pending" and _is_expired(invitation, now):
            invitation.status = "expired"
        if invitation.status == "expired":
            await session.commit()
            raise HTTPException(status_code=410, detail="Invitation has expired")
        if invitation.status == "revoked":
            await session.commit()
            raise HTTPException(status_code=410, detail="Invitation was revoked")
        if invitation.status == "accepted":
            await session.commit()
            raise HTTPException(status_code=409, detail="Invitation has already been accepted")

        clean_invited_email = _normalize_email(invitation.email)
        if _normalize_email(user_email) != clean_invited_email:
            await session.commit()
            raise HTTPException(
                status_code=403,
                detail="This invitation was issued to a different email address",
            )

        # Idempotent-ish: an existing membership consumes the invitation.
        existing = (
            await session.execute(
                select(OrgMember).where(
                    OrgMember.organization_id == invitation.organization_id,
                    OrgMember.user_id == user_id,
                )
            )
        ).scalar_one_or_none()
        if existing:
            invitation.status = "accepted"
            invitation.accepted_at = now
            await session.commit()
            raise HTTPException(status_code=400, detail="User is already a member of this organization")

        member = OrgMember(
            id=str(uuid.uuid4()),
            organization_id=invitation.organization_id,
            user_id=user_id,
            role=invitation.role,
            joined_at=now,
        )
        session.add(member)
        invitation.status = "accepted"
        invitation.accepted_at = now
        await session.commit()

        org = await session.get(OrgOrganization, invitation.organization_id)
        logger.info("invitation %s accepted by user %s -> org %s as %s",
                    invitation.id, user_id, invitation.organization_id, invitation.role)
        return {
            "organization_id": invitation.organization_id,
            "organization_name": org.name if org else "",
            "role": invitation.role,
            "member_id": member.id,
            "joined_at": member.joined_at.isoformat(),
        }


def invitation_to_dict(invitation: OrgInvitation, include_token: str = None) -> dict:
    """Serialize an invitation row. ``include_token`` carries the raw token on
    the create response (plaintext-once); never include token_hash."""
    payload = {
        "id": invitation.id,
        "organization_id": invitation.organization_id,
        "email": invitation.email,
        "role": invitation.role,
        "status": invitation.status,
        "invited_by": invitation.invited_by,
        "expires_at": invitation.expires_at.isoformat() if invitation.expires_at else None,
        "accepted_at": invitation.accepted_at.isoformat() if invitation.accepted_at else None,
        "created_at": invitation.created_at.isoformat() if invitation.created_at else None,
    }
    if include_token is not None:
        payload["token"] = include_token
    return payload
