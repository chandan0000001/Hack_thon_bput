"""Audit logging service using Async SQLAlchemy."""

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext
from app.db.models import AuditLog

logger = logging.getLogger("cyberguard.audit")


async def log_action(
    db: AsyncSession,
    *,
    tenant: Optional[TenantContext] = None,
    owner_user_id: Optional[str] = None,
    user_id: Optional[str] = None,
    user_name: Optional[str] = None,
    action: str,
    resource: Optional[str] = None,
    details: Optional[str] = None,
    actor_type: str = "user",  # user | system | scheduler (Phase 5)
) -> None:
    """Insert an audit log entry for a state-changing operation."""
    from app.db.session import current_user_id

    resolved_owner = (
        owner_user_id
        or (tenant.owner_user_id if tenant and tenant.owner_user_id else None)
        or (tenant.user_id if tenant and tenant.user_id else None)
        or user_id
        or current_user_id.get()
    )
    if not resolved_owner:
        logger.warning("Skipping audit log for action %r: no owner/user identity available", action)
        return

    # ORG-WIRE: stamp the org (explicit tenant org, else the owner's active /
    # personal org) for the org-branch RLS policies (migration 0018).
    organization_id = tenant.organization_id if tenant else None
    if organization_id is None:
        try:
            from app.services.org_context import resolve_org_id

            organization_id = await resolve_org_id(db, resolved_owner)
        except Exception:  # noqa: BLE001 - stamping is best-effort
            organization_id = None

    try:
        entry = AuditLog(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            owner_user_id=resolved_owner,
            actor_type=actor_type,
            user_id=user_id or resolved_owner,
            user_name=user_name or "System",
            action=action,
            resource=resource,
            details=details,
        )
        db.add(entry)
        await db.commit()
    except Exception:
        await db.rollback()
        logger.exception("Failed to write audit log for action %r", action)


async def get_audit_logs(
    db: AsyncSession,
    tenant: TenantContext,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLog]:
    """Fetch audit logs scoped to the active tenant, newest first."""
    from app.core.security import tenant_criteria

    query = (
        select(AuditLog)
        .where(tenant_criteria(AuditLog, tenant))
        .order_by(desc(AuditLog.created_at))
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(query)
    return list(result.scalars().all())
