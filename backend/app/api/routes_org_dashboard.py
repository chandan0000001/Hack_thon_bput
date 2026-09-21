"""ORG-2: org-scoped dashboards (summary + per-feature verbose feeds).

Aggregations run through the SERVICE ROLE with an explicit
``organization_id`` filter: org rows (events/alerts/executions) are
owner-scoped in RLS to the org creator, so member sessions would see zero
rows. Membership is still enforced by ``require_org_role`` on the request
path before any query runs; the service role only widens the SQL view, the
org_id predicate keeps the data scoped to one organization.

Real-time: the frontend subscribes to ``alerts``/``org_log_events`` via
Supabase ``postgres_changes`` (migration 0009 adds both to the
``supabase_realtime`` publication); these REST endpoints are the
initial-load + pagination source.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, ValidationError
from app.core.permissions import OrgRole, require_org_role
from app.db.admin import _get_admin_session_maker
from app.db.models import (
    ActionExecution,
    Alert,
    Event,
    Organization,
    OrganizationMember,
    OrgLogEvent,
    OrgMailServer,
    OrgNotificationEmail,
    Project,
    SecurityEvent,
)
from app.schemas.org_dashboards import (
    DashboardSummaryResponse,
    FeatureDashboardResponse,
    FeatureScanRow,
)
logger = logging.getLogger("cyberguard.org_dashboards")

router = APIRouter(prefix="/org", tags=["Org Dashboards"])

# feature slug -> alerts.module
FEATURE_MODULES = {
    "phishing": "phishing",
    "url": "url",
    "deepfake": "deepfake",
    "impersonation": "impersonation",
}

SEVERITIES = {"safe", "low", "medium", "high", "critical"}

def _parse_date(value: str | None, field: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError as exc:
        raise ValidationError(f"Invalid {field} (expected ISO-8601)") from exc


async def _feature_severity(
    db: AsyncSession,
    model: Any,
    *,
    org_id: str,
    project_id: str | None,
    since: datetime | None,
    module: str | None = None,
) -> dict[str, Any]:
    """Count + severity distribution for one feature (7-day window)."""
    preds = [model.organization_id == org_id]
    if project_id is not None:
        preds.append(model.project_id == project_id)
    if since is not None:
        preds.append(model.created_at >= since)
    if module is not None:
        preds.append(model.module == module)
    total = (
        await db.execute(select(func.count()).select_from(model).where(*preds))
    ).scalar() or 0
    sev_rows = (
        await db.execute(
            select(model.severity, func.count())
            .where(*preds)
            .group_by(model.severity)
        )
    ).all()
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
    for sev, cnt in sev_rows:
        dist[str(sev) if str(sev) in dist else "other"] += int(cnt)
    return {"total": int(total), "severity": dist}


async def _summary(
    db: AsyncSession, org_id: str, project_id: str | None = None
) -> DashboardSummaryResponse:
    """Aggregate counts for one organization, optionally scoped to a project
    (service-role session; membership enforced on the request path)."""
    project_filter = [Event.project_id == project_id] if project_id is not None else []
    project_filter_alert = [Alert.project_id == project_id] if project_id is not None else []
    project_filter_exec = [ActionExecution.project_id == project_id] if project_id is not None else []
    total_scans = (
        await db.execute(
            select(func.count()).select_from(Event).where(
                Event.organization_id == org_id, *project_filter
            )
        )
    ).scalar() or 0
    threats_detected = (
        await db.execute(
            select(func.count()).select_from(Alert).where(
                Alert.organization_id == org_id, *project_filter_alert
            )
        )
    ).scalar() or 0
    critical_alerts = (
        await db.execute(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.organization_id == org_id,
                Alert.severity == "critical",
                *project_filter_alert,
            )
        )
    ).scalar() or 0
    quarantined_emails = (
        await db.execute(
            select(func.count())
            .select_from(ActionExecution)
            .where(
                ActionExecution.organization_id == org_id,
                ActionExecution.action_type == "quarantine_email",
                *project_filter_exec,
            )
        )
    ).scalar() or 0
    blocked_senders = (
        await db.execute(
            select(func.count())
            .select_from(ActionExecution)
            .where(
                ActionExecution.organization_id == org_id,
                ActionExecution.action_type.like("block%"),
                *project_filter_exec,
            )
        )
    ).scalar() or 0
    last_scan_at = (
        await db.execute(
            select(func.max(Event.created_at)).where(
                Event.organization_id == org_id, *project_filter
            )
        )
    ).scalar()

    # ORG-REDESIGN: per-feature aggregates for the dashboard tiles — event
    # counts + severity distributions over the LAST 7 DAYS, scoped to the
    # project when one is selected. Mail servers / email groups are config
    # surfaces, so they report inventory counts instead of event counts.
    features: dict[str, Any] = {}
    if project_id is not None:
        since = datetime.now(timezone.utc) - timedelta(days=7)
        for feature, module in FEATURE_MODULES.items():
            features[feature] = await _feature_severity(
                db, Alert, org_id=org_id, project_id=project_id, since=since, module=module
            )
        features["logs"] = await _feature_severity(
            db, OrgLogEvent, org_id=org_id, project_id=project_id, since=since
        )
        mail_rows = (
            await db.execute(
                select(OrgMailServer.status, func.count()).where(
                    OrgMailServer.organization_id == org_id
                ).group_by(OrgMailServer.status)
            )
        ).all()
        mail_total = sum(int(c) for _, c in mail_rows)
        features["mail_servers"] = {
            "total": mail_total,
            "by_status": {str(s): int(c) for s, c in mail_rows},
        }
        groups_total = (
            await db.execute(
                select(func.count()).select_from(OrgNotificationEmail).where(
                    OrgNotificationEmail.organization_id == org_id
                )
            )
        ).scalar() or 0
        features["email_groups"] = {"total": int(groups_total)}

    # ORG-LIVE-VIEWS: ingestion health strip — proves the system is
    # monitoring even when the feature tiles are quiet. Gateway metrics
    # honor the project scope; connector/pipeline metrics are org-wide.
    now_utc = datetime.now(timezone.utc)
    gateway_preds = [Event.organization_id == org_id, Event.source == "gateway"]
    if project_id is not None:
        gateway_preds.append(Event.project_id == project_id)
    gateway_last_event_ts = (
        await db.execute(
            select(func.max(Event.created_at)).where(*gateway_preds)
        )
    ).scalar()
    gateway_event_count_24h = (
        await db.execute(
            select(func.count()).select_from(Event).where(
                *gateway_preds, Event.created_at >= now_utc - timedelta(hours=24)
            )
        )
    ).scalar() or 0
    connector_rows = (
        await db.execute(
            select(OrgMailServer.status, func.count()).where(
                OrgMailServer.organization_id == org_id
            ).group_by(OrgMailServer.status)
        )
    ).all()
    by_status = {str(s): int(c) for s, c in connector_rows}
    pipeline_last_sync_ts = (
        await db.execute(
            select(func.max(SecurityEvent.created_at)).where(
                SecurityEvent.organization_id == org_id
            )
        )
    ).scalar()
    ingestion = {
        "gateway_last_event_ts": gateway_last_event_ts,
        "gateway_event_count_24h": int(gateway_event_count_24h),
        "connectors_connected": by_status.get("connected", 0),
        "connectors_total": sum(by_status.values()),
        "pipeline_last_sync_ts": pipeline_last_sync_ts,
    }

    return DashboardSummaryResponse(
        organization_id=org_id,
        total_scans=total_scans,
        threats_detected=threats_detected,
        quarantined_emails=quarantined_emails,
        blocked_senders=blocked_senders,
        critical_alerts=critical_alerts,
        last_scan_at=last_scan_at,
        project_id=project_id,
        features=features,
        ingestion=ingestion,
    )


@router.get("/{org_id}/dashboard/summary", response_model=DashboardSummaryResponse)
async def org_dashboard_summary(
    org_id: str,
    request: Request,
    project_id: str | None = Query(default=None),
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
) -> Any:
    """Org-scoped headline metrics (analyst+).

    ORG-REDESIGN: pass ``?project_id=`` (or the ``X-Project-Id`` header the
    frontend stamps) to scope every count to one project and receive the
    per-feature aggregates for the dashboard tiles."""
    scoped = project_id or request.headers.get("x-project-id") or None
    async with _get_admin_session_maker()() as db:
        return await _summary(db, org_id, scoped)


@router.get("/{org_id}/dashboard/{feature}", response_model=FeatureDashboardResponse)
async def org_feature_dashboard(
    org_id: str,
    feature: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    member: OrganizationMember = Depends(require_org_role(OrgRole.VIEWER)),
) -> Any:
    """Verbose per-feature scan feed (phishing | url | deepfake | impersonation)."""
    module = FEATURE_MODULES.get(feature)
    if module is None:
        raise NotFoundError("Feature dashboard", feature)
    if severity is not None and severity not in SEVERITIES:
        raise ValidationError(f"severity must be one of {sorted(SEVERITIES)}")
    from_dt = _parse_date(from_date, "from_date")
    to_dt = _parse_date(to_date, "to_date")

    predicates = [Alert.organization_id == org_id, Alert.module == module]
    if severity:
        predicates.append(Alert.severity == severity)
    if from_dt:
        predicates.append(Alert.created_at >= from_dt)
    if to_dt:
        predicates.append(Alert.created_at <= to_dt)

    async with _get_admin_session_maker()() as db:
        total = (
            await db.execute(
                select(func.count()).select_from(Alert).where(*predicates)
            )
        ).scalar() or 0
        result = await db.execute(
            select(Alert)
            .where(*predicates)
            .order_by(Alert.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        alerts = result.scalars().all()

        rows: list[FeatureScanRow] = []
        for alert in alerts:
            latest_action = (
                await db.execute(
                    select(ActionExecution.action_type)
                    .where(ActionExecution.alert_id == alert.id)
                    .order_by(ActionExecution.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            target = None
            for field in ("target_user", "target_service", "source_ip"):
                value = getattr(alert, field, None)
                if value:
                    target = value
                    break
            rows.append(
                FeatureScanRow(
                    alert_id=alert.id,
                    timestamp=alert.created_at,
                    severity=alert.severity,
                    score=alert.risk_score,
                    title=alert.title,
                    target=target,
                    indicators=alert.indicators or [],
                    explanation=alert.explanation,
                    action_taken=latest_action,
                )
            )

    return FeatureDashboardResponse(feature=feature, total=total, limit=limit, offset=offset, rows=rows)
