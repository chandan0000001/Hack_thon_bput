"""ORG-LIVE-VIEWS: read-only monitored event streams per feature.

    GET /org/{org_id}/projects/{project_slug}/streams/{feature}
    GET /org/{org_id}/projects/{project_slug}/streams/{feature}/{event_id}

These are VIEWERS over already-ingested data — nothing here creates or
analyzes anything (the org mode contract: no entry forms).

Data sources, per feature (the union is the stream):

- phishing | url | impersonation | deepfake | network | ato
    → ``alerts`` rows for the feature's modules. Alerts are the richest
      verdict record (severity, risk_score, summary, status, indicators);
      their ingest source is resolved through the linked Event row
      (gateway | connector | pipeline | api → manual-org).
- logs
    → ``org_log_events`` (exclusively gateway-fed per the model contract);
      summary/risk come from the stored ``analysis_result``.

Feature → sources mapping (event_type patterns documented in DECISIONS-style
comments; the actual stored values today are phishing_email, malicious_url,
impersonation_message, deepfake_media, and log_type auth|network|app).

Access: org member (viewer+) via ``require_org_role``; rows are additionally
RLS-scoped by the request's GUC. ``project_slug`` filters to one project;
the literal ``__all__`` returns the org-wide stream.

Pagination is keyset ((created_at, id) DESC) encoded in an opaque cursor so
polls never skip or repeat rows.
"""

import base64
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, ValidationError
from app.core.permissions import OrgRole, require_org_role
from app.db.models import Alert, Event, OrgLogEvent, Project
from app.db.session import get_db
from app.services.project_service import get_project_by_slug

router = APIRouter(prefix="/org", tags=["Org Streams"])

# ---------------------------------------------------------------------------
# Feature mapping
# ---------------------------------------------------------------------------

# feature -> alert.module values
FEATURE_MODULES: dict[str, set[str]] = {
    "phishing": {"phishing"},
    "url": {"url"},
    "impersonation": {"impersonation"},
    "deepfake": {"deepfake"},
    "network": {"network", "api_abuse"},
    "ato": {"account_takeover"},
    "logs": set(),
}

# feature -> event_type patterns kept for documentation/future sources
# (phishing: phishing_email, email_*; url: url_*; impersonation:
# impersonation_*, bec_*; deepfake: media_*, deepfake_*; logs: auth_log,
# network_flow, app_log, splunk_*; network: network_*; ato: ato_*,
# credential_*). The stored verdict rows are reached through the alert
# linkage above, so no LIKE scan over events is needed for the streams.
FEATURES = tuple(FEATURE_MODULES.keys())

SEVERITIES = {"critical", "high", "medium", "low", "safe", "info"}

SOURCES = ("gateway", "connector", "pipeline", "manual-org")


def _normalize_source(raw: Optional[str]) -> str:
    """Fold the stored Event.source values into the four stream buckets."""
    s = (raw or "").lower()
    if "gateway" in s:
        return "gateway"
    if "connector" in s or "mail" in s:
        return "connector"
    if "pipeline" in s or "scheduler" in s or "system" in s or "worker" in s:
        return "pipeline"
    return "manual-org"


class StreamRow(BaseModel):
    id: str
    ts: Optional[Any] = None
    event_type: str
    feature: str
    severity: Optional[str] = None
    source: str
    summary: Optional[str] = None
    risk_score: Optional[float] = None
    status: Optional[str] = None
    project_id: Optional[str] = None
    organization_id: Optional[str] = None


class StreamResponse(BaseModel):
    feature: str
    project_slug: str
    rows: list[StreamRow]
    next_cursor: Optional[str] = None


class StreamDetailResponse(BaseModel):
    row: StreamRow
    analysis: dict[str, Any] = {}


class _Cursor:
    __slots__ = ("ts", "id")

    def __init__(self, raw: str) -> None:
        try:
            decoded = base64.urlsafe_b64decode(raw.encode()).decode()
            ts_str, row_id = decoded.split("|", 1)
            self.ts = datetime.fromisoformat(ts_str)
            self.id = row_id
        except Exception as exc:  # noqa: BLE001 - malformed cursor
            raise ValidationError("Invalid cursor") from exc

    @staticmethod
    def encode(ts: datetime, row_id: str) -> str:
        payload = f"{ts.isoformat()}|{row_id}"
        return base64.urlsafe_b64encode(payload.encode()).decode()


async def _stream_rows(
    db: AsyncSession,
    *,
    org_id: str,
    project_id: Optional[str],
    feature: str,
    severity: Optional[str],
    source: Optional[str],
    q: Optional[str],
    since: Optional[datetime],
    until: Optional[datetime],
    limit: int,
    cursor: Optional[_Cursor],
) -> tuple[list[StreamRow], Optional[str]]:
    """Merge alerts + org_log_events into one normalized, newest-first page."""
    collected: list[StreamRow] = []
    fetch = limit + 1  # per-source budget: +1 detects a next page for the keyset

    # --- alerts branch -----------------------------------------------------
    if feature != "logs":
        modules = FEATURE_MODULES[feature]
        preds = [Alert.organization_id == org_id, Alert.module.in_(modules)]
        if project_id is not None:
            preds.append(Alert.project_id == project_id)
        if severity is not None:
            preds.append(Alert.severity == severity)
        if since is not None:
            preds.append(Alert.created_at >= since)
        if until is not None:
            preds.append(Alert.created_at <= until)
        if q is not None:
            like = f"%{q}%"
            preds.append(or_(Alert.title.ilike(like), Alert.summary.ilike(like)))
        if cursor is not None:
            preds.append((Alert.created_at, Alert.id) < (cursor.ts, cursor.id))
        result = await db.execute(
            select(Alert, Event.source)
            .outerjoin(Event, Alert.event_id == Event.id)
            .where(*preds)
            .order_by(Alert.created_at.desc(), Alert.id.desc())
            .limit(fetch)
        )
        for alert, event_source in result.all():
            row_source = _normalize_source(event_source)
            if source is not None and row_source != source:
                continue
            collected.append(
                StreamRow(
                    id=alert.id,
                    ts=alert.created_at,
                    event_type=_alert_event_type(alert.module),
                    feature=feature,
                    severity=alert.severity,
                    source=row_source,
                    summary=alert.title or alert.summary,
                    risk_score=float(alert.risk_score or 0),
                    status=alert.status,
                    project_id=alert.project_id,
                    organization_id=alert.organization_id,
                )
            )

    # --- org_log_events branch (feature=logs only) --------------------------
    if feature == "logs":
        preds = [OrgLogEvent.organization_id == org_id]
        if project_id is not None:
            preds.append(OrgLogEvent.project_id == project_id)
        if severity is not None:
            preds.append(OrgLogEvent.severity == severity)
        if since is not None:
            preds.append(OrgLogEvent.created_at >= since)
        if until is not None:
            preds.append(OrgLogEvent.created_at <= until)
        if q is not None:
            preds.append(OrgLogEvent.analysis_result["summary"].as_string().ilike(f"%{q}%"))
        if cursor is not None:
            preds.append((OrgLogEvent.created_at, OrgLogEvent.id) < (cursor.ts, cursor.id))
        result = await db.execute(
            select(OrgLogEvent)
            .where(*preds)
            .order_by(OrgLogEvent.created_at.desc(), OrgLogEvent.id.desc())
            .limit(fetch)
        )
        for log in result.scalars().all():
            row_source = "gateway"  # org_log_events are exclusively gateway-fed
            if source is not None and row_source != source:
                continue
            analysis = log.analysis_result or {}
            collected.append(
                StreamRow(
                    id=log.id,
                    ts=log.created_at,
                    event_type=str(log.log_type),
                    feature="logs",
                    severity=log.severity,
                    source=row_source,
                    summary=str(analysis.get("summary") or f"{log.log_type} log event"),
                    risk_score=float(analysis.get("risk_score") or 0),
                    status="acted" if log.manual_action_taken else "monitored",
                    project_id=log.project_id,
                    organization_id=log.organization_id,
                )
            )

    collected.sort(key=lambda r: (r.ts or datetime.min.replace(tzinfo=timezone.utc), r.id), reverse=True)
    page = collected[:limit]
    next_cursor = None
    if len(collected) > limit and page:
        last = page[-1]
        if last.ts is not None:
            next_cursor = _Cursor.encode(last.ts, last.id)
    return page, next_cursor


_MODULE_EVENT_TYPES = {
    "phishing": "phishing_email",
    "url": "malicious_url",
    "impersonation": "impersonation_message",
    "deepfake": "deepfake_media",
    "network": "network_event",
    "ato": "ato_event",
    "logs": "log",
}


def _alert_event_type(module: Optional[str]) -> str:
    return _MODULE_EVENT_TYPES.get(str(module or ""), str(module or "event"))


def _parse_iso(value: Optional[str], field: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError as exc:
        raise ValidationError(f"Invalid {field} (expected ISO-8601)") from exc


def _parse_range(range_key: Optional[str]) -> Optional[datetime]:
    """Time-range preset: 1h | 24h | 7d."""
    if not range_key or range_key == "all":
        return None
    deltas = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
    if range_key not in deltas:
        raise ValidationError("range must be one of 1h, 24h, 7d, all")
    return datetime.now(timezone.utc) - deltas[range_key]


@router.get("/{org_id}/projects/{project_slug}/streams/{feature}", response_model=StreamResponse)
async def org_feature_stream(
    org_id: str,
    project_slug: str,
    feature: str,
    severity: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
    range: Optional[str] = Query(default=None, alias="range"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    member: Any = Depends(require_org_role(OrgRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Read-only monitored event stream for one feature (viewer+).

    ``project_slug`` scopes to a project; ``__all__`` is org-wide. RLS on the
    request identity additionally constrains every row."""
    if feature not in FEATURE_MODULES:
        raise NotFoundError("Feature stream", feature)
    if severity is not None and severity not in SEVERITIES:
        raise ValidationError(f"severity must be one of {sorted(SEVERITIES)}")
    if source is not None and source not in SOURCES:
        raise ValidationError(f"source must be one of {list(SOURCES)}")

    if project_slug != "__all__":
        await get_project_by_slug(db, org_id=org_id, slug=project_slug)  # 404 unknown/archived
        project_id: Optional[str] = (
            (await db.execute(
                select(Project.id).where(
                    Project.organization_id == org_id, Project.slug == project_slug
                )
            ))
        ).scalar()
    else:
        project_id = None

    since_dt = _parse_iso(since, "since") or _parse_range(range)
    until_dt = _parse_iso(until, "until")
    cursor_obj = _Cursor(cursor) if cursor else None

    rows, next_cursor = await _stream_rows(
        db,
        org_id=org_id,
        project_id=project_id,
        feature=feature,
        severity=severity,
        source=source,
        q=q,
        since=since_dt,
        until=until_dt,
        limit=limit,
        cursor=cursor_obj,
    )
    return StreamResponse(feature=feature, project_slug=project_slug, rows=rows, next_cursor=next_cursor)


@router.get(
    "/{org_id}/projects/{project_slug}/streams/{feature}/{event_id}",
    response_model=StreamDetailResponse,
)
async def org_feature_stream_detail(
    org_id: str,
    project_slug: str,
    feature: str,
    event_id: str,
    member: Any = Depends(require_org_role(OrgRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Full row + stored analysis for one stream entry (viewer+, RLS-scoped)."""
    if feature not in FEATURE_MODULES:
        raise NotFoundError("Feature stream", feature)
    if project_slug != "__all__":
        await get_project_by_slug(db, org_id=org_id, slug=project_slug)

    if feature == "logs":
        log = (await db.execute(
            select(OrgLogEvent).where(
                OrgLogEvent.id == event_id, OrgLogEvent.organization_id == org_id
            )
        )).scalar_one_or_none()
        if log is None:
            raise NotFoundError("Stream event", event_id)
        analysis = log.analysis_result or {}
        row = StreamRow(
            id=log.id,
            ts=log.created_at,
            event_type=str(log.log_type),
            feature="logs",
            severity=log.severity,
            source="gateway",
            summary=str(analysis.get("summary") or f"{log.log_type} log event"),
            risk_score=float(analysis.get("risk_score") or 0),
            status="acted" if log.manual_action_taken else "monitored",
            project_id=log.project_id,
            organization_id=log.organization_id,
        )
        return StreamDetailResponse(
            row=row,
            analysis={
                "analysis_result": analysis,
                "raw_data": log.raw_data,
                "indicators": analysis.get("indicators") or [],
                "mitre_techniques": analysis.get("mitre_techniques") or [],
            },
        )

    alert = (await db.execute(
        select(Alert).where(
            Alert.id == event_id,
            Alert.organization_id == org_id,
            Alert.module.in_(FEATURE_MODULES[feature]),
        )
    )).scalar_one_or_none()
    if alert is None:
        raise NotFoundError("Stream event", event_id)
    event_source = (
        await db.execute(select(Event.source).where(Event.id == alert.event_id))
    ).scalar_one_or_none()
    row = StreamRow(
        id=alert.id,
        ts=alert.created_at,
        event_type=_alert_event_type(alert.module),
        feature=feature,
        severity=alert.severity,
        source=_normalize_source(event_source),
        summary=alert.title or alert.summary,
        risk_score=float(alert.risk_score or 0),
        status=alert.status,
        project_id=alert.project_id,
        organization_id=alert.organization_id,
    )
    return StreamDetailResponse(
        row=row,
        analysis={
            "title": alert.title,
            "summary": alert.summary,
            "explanation": alert.explanation,
            "indicators": alert.indicators or [],
            "mitre": alert.mitre or [],
        },
    )
