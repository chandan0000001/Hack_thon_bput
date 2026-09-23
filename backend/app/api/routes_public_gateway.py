"""Public Project Gateway API.

Single public ingress point for organization projects.
Secured exclusively via Project API Key (Bearer token).
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import OrgBlockedIndicator, OrgEvent, OrgProject
from app.db.session import get_session, set_session_user

logger = logging.getLogger("cyberguard.gateway")

router = APIRouter(tags=["Project Gateway"])


class GatewayRequest(BaseModel):
    action: str
    data: Any = Field(default_factory=dict)


def _check_indicator_matches(
    blocked_rows: list[OrgBlockedIndicator], data: Any, indicators: list[Any]
) -> list[dict[str, Any]]:
    """Determine if any registered blocked indicator matches the payload or analysis output."""
    matched: list[dict[str, Any]] = []
    data_str = json.dumps(data).lower() if isinstance(data, (dict, list)) else str(data).lower()

    for b in blocked_rows:
        val = b.indicator_value.strip().lower()
        if not val:
            continue

        hit = False
        # Check against analyzer indicators
        for ind in indicators:
            if isinstance(ind, str) and val in ind.lower():
                hit = True
                break
            elif isinstance(ind, dict):
                for v in ind.values():
                    if isinstance(v, str) and val in v.lower():
                        hit = True
                        break
                if hit:
                    break

        # Check in raw payload string
        if not hit and val in data_str:
            hit = True

        if hit:
            matched.append(
                {
                    "id": str(b.id),
                    "type": b.indicator_type,
                    "value": b.indicator_value,
                    "reason": b.reason,
                }
            )

    return matched


@router.post("/p/{project_slug}/gateway")
async def project_gateway(
    project_slug: str,
    req: GatewayRequest,
    authorization: str | None = Header(None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> JSONResponse:
    """Project ingestion gateway.

    Accepts analysis requests, authenticates via project API key, runs the
    requested analyzer, checks blocked indicators, and stores an org_event row.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer authorization header")

    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    # Validate key via security definer function
    val_stmt = text(
        "SELECT key_id, project_id, organization_id, role, owner_user_id, status "
        "FROM cyberguard.validate_org_api_key(:h)"
    )
    res = await session.execute(val_stmt, {"h": token_hash})
    key_row = res.mappings().first()

    if not key_row or key_row["status"] != "active":
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    # Set app.user_id for RLS context across subsequent queries
    await set_session_user(session, str(key_row["owner_user_id"]))

    # Update last_used_at
    await session.execute(
        text("UPDATE cyberguard.org_api_keys SET last_used_at = now() WHERE id = :kid"),
        {"kid": key_row["key_id"]},
    )

    # Resolve project by slug within key's organization
    proj_stmt = select(OrgProject).where(
        OrgProject.slug == project_slug,
        OrgProject.organization_id == str(key_row["organization_id"]),
    )
    proj_res = await session.execute(proj_stmt)
    project = proj_res.scalar_one_or_none()

    if not project or project.status == "archived" or str(project.id) != str(key_row["project_id"]):
        raise HTTPException(status_code=404, detail=f"Project '{project_slug}' not found")

    # Viewer role check
    if key_row["role"] == "viewer":
        raise HTTPException(status_code=403, detail="Viewer keys cannot perform analysis actions")

    action = req.action.strip() if req.action else ""
    data = req.data

    # Dispatch to analyzer
    if action == "analyze_log":
        from app.services.org_analyzers import log_analyzer

        analysis = log_analyzer.analyze(
            data if isinstance(data, dict) else {"payload": data},
            {"organization_id": str(project.organization_id)},
        )
        event_type = "log_event"
    elif action == "analyze_ato":
        from app.services.org_analyzers import ato_analyzer

        analysis = ato_analyzer.analyze(
            data if isinstance(data, dict) else {"payload": data},
            {"organization_id": str(project.organization_id)},
        )
        event_type = "ato_event"
    elif action == "analyze_network":
        from app.services.org_analyzers import network_analyzer

        analysis = network_analyzer.analyze(
            data if isinstance(data, dict) else {"payload": data},
            {"organization_id": str(project.organization_id)},
        )
        event_type = "network_event"
    else:
        return JSONResponse(
            status_code=501,
            content={"error": "analyzer_not_implemented", "analyzer": action},
        )

    if not analysis.get("available", False):
        return JSONResponse(
            status_code=501,
            content={"error": "analyzer_not_implemented", "analyzer": action},
        )

    # Check blocked indicators
    blocked_stmt = select(OrgBlockedIndicator).where(
        OrgBlockedIndicator.organization_id == str(project.organization_id)
    )
    blocked_rows = (await session.execute(blocked_stmt)).scalars().all()
    matched = _check_indicator_matches(blocked_rows, data, analysis.get("indicators", []))

    if matched:
        verdict = "blocked_permanently"
        user_action = "auto_blocked"
        acted_at = datetime.now(timezone.utc)
    else:
        verdict = "pending_review"
        user_action = None
        acted_at = None

    # Satisfy RLS for the insert
    await set_session_user(session, str(key_row["owner_user_id"]))

    event = OrgEvent(
        id=str(uuid.uuid4()),
        project_id=str(project.id),
        organization_id=str(project.organization_id),
        event_type=event_type,
        severity=str(analysis.get("severity", "medium")).lower(),
        source="gateway",
        raw_data=data if isinstance(data, dict) else {"payload": data},
        analysis_result=analysis,
        verdict=verdict,
        user_action=user_action,
        acted_by=None,
        acted_at=acted_at,
        created_at=datetime.now(timezone.utc),
    )
    session.add(event)
    await session.commit()

    response_payload = {
        "event_id": str(event.id),
        "risk_score": analysis.get("risk_score"),
        "severity": analysis.get("severity"),
        "indicators": analysis.get("indicators"),
        "verdict": verdict,
    }
    if matched:
        response_payload["blocked_indicator_matched"] = True
        response_payload["matched_indicators"] = matched

    return JSONResponse(status_code=200, content=response_payload)
