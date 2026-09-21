"""Pydantic schemas for ORG-2: org dashboards and Splunk-style log analysis."""

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

LogTypeValue = Literal["auth", "network", "app"]

LogActionValue = Literal[
    "block_ip", "revoke_session", "escalate_incident", "mark_safe", "isolate_host"
]

DashboardFeature = Literal["phishing", "url", "deepfake", "impersonation"]


class LogIngestRequest(BaseModel):
    """Gateway log-ingestion payload — shape auto-detection runs server-side."""

    data: Any
    log_type: Optional[LogTypeValue] = None  # optional force; default: auto


class LogIngestResponse(BaseModel):
    status: str
    log_id: str
    log_type: str
    result: dict[str, Any]
    alert_id: Optional[str] = None


class OrgLogEventResponse(BaseModel):
    id: str
    log_type: str
    severity: str
    raw_data: dict[str, Any]
    analysis_result: dict[str, Any]
    manual_action_taken: Optional[str] = None
    acted_by: Optional[str] = None
    acted_at: Optional[Any] = None
    created_at: Optional[Any] = None


class LogActionRequest(BaseModel):
    action: LogActionValue
    target: Optional[str] = None  # e.g. the IP to block / session to revoke
    note: Optional[str] = Field(default=None, max_length=500)


class LogActionResponse(BaseModel):
    log_id: str
    action: str
    taken_by: str
    taken_at: Any
    audit_logged: bool = True


class DashboardSummaryResponse(BaseModel):
    organization_id: str
    total_scans: int
    threats_detected: int
    quarantined_emails: int
    blocked_senders: int
    critical_alerts: int
    last_scan_at: Optional[Any] = None
    # ORG-REDESIGN: project scope + per-feature aggregates. Additive and
    # optional so existing clients (and the pre-project test suites) keep
    # passing: features is {} when no project filter was requested.
    project_id: Optional[str] = None
    features: dict[str, Any] = {}


class FeatureScanRow(BaseModel):
    alert_id: str
    timestamp: Optional[Any] = None
    severity: str
    score: int
    title: str
    target: Optional[str] = None  # sender / URL / media name / claimed identity
    indicators: list = []
    explanation: Optional[str] = None
    action_taken: Optional[str] = None


class FeatureDashboardResponse(BaseModel):
    feature: str
    total: int
    limit: int
    offset: int
    rows: list[FeatureScanRow]
