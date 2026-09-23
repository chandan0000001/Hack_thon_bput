"""SQLAlchemy ORM models for CYBERGUARD."""

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid_str() -> str:
    return str(uuid.uuid4())


# Portable JSON type: uses JSONB on PostgreSQL, standard JSON on SQLite
PortableJSON = JSON().with_variant(JSONB(), "postgresql")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # Supabase Auth UUID
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, unique=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # 'active' | 'invited'
    account_type: Mapped[str] = mapped_column(String(16), default="personal")  # 'personal' | 'org'
    # Notification address (Phase 7) — strictly separate from any connected
    # mailbox; system notifications NEVER go to connected mailboxes.
    notification_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_single_user: Mapped[bool] = mapped_column(Boolean, default=True)
    active_organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    # ORG-REDESIGN: persisted project switcher selection (org scope only).
    active_project_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    # Relationships
    memberships: Mapped[list["OrgMember"]] = relationship(
        "OrgMember", back_populates="user", cascade="all, delete-orphan"
    )
    owned_organizations: Mapped[list["OrgOrganization"]] = relationship(
        "OrgOrganization", back_populates="owner", foreign_keys="OrgOrganization.owner_id"
    )


class OrgOrganization(Base):
    __tablename__ = "org_organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    owner: Mapped["User"] = relationship("User", back_populates="owned_organizations", foreign_keys=[owner_id])
    members: Mapped[list["OrgMember"]] = relationship("OrgMember", back_populates="organization", cascade="all, delete-orphan")
    projects: Mapped[list["OrgProject"]] = relationship("OrgProject", back_populates="organization", cascade="all, delete-orphan")

    def __init__(self, **kwargs: Any) -> None:
        kwargs.pop("slug", None)
        kwargs.pop("is_personal", None)
        super().__init__(**kwargs)

    @property
    def is_personal(self) -> bool:
        return self.name == "Personal Workspace"

    @property
    def slug(self) -> str:
        import re
        return re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-")


class OrgMember(Base):
    __tablename__ = "org_members"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_members_org_user"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("org_organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # admin | analyst | viewer
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    organization: Mapped["OrgOrganization"] = relationship("OrgOrganization", back_populates="members")
    user: Mapped["User"] = relationship("User", back_populates="memberships", foreign_keys=[user_id])


class OrgProject(Base):
    __tablename__ = "org_projects"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug", name="uq_org_projects_org_slug"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("org_organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | archived
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    organization: Mapped["OrgOrganization"] = relationship("OrgOrganization", back_populates="projects")
    api_keys: Mapped[list["OrgApiKey"]] = relationship("OrgApiKey", back_populates="project", cascade="all, delete-orphan")
    events: Mapped[list["OrgEvent"]] = relationship("OrgEvent", back_populates="project", cascade="all, delete-orphan")


class OrgApiKey(Base):
    __tablename__ = "org_api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("org_projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("org_organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # master | viewer
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | revoked
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    project: Mapped["OrgProject"] = relationship("OrgProject", back_populates="api_keys")


class OrgEvent(Base):
    __tablename__ = "org_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("org_projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("org_organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)  # log_event | ato_event | network_event
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # critical | high | medium | low
    source: Mapped[str] = mapped_column(String(20), default="gateway")  # gateway | manual
    raw_data: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    analysis_result: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    verdict: Mapped[str] = mapped_column(String(32), default="pending_review")  # pending_review | released | blocked_permanently | false_positive
    user_action: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    acted_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    acted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    project: Mapped["OrgProject"] = relationship("OrgProject", back_populates="events")


class OrgBlockedIndicator(Base):
    __tablename__ = "org_blocked_indicators"
    __table_args__ = (
        UniqueConstraint("organization_id", "indicator_type", "indicator_value", name="uq_org_blocked_ind"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("org_organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("org_projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)  # ip | domain | email | hash | actor
    indicator_value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    blocked_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    blocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


# Compatibility aliases
Organization = OrgOrganization
OrganizationMember = OrgMember
Project = OrgProject


class Event(Base):
    __tablename__ = "events"

    # ORG-REDESIGN: which project produced this row (project gateway / active
    # project). Nullable — personal-mode and legacy rows have it NULL.
    project_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_data: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="received", index=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    media_files: Mapped[list["MediaFile"]] = relationship(
        "MediaFile", back_populates="event", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="event")


class MediaFile(Base):
    __tablename__ = "media_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    file_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    # Relationships
    event: Mapped["Event"] = relationship("Event", back_populates="media_files")


class Alert(Base):
    __tablename__ = "alerts"

    # ORG-REDESIGN: which project produced this row (project gateway / active
    # project). Nullable — personal-mode and legacy rows have it NULL.
    project_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    event_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    module: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    threat_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    indicators: Mapped[list[dict[str, Any]]] = mapped_column(PortableJSON, default=list)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre: Mapped[list[dict[str, Any]]] = mapped_column(PortableJSON, default=list)
    target_user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    target_service: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    event: Mapped[Optional["Event"]] = relationship("Event", back_populates="alerts")
    recommended_actions: Mapped[list["RecommendedAction"]] = relationship(
        "RecommendedAction", back_populates="alert", cascade="all, delete-orphan", lazy="selectin"
    )
    action_executions: Mapped[list["ActionExecution"]] = relationship(
        "ActionExecution", back_populates="alert", cascade="all, delete-orphan"
    )
    incident_links: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="alert", cascade="all, delete-orphan"
    )


class RecommendedAction(Base):
    __tablename__ = "recommended_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    automation_level: Mapped[str] = mapped_column(String(32), default="manual")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    priority: Mapped[str] = mapped_column(String(32), default="low")
    executed: Mapped[bool] = mapped_column(Boolean, default=False)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    # Relationships
    alert: Mapped["Alert"] = relationship("Alert", back_populates="recommended_actions")


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    alert_links: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    timeline: Mapped[list["IncidentEvent"]] = relationship(
        "IncidentEvent", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True, index=True
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="alert_links")
    alert: Mapped["Alert"] = relationship("Alert", back_populates="incident_links")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline")


class ResponseCatalog(Base):
    __tablename__ = "response_catalog"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    action: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    target_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    automation_level: Mapped[str] = mapped_column(String(32), default="manual")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ResponseExecution(Base):
    __tablename__ = "response_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    catalog_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("response_catalog.id", ondelete="SET NULL"), nullable=True
    )
    action_name: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    executed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    catalog_entry: Mapped[Optional["ResponseCatalog"]] = relationship("ResponseCatalog")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    # ORG-REDESIGN: which project produced this row (project gateway / active
    # project). Nullable — personal-mode and legacy rows have it NULL.
    project_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    user_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # user | system | scheduler — distinguishes automated vs user-initiated.
    actor_type: Mapped[str] = mapped_column(String(16), default="user")
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    

class EnforcementPolicy(Base):
    __tablename__ = "enforcement_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    # Nullable: personal-workspace policies carry organization_id = NULL and are
    # owner-scoped via owner_user_id instead.
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)  # e.g. "Strict", "Balanced", "Permissive"
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    # --- Per-threat-type risk thresholds (0-100), independent of display severity ---
    # phishing (also reused for URLs)
    phishing_high_threshold: Mapped[int] = mapped_column(Integer, default=75)
    phishing_medium_threshold: Mapped[int] = mapped_column(Integer, default=40)
    # deepfake / media
    deepfake_high_threshold: Mapped[int] = mapped_column(Integer, default=70)
    deepfake_medium_threshold: Mapped[int] = mapped_column(Integer, default=50)
    # account takeover
    ato_high_threshold: Mapped[int] = mapped_column(Integer, default=60)
    ato_medium_threshold: Mapped[int] = mapped_column(Integer, default=40)
    # network / api abuse
    network_high_threshold: Mapped[int] = mapped_column(Integer, default=70)
    network_medium_threshold: Mapped[int] = mapped_column(Integer, default=50)
    # impersonation / BEC
    impersonation_high_threshold: Mapped[int] = mapped_column(Integer, default=70)
    impersonation_medium_threshold: Mapped[int] = mapped_column(Integer, default=40)

    # --- Action per enforcement severity band ---
    action_on_critical: Mapped[str] = mapped_column(String(64), default="block_and_quarantine")
    action_on_high: Mapped[str] = mapped_column(String(64), default="block")
    action_on_medium: Mapped[str] = mapped_column(String(64), default="warn_and_log")
    action_on_low: Mapped[str] = mapped_column(String(64), default="allow")

    # --- Auto-execute toggles ---
    auto_execute_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_execute_high: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_execute_medium: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_execute_low: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- Notifications ---
    notify_soc_on_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_soc_on_high: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_user_on_medium: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    

class EmailConnectorAccount(Base):
    __tablename__ = "email_connector_accounts"
    __table_args__ = (
        UniqueConstraint("owner_user_id", "provider", "provider_email", name="uq_connector_owner_provider_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # gmail | outlook | yahoo | icloud
    provider_email: Mapped[str] = mapped_column(String(255), nullable=False)
    # connected | reauth_required | revoked | error
    status: Mapped[str] = mapped_column(String(32), default="connected", index=True)
    scopes: Mapped[list[Any]] = mapped_column(PortableJSON, default=list)
    capabilities: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)

    # Encrypted at rest (app.core.crypto); never returned by any API.
    access_token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    refresh_token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    access_token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)


class ConnectorOAuthState(Base):
    __tablename__ = "connector_oauth_states"

    state: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    redirect_after: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class ConnectorOperationLog(Base):
    __tablename__ = "connector_operation_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    connector_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    # authorize | callback | token_refresh | test_connection | disconnect
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    # success | failed | unsupported | insufficient_scope | reauth_required
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    provider_error_code: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    provider_error_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)


class ConnectorSettings(Base):
    __tablename__ = "connector_settings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    connector_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    # Hours until a quarantined message auto-releases; NULL = manual (never expire).
    quarantine_expiry_hours: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    permanent_delete_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_quarantine_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)


class QuarantinedItem(Base):
    __tablename__ = "quarantined_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    connector_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    provider_message_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    # Full Phase 3 ScanResult, stored for the review view.
    scan_result_json: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    quarantined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # quarantined | released | deleted | expired
    status: Mapped[str] = mapped_column(String(32), default="quarantined", index=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class BlockedSender(Base):
    __tablename__ = "blocked_senders"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    connector_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False)
    # Gmail filter id; NULL when rule creation failed or is not applicable.
    provider_rule_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # blocked | released | expired
    status: Mapped[str] = mapped_column(String(32), default="blocked", index=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class SecurityEvent(Base):
    """Permanent security history: one row per real security event / provider
    operation (Phase 5). AI chat content is NEVER written here."""

    __tablename__ = "security_events"

    # ORG-REDESIGN: which project produced this row (project gateway / active
    # project). Nullable — personal-mode and legacy rows have it NULL.
    project_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    # ORG-WIRE: org stamp (owner's active org / personal org fallback) so
    # org-plane members can see pipeline events under the org-branch RLS
    # policies (migration 0018). Personal mailbox artifacts stay owner-only.
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True,
    )
    # scan_verdict | quarantine | release | keep | delete | sender_block |
    # sender_release | sender_expiry | connector_connect |
    # connector_disconnect | connector_test | enforcement_decision |
    # sender_trust | sender_untrust
    event_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    connector_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="SET NULL"), nullable=True,
    )
    provider: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    provider_message_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    sender_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    indicators: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(PortableJSON, nullable=True)
    action_requested: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    action_performed: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # user | system | scheduler
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="user", index=True)
    # success | failed | unsupported | insufficient_scope | reauth_required
    operation_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    operation_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    quarantined_item_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("quarantined_items.id", ondelete="SET NULL"), nullable=True,
    )
    blocked_sender_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("blocked_senders.id", ondelete="SET NULL"), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)


class NotificationLog(Base):
    """Delivery log for event email notifications (Phase 7).

    Recipient is ALWAYS the user's notification_email — never a connected
    mailbox. The default backend is DB-logged delivery (hackathon-demo safe);
    optional SMTP is best-effort with fallback to DB logging.
    """

    __tablename__ = "notification_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # sent | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    error_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # db_log | smtp — how the message was actually delivered
    backend: Mapped[str] = mapped_column(String(16), default="db_log")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)


class ActionExecution(Base):
    __tablename__ = "action_executions"

    # ORG-REDESIGN: which project produced this row (project gateway / active
    # project). Nullable — personal-mode and legacy rows have it NULL.
    project_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    event_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    # What to do
    # values: quarantine_email | block_url | drop_packet | block_ip | revoke_session |
    #         require_mfa | rate_limit | tag_and_warn | allow | flag_for_review
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # e.g. {"email_id": "...", "recipient": "..."} or {"url": "..."} or {"ip": "..."}
    target: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)

    # Lifecycle: pending | approved | executing | success | failed | rejected | skipped | released | unblocked
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    execution_mode: Mapped[str] = mapped_column(String(16), nullable=False)  # "client" | "server"

    # Origin: user | api | automated_system | webhook
    triggered_by: Mapped[str] = mapped_column(String(64), nullable=False)
    triggered_by_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Approval workflow
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Execution result, e.g. {"quarantine_id": "q_abc", "simulated": true}
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_result: Mapped[Optional[dict[str, Any]]] = mapped_column(PortableJSON, nullable=True)

    # Risk context (denormalized for fast queries)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # critical|high|medium|low
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False)  # phishing|deepfake|ato|network|impersonation
    module: Mapped[str] = mapped_column(String(64), nullable=False)  # mirrors Alert.module

    # Policy reference
    policy_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("enforcement_policies.id", ondelete="SET NULL"), nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    alert: Mapped[Optional["Alert"]] = relationship("Alert", back_populates="action_executions")
    event: Mapped[Optional["Event"]] = relationship("Event")
    policy: Mapped[Optional["EnforcementPolicy"]] = relationship("EnforcementPolicy")


class TrustedSender(Base):
    """Sender trust list (FP-hardening, Deliverable 1).

    Populated explicitly by the user via "Release & trust sender" on a
    quarantined message (or from the Blocked Senders page). Trusted senders
    never auto-enforce: scans still run and verdicts are still shown, but the
    action engine becomes recommend-only for their messages with an explicit
    "sender is in your trust list" annotation.
    """

    __tablename__ = "trusted_senders"
    __table_args__ = (
        UniqueConstraint("owner_user_id", "sender_email", name="uq_trusted_sender_owner_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False)
    sender_domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Why the trust entry exists, e.g. "released: <subject>" — shown in the UI.
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)


class ScanResult(Base):
    """Scan results for emails/items (real-time and manual scans)."""

    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_message_id: Mapped[str] = mapped_column(String(128), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), default="safe")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    scan_details: Mapped[Optional[dict[str, Any]]] = mapped_column(PortableJSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    @property
    def indicators(self) -> list[dict[str, Any]]:
        return (self.scan_details or {}).get("indicators", [])

    @property
    def explanation(self) -> str:
        return (self.scan_details or {}).get("explanation", "")

    @property
    def severity(self) -> str:
        return (self.scan_details or {}).get("severity", self.verdict)

    @property
    def engine_results(self) -> dict[str, Any]:
        return (self.scan_details or {}).get("engine_results", {})


class GmailAccount(Base):
    """Connected Gmail account for real-time inbox monitoring."""

    __tablename__ = "gmail_accounts"
    __table_args__ = (
        UniqueConstraint("owner_user_id", "email", name="uq_gmail_accounts_owner_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="connected", index=True)  # 'connected', 'paused', 'disconnected', 'purged'
    disconnected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    paused_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    pubsub_stopped_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_push_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    access_token_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    refresh_token_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_history_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    watch_expiration: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    sync_status: Mapped[str] = mapped_column(String(32), default="active")  # 'active', 'paused', 'error'
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    processed_emails: Mapped[list["ProcessedEmail"]] = relationship(
        "ProcessedEmail", back_populates="gmail_account", cascade="all, delete-orphan"
    )

    VALID_SYNC_TRANSITIONS = {
        "active": {"paused", "error", "active"},
        "paused": {"active", "error", "paused"},
        "error": {"active", "error"},
    }

    def set_access_token(self, token: Optional[str]) -> None:
        if token is None:
            self.access_token_encrypted = None
        else:
            from app.core.crypto import encrypt_secret

            self.access_token_encrypted = encrypt_secret(token)

    def get_access_token(self) -> Optional[str]:
        if not self.access_token_encrypted:
            return None
        from app.core.crypto import decrypt_secret

        return decrypt_secret(self.access_token_encrypted)

    def set_refresh_token(self, token: Optional[str]) -> None:
        if token is None:
            self.refresh_token_encrypted = None
        else:
            from app.core.crypto import encrypt_secret

            self.refresh_token_encrypted = encrypt_secret(token)

    def get_refresh_token(self) -> Optional[str]:
        if not self.refresh_token_encrypted:
            return None
        from app.core.crypto import decrypt_secret

        return decrypt_secret(self.refresh_token_encrypted)

    @classmethod
    def can_transition_sync_status(cls_or_self, from_or_to: str, to_status: Optional[str] = None) -> bool:
        if to_status is None:
            if isinstance(cls_or_self, GmailAccount):
                from_status = cls_or_self.sync_status
                target_status = from_or_to
            else:
                return False
        else:
            from_status = from_or_to
            target_status = to_status
        return target_status in cls_or_self.VALID_SYNC_TRANSITIONS.get(from_status, set())


class JobQueue(Base):
    """Durable job queue state alongside Redis/Arq."""

    __tablename__ = "job_queue"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    job_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=5)
    payload: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    result: Mapped[Optional[dict[str, Any]]] = mapped_column(PortableJSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    next_retry_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    @classmethod
    def can_transition(
        cls_or_self,
        from_or_to: str,
        to_status: Optional[str] = None,
        retry_count: Optional[int] = None,
        max_retries: Optional[int] = None,
    ) -> bool:
        if to_status is None:
            if isinstance(cls_or_self, JobQueue):
                from_status = cls_or_self.status
                target_status = from_or_to
                r_count = cls_or_self.retry_count if retry_count is None else retry_count
                m_retries = cls_or_self.max_retries if max_retries is None else max_retries
            else:
                return False
        else:
            from_status = from_or_to
            target_status = to_status
            r_count = 0 if retry_count is None else retry_count
            m_retries = 5 if max_retries is None else max_retries

        if from_status == target_status:
            return True
        if target_status == "deleted":
            return True
        if from_status == "dead_letter":
            return target_status == "queued"
        if from_status == "queued":
            if target_status == "dead_letter":
                return True
            return target_status == "running"
        if from_status == "running":
            if target_status == "completed":
                return True
            if target_status == "failed":
                return r_count < m_retries
            if target_status == "dead_letter":
                return True
            return False
        if from_status == "failed":
            if target_status == "queued":
                return r_count < m_retries
            if target_status == "dead_letter":
                return True
            return False
        return False


class ProcessedEmail(Base):
    """Processed email record for real-time ingestion & idempotency."""

    __tablename__ = "processed_emails"
    __table_args__ = (
        UniqueConstraint("owner_user_id", "gmail_message_id", name="uq_processed_emails_owner_msg"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    gmail_account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("gmail_accounts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    gmail_message_id: Mapped[str] = mapped_column(String(128), nullable=False)
    subject: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sender: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processing_status: Mapped[str] = mapped_column(String(32), default="received")
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    classification: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    signals: Mapped[Optional[dict[str, Any]]] = mapped_column(PortableJSON, nullable=True)
    scan_result_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scan_results.id", ondelete="SET NULL"), nullable=True
    )
    # ATTACH-SCAN: per-attachment scan metadata + results (metadata ONLY —
    # attachment files themselves are NEVER stored; they exist only as
    # ephemeral 0600 temp files during scanning and are deleted afterwards):
    # [
    #   {
    #     "attachment_id": "<gmail attachment id>",
    #     "filename": "invoice.pdf",
    #     "mime_type": "application/pdf",          # declared by the sender
    #     "size_bytes": 123456,
    #     "scan_status": "completed|skipped|failed",
    #     "scan_results": {
    #       "status": "completed",
    #       "risk_score": 30,
    #       "verdict": "safe|suspicious|malicious",
    #       "indicators": [{"type": "mime_mismatch", "severity": "medium", ...}],
    #       "sha256": "<64-hex content hash>",
    #       "detected_mime": "application/pdf",    # from magic bytes
    #       "declared_mime": "application/pdf",
    #       "mime_mismatch": false,
    #       "scan_duration_ms": 412
    #     }
    #   }, ...
    # ]
    attachments_meta: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(PortableJSON, nullable=True)
    # Phase 4: final explainable verdict including attachment signals
    # (verdict/severity from VerdictBuilder; classification keeps its
    # legacy body-only semantics for existing consumers).
    verdict: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    gmail_account: Mapped["GmailAccount"] = relationship("GmailAccount", back_populates="processed_emails")
    scan_result: Mapped[Optional["ScanResult"]] = relationship("ScanResult")

    VALID_TRANSITIONS = {
        "received": {"fetching", "failed"},
        "fetching": {"fetched", "failed"},
        "fetched": {"analyzing", "failed"},
        "analyzing": {"analyzed", "failed"},
        "analyzed": {"completed", "failed"},
        "failed": {"received", "fetching"},
        "completed": set(),
    }

    @property
    def normalized_email(self) -> Optional[dict[str, Any]]:
        return (self.signals or {}).get("normalized_email")

    @property
    def headers(self) -> dict[str, str]:
        return (self.signals or {}).get("headers", {})

    @property
    def urls(self) -> list[str]:
        return (self.signals or {}).get("urls", [])

    @property
    def size_bytes(self) -> int:
        return (self.signals or {}).get("size_bytes", 0)

    @property
    def error(self) -> Optional[str]:
        return (self.signals or {}).get("error") or (self.signals or {}).get("failure_reason")

    @classmethod
    def can_transition(cls_or_self, from_or_to: str, to_status: Optional[str] = None) -> bool:
        if to_status is None:
            if isinstance(cls_or_self, ProcessedEmail):
                from_status = cls_or_self.processing_status
                target_status = from_or_to
            else:
                return False
        else:
            from_status = from_or_to
            target_status = to_status
        return target_status in cls_or_self.VALID_TRANSITIONS.get(from_status, set())


