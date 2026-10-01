"""Squashed baseline migration for fresh database provisioning.

Revision ID: 0102_squash_baseline
Revises: 0101_user_identity_status
Create Date: 2026-09-23

Provides a deterministic, pure static DDL baseline for fresh database setups
without dynamic ORM coupling to deprecated legacy models.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0102_squash_baseline"
down_revision: Union[str, Sequence[str], None] = "0101_user_identity_status"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.squash_baseline")
SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name != "sqlite"

    # 0. Check if database is already provisioned (has tables from 0001-0101)
    result = bind.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'cyberguard'"))
    table_count = result.scalar() or 0
    if table_count > 10:
        logger.info("Database already provisioned (tables=%d) — skipping 0102_squash_baseline", table_count)
        return

    logger.info("Fresh database detected (tables=%d) — applying 0102 squashed baseline", table_count)

    # 1. Schema & Auth Compatibility
    bind.execute(text(f'CREATE SCHEMA IF NOT EXISTS {SCHEMA}'))
    bind.execute(text("CREATE SCHEMA IF NOT EXISTS auth"))
    if is_pg:
        bind.execute(text("""
            CREATE OR REPLACE FUNCTION auth.uid() RETURNS text AS $$
                SELECT coalesce(
                    nullif(current_setting('request.jwt.claim.sub', true), ''),
                    nullif(current_setting('app.user_id', true), '')
                );
            $$ LANGUAGE sql STABLE;
        """))

    # 2. Static Tables and Indexes DDL
    bind.execute(text("""CREATE TABLE cyberguard.audit_logs (
	project_id VARCHAR(36), 
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36), 
	user_id VARCHAR(64), 
	user_name VARCHAR(255), 
	actor_type VARCHAR(16) NOT NULL, 
	action VARCHAR(255) NOT NULL, 
	resource VARCHAR(255), 
	details TEXT, 
	owner_user_id VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_audit_logs_project_id ON cyberguard.audit_logs (project_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_audit_logs_organization_id ON cyberguard.audit_logs (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_audit_logs_created_at ON cyberguard.audit_logs (created_at)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_audit_logs_user_id ON cyberguard.audit_logs (user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_audit_logs_owner_user_id ON cyberguard.audit_logs (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.enforcement_policies (
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36), 
	owner_user_id VARCHAR(64), 
	name VARCHAR(120) NOT NULL, 
	description TEXT, 
	is_active BOOLEAN NOT NULL, 
	phishing_high_threshold INTEGER NOT NULL, 
	phishing_medium_threshold INTEGER NOT NULL, 
	deepfake_high_threshold INTEGER NOT NULL, 
	deepfake_medium_threshold INTEGER NOT NULL, 
	ato_high_threshold INTEGER NOT NULL, 
	ato_medium_threshold INTEGER NOT NULL, 
	network_high_threshold INTEGER NOT NULL, 
	network_medium_threshold INTEGER NOT NULL, 
	impersonation_high_threshold INTEGER NOT NULL, 
	impersonation_medium_threshold INTEGER NOT NULL, 
	action_on_critical VARCHAR(64) NOT NULL, 
	action_on_high VARCHAR(64) NOT NULL, 
	action_on_medium VARCHAR(64) NOT NULL, 
	action_on_low VARCHAR(64) NOT NULL, 
	auto_execute_critical BOOLEAN NOT NULL, 
	auto_execute_high BOOLEAN NOT NULL, 
	auto_execute_medium BOOLEAN NOT NULL, 
	auto_execute_low BOOLEAN NOT NULL, 
	notify_soc_on_critical BOOLEAN NOT NULL, 
	notify_soc_on_high BOOLEAN NOT NULL, 
	notify_user_on_medium BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_enforcement_policies_owner_user_id ON cyberguard.enforcement_policies (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_enforcement_policies_is_active ON cyberguard.enforcement_policies (is_active)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_enforcement_policies_organization_id ON cyberguard.enforcement_policies (organization_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.events (
	project_id VARCHAR(36), 
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36), 
	event_type VARCHAR(64) NOT NULL, 
	source VARCHAR(64) NOT NULL, 
	raw_data JSONB NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	created_by VARCHAR(64), 
	owner_user_id VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_events_status ON cyberguard.events (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_events_project_id ON cyberguard.events (project_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_events_owner_user_id ON cyberguard.events (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_events_created_at ON cyberguard.events (created_at)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_events_organization_id ON cyberguard.events (organization_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.incidents (
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36), 
	title VARCHAR(255) NOT NULL, 
	severity VARCHAR(32) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	assigned_to VARCHAR(255), 
	created_by VARCHAR(64), 
	owner_user_id VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_incidents_owner_user_id ON cyberguard.incidents (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_incidents_created_at ON cyberguard.incidents (created_at)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_incidents_organization_id ON cyberguard.incidents (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_incidents_status ON cyberguard.incidents (status)"""))
    bind.execute(text("""CREATE TABLE cyberguard.response_catalog (
	id VARCHAR(36) NOT NULL, 
	action VARCHAR(255) NOT NULL, 
	target_type VARCHAR(64), 
	automation_level VARCHAR(32) NOT NULL, 
	requires_approval BOOLEAN NOT NULL, 
	description TEXT, 
	PRIMARY KEY (id), 
	UNIQUE (action)
)"""))
    bind.execute(text("""CREATE TABLE cyberguard.users (
	id VARCHAR(64) NOT NULL, 
	email VARCHAR(255), 
	username VARCHAR(64), 
	status VARCHAR(20) NOT NULL DEFAULT 'active', 
	account_type VARCHAR(16) NOT NULL DEFAULT 'user', 
	notification_email VARCHAR(255), 
	full_name VARCHAR(255), 
	is_single_user BOOLEAN NOT NULL DEFAULT true, 
	active_organization_id VARCHAR(36), 
	active_project_id VARCHAR(36), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), 
	PRIMARY KEY (id)
)"""))
    bind.execute(text("""CREATE UNIQUE INDEX ix_cyberguard_users_username ON cyberguard.users (username)"""))
    bind.execute(text("""CREATE UNIQUE INDEX ix_cyberguard_users_email ON cyberguard.users (email)"""))
    bind.execute(text("""CREATE TABLE cyberguard.alerts (
	project_id VARCHAR(36), 
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36), 
	event_id VARCHAR(36), 
	title VARCHAR(255) NOT NULL, 
	module VARCHAR(64) NOT NULL, 
	threat_type VARCHAR(64), 
	severity VARCHAR(32) NOT NULL, 
	risk_score INTEGER NOT NULL, 
	confidence FLOAT, 
	status VARCHAR(32) NOT NULL, 
	summary TEXT, 
	indicators JSONB NOT NULL, 
	explanation TEXT, 
	mitre JSONB NOT NULL, 
	target_user VARCHAR(255), 
	target_service VARCHAR(255), 
	source_ip VARCHAR(64), 
	created_by VARCHAR(64), 
	owner_user_id VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(event_id) REFERENCES cyberguard.events (id) ON DELETE SET NULL
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_status ON cyberguard.alerts (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_target_user ON cyberguard.alerts (target_user)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_severity ON cyberguard.alerts (severity)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_module ON cyberguard.alerts (module)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_created_at ON cyberguard.alerts (created_at)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_organization_id ON cyberguard.alerts (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_event_id ON cyberguard.alerts (event_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_target_service ON cyberguard.alerts (target_service)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_owner_user_id ON cyberguard.alerts (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_alerts_project_id ON cyberguard.alerts (project_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.connector_oauth_states (
	state VARCHAR(128) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	provider VARCHAR(32) NOT NULL, 
	redirect_after VARCHAR(512), 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (state), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_connector_oauth_states_owner_user_id ON cyberguard.connector_oauth_states (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.email_connector_accounts (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	provider VARCHAR(32) NOT NULL, 
	provider_email VARCHAR(255) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	scopes JSONB NOT NULL, 
	capabilities JSONB NOT NULL, 
	access_token_enc TEXT, 
	refresh_token_enc TEXT, 
	access_token_expires_at TIMESTAMP WITH TIME ZONE, 
	last_sync_at TIMESTAMP WITH TIME ZONE, 
	last_test_at TIMESTAMP WITH TIME ZONE, 
	last_error TEXT, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_connector_owner_provider_email UNIQUE (owner_user_id, provider, provider_email), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_email_connector_accounts_status ON cyberguard.email_connector_accounts (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_email_connector_accounts_owner_user_id ON cyberguard.email_connector_accounts (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.gmail_accounts (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	email VARCHAR(255) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	disconnected_at TIMESTAMP WITH TIME ZONE, 
	paused_at TIMESTAMP WITH TIME ZONE, 
	pubsub_stopped_at TIMESTAMP WITH TIME ZONE, 
	last_push_at TIMESTAMP WITH TIME ZONE, 
	access_token_encrypted TEXT, 
	refresh_token_encrypted TEXT, 
	last_history_id VARCHAR(128), 
	watch_expiration TIMESTAMP WITH TIME ZONE, 
	sync_status VARCHAR(32) NOT NULL, 
	last_sync_at TIMESTAMP WITH TIME ZONE, 
	last_error TEXT, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_gmail_accounts_owner_email UNIQUE (owner_user_id, email), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_gmail_accounts_status ON cyberguard.gmail_accounts (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_gmail_accounts_owner_user_id ON cyberguard.gmail_accounts (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.incident_events (
	id VARCHAR(36) NOT NULL, 
	incident_id VARCHAR(36) NOT NULL, 
	action VARCHAR(255) NOT NULL, 
	actor VARCHAR(255) NOT NULL, 
	details TEXT, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(incident_id) REFERENCES cyberguard.incidents (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_incident_events_incident_id ON cyberguard.incident_events (incident_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_incident_events_created_at ON cyberguard.incident_events (created_at)"""))
    bind.execute(text("""CREATE TABLE cyberguard.job_queue (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	job_type VARCHAR(32) NOT NULL, 
	job_id VARCHAR(255) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	retry_count INTEGER NOT NULL, 
	max_retries INTEGER NOT NULL, 
	payload JSONB NOT NULL, 
	result JSONB, 
	error TEXT, 
	next_retry_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	started_at TIMESTAMP WITH TIME ZONE, 
	completed_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_job_queue_owner_user_id ON cyberguard.job_queue (owner_user_id)"""))
    bind.execute(text("""CREATE UNIQUE INDEX ix_cyberguard_job_queue_job_id ON cyberguard.job_queue (job_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.media_files (
	id VARCHAR(36) NOT NULL, 
	event_id VARCHAR(36) NOT NULL, 
	file_name VARCHAR(255) NOT NULL, 
	storage_path VARCHAR(512) NOT NULL, 
	file_type VARCHAR(64), 
	size_bytes BIGINT NOT NULL, 
	file_hash VARCHAR(128), 
	owner_user_id VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(event_id) REFERENCES cyberguard.events (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_media_files_owner_user_id ON cyberguard.media_files (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_media_files_event_id ON cyberguard.media_files (event_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.notification_logs (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	event_type VARCHAR(48) NOT NULL, 
	recipient_email VARCHAR(255) NOT NULL, 
	subject VARCHAR(255) NOT NULL, 
	body_html TEXT, 
	status VARCHAR(16) NOT NULL, 
	error_detail TEXT, 
	backend VARCHAR(16) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_notification_logs_status ON cyberguard.notification_logs (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_notification_logs_owner_user_id ON cyberguard.notification_logs (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_notification_logs_created_at ON cyberguard.notification_logs (created_at)"""))
    bind.execute(text("""CREATE TABLE cyberguard.org_organizations (
	id VARCHAR(36) NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	owner_id VARCHAR(64) NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_organizations_owner_id ON cyberguard.org_organizations (owner_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.response_executions (
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36), 
	catalog_id VARCHAR(36), 
	action_name VARCHAR(255) NOT NULL, 
	target VARCHAR(255), 
	status VARCHAR(32) NOT NULL, 
	executed_by VARCHAR(255), 
	approved_by VARCHAR(255), 
	owner_user_id VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(catalog_id) REFERENCES cyberguard.response_catalog (id) ON DELETE SET NULL
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_response_executions_owner_user_id ON cyberguard.response_executions (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_response_executions_organization_id ON cyberguard.response_executions (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_response_executions_status ON cyberguard.response_executions (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_response_executions_created_at ON cyberguard.response_executions (created_at)"""))
    bind.execute(text("""CREATE TABLE cyberguard.scan_results (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	provider_message_id VARCHAR(128) NOT NULL, 
	verdict VARCHAR(32) NOT NULL, 
	risk_score FLOAT NOT NULL, 
	scan_details JSONB, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_scan_results_owner_user_id ON cyberguard.scan_results (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.trusted_senders (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	sender_email VARCHAR(255) NOT NULL, 
	sender_domain VARCHAR(255), 
	reason VARCHAR(255) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_trusted_sender_owner_email UNIQUE (owner_user_id, sender_email), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_trusted_senders_created_at ON cyberguard.trusted_senders (created_at)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_trusted_senders_owner_user_id ON cyberguard.trusted_senders (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.action_executions (
	project_id VARCHAR(36), 
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36), 
	alert_id VARCHAR(36), 
	event_id VARCHAR(36), 
	owner_user_id VARCHAR(64), 
	action_type VARCHAR(64) NOT NULL, 
	target JSONB NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	execution_mode VARCHAR(16) NOT NULL, 
	triggered_by VARCHAR(64) NOT NULL, 
	triggered_by_id VARCHAR(64), 
	requires_approval BOOLEAN NOT NULL, 
	approved_by VARCHAR(64), 
	approved_at TIMESTAMP WITH TIME ZONE, 
	rejection_reason TEXT, 
	executed_at TIMESTAMP WITH TIME ZONE, 
	execution_result JSONB, 
	risk_score INTEGER NOT NULL, 
	severity VARCHAR(32) NOT NULL, 
	threat_type VARCHAR(64) NOT NULL, 
	module VARCHAR(64) NOT NULL, 
	policy_id VARCHAR(36), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(alert_id) REFERENCES cyberguard.alerts (id) ON DELETE SET NULL, 
	FOREIGN KEY(event_id) REFERENCES cyberguard.events (id) ON DELETE SET NULL, 
	FOREIGN KEY(policy_id) REFERENCES cyberguard.enforcement_policies (id) ON DELETE SET NULL
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_action_executions_project_id ON cyberguard.action_executions (project_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_action_executions_organization_id ON cyberguard.action_executions (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_action_executions_status ON cyberguard.action_executions (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_action_executions_event_id ON cyberguard.action_executions (event_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_action_executions_owner_user_id ON cyberguard.action_executions (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_action_executions_alert_id ON cyberguard.action_executions (alert_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_action_executions_action_type ON cyberguard.action_executions (action_type)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_action_executions_created_at ON cyberguard.action_executions (created_at)"""))
    bind.execute(text("""CREATE TABLE cyberguard.blocked_senders (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	connector_id VARCHAR(36) NOT NULL, 
	sender_email VARCHAR(255) NOT NULL, 
	provider_rule_id VARCHAR(128), 
	reason VARCHAR(255) NOT NULL, 
	blocked_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE, 
	status VARCHAR(32) NOT NULL, 
	last_error TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE, 
	FOREIGN KEY(connector_id) REFERENCES cyberguard.email_connector_accounts (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_blocked_senders_connector_id ON cyberguard.blocked_senders (connector_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_blocked_senders_status ON cyberguard.blocked_senders (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_blocked_senders_owner_user_id ON cyberguard.blocked_senders (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.connector_operation_logs (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	connector_id VARCHAR(36), 
	provider VARCHAR(32) NOT NULL, 
	operation VARCHAR(64) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	message TEXT, 
	provider_error_code VARCHAR(128), 
	provider_error_detail TEXT, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE, 
	FOREIGN KEY(connector_id) REFERENCES cyberguard.email_connector_accounts (id) ON DELETE SET NULL
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_connector_operation_logs_connector_id ON cyberguard.connector_operation_logs (connector_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_connector_operation_logs_status ON cyberguard.connector_operation_logs (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_connector_operation_logs_created_at ON cyberguard.connector_operation_logs (created_at)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_connector_operation_logs_owner_user_id ON cyberguard.connector_operation_logs (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.connector_settings (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	connector_id VARCHAR(36) NOT NULL, 
	quarantine_expiry_hours INTEGER, 
	permanent_delete_enabled BOOLEAN NOT NULL, 
	auto_quarantine_enabled BOOLEAN NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE, 
	FOREIGN KEY(connector_id) REFERENCES cyberguard.email_connector_accounts (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE UNIQUE INDEX ix_cyberguard_connector_settings_connector_id ON cyberguard.connector_settings (connector_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_connector_settings_owner_user_id ON cyberguard.connector_settings (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.incident_alerts (
	incident_id VARCHAR(36) NOT NULL, 
	alert_id VARCHAR(36) NOT NULL, 
	PRIMARY KEY (incident_id, alert_id), 
	FOREIGN KEY(incident_id) REFERENCES cyberguard.incidents (id) ON DELETE CASCADE, 
	FOREIGN KEY(alert_id) REFERENCES cyberguard.alerts (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_incident_alerts_alert_id ON cyberguard.incident_alerts (alert_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.org_members (
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36) NOT NULL, 
	user_id VARCHAR(64) NOT NULL, 
	role VARCHAR(20) NOT NULL, 
	joined_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_org_members_org_user UNIQUE (organization_id, user_id), 
	FOREIGN KEY(organization_id) REFERENCES cyberguard.org_organizations (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_members_organization_id ON cyberguard.org_members (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_members_user_id ON cyberguard.org_members (user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.org_projects (
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36) NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	slug VARCHAR(60) NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_org_projects_org_slug UNIQUE (organization_id, slug), 
	FOREIGN KEY(organization_id) REFERENCES cyberguard.org_organizations (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_projects_slug ON cyberguard.org_projects (slug)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_projects_organization_id ON cyberguard.org_projects (organization_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.processed_emails (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	gmail_account_id VARCHAR(36) NOT NULL, 
	gmail_message_id VARCHAR(128) NOT NULL, 
	subject TEXT, 
	sender VARCHAR(255), 
	received_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	processing_status VARCHAR(32) NOT NULL, 
	risk_score FLOAT, 
	classification VARCHAR(32), 
	signals JSONB, 
	scan_result_id VARCHAR(36), 
	attachments_meta JSONB, 
	verdict VARCHAR(32), 
	severity VARCHAR(32), 
	explanation TEXT, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_processed_emails_owner_msg UNIQUE (owner_user_id, gmail_message_id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE, 
	FOREIGN KEY(gmail_account_id) REFERENCES cyberguard.gmail_accounts (id) ON DELETE CASCADE, 
	FOREIGN KEY(scan_result_id) REFERENCES cyberguard.scan_results (id) ON DELETE SET NULL
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_processed_emails_gmail_account_id ON cyberguard.processed_emails (gmail_account_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_processed_emails_owner_user_id ON cyberguard.processed_emails (owner_user_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.quarantined_items (
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	connector_id VARCHAR(36) NOT NULL, 
	provider_message_id VARCHAR(128) NOT NULL, 
	sender_email VARCHAR(255) NOT NULL, 
	reason VARCHAR(255) NOT NULL, 
	severity VARCHAR(32) NOT NULL, 
	scan_result_json JSONB NOT NULL, 
	quarantined_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE, 
	status VARCHAR(32) NOT NULL, 
	last_error TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE, 
	FOREIGN KEY(connector_id) REFERENCES cyberguard.email_connector_accounts (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_quarantined_items_status ON cyberguard.quarantined_items (status)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_quarantined_items_owner_user_id ON cyberguard.quarantined_items (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_quarantined_items_connector_id ON cyberguard.quarantined_items (connector_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.recommended_actions (
	id VARCHAR(36) NOT NULL, 
	alert_id VARCHAR(36) NOT NULL, 
	action VARCHAR(255) NOT NULL, 
	description TEXT, 
	automation_level VARCHAR(32) NOT NULL, 
	requires_approval BOOLEAN NOT NULL, 
	priority VARCHAR(32) NOT NULL, 
	executed BOOLEAN NOT NULL, 
	executed_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(alert_id) REFERENCES cyberguard.alerts (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_recommended_actions_alert_id ON cyberguard.recommended_actions (alert_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.org_api_keys (
	id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36) NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	role VARCHAR(20) NOT NULL, 
	key_hash VARCHAR(128) NOT NULL, 
	key_prefix VARCHAR(16) NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	last_used_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES cyberguard.org_projects (id) ON DELETE CASCADE, 
	FOREIGN KEY(organization_id) REFERENCES cyberguard.org_organizations (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_api_keys_project_id ON cyberguard.org_api_keys (project_id)"""))
    bind.execute(text("""CREATE UNIQUE INDEX ix_cyberguard_org_api_keys_key_hash ON cyberguard.org_api_keys (key_hash)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_api_keys_organization_id ON cyberguard.org_api_keys (organization_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.org_blocked_indicators (
	id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36), 
	indicator_type VARCHAR(20) NOT NULL, 
	indicator_value VARCHAR(255) NOT NULL, 
	reason TEXT, 
	blocked_by VARCHAR(64), 
	blocked_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_org_blocked_ind UNIQUE (organization_id, indicator_type, indicator_value), 
	FOREIGN KEY(organization_id) REFERENCES cyberguard.org_organizations (id) ON DELETE CASCADE, 
	FOREIGN KEY(project_id) REFERENCES cyberguard.org_projects (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_blocked_indicators_project_id ON cyberguard.org_blocked_indicators (project_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_blocked_indicators_organization_id ON cyberguard.org_blocked_indicators (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_blocked_indicators_indicator_value ON cyberguard.org_blocked_indicators (indicator_value)"""))
    bind.execute(text("""CREATE TABLE cyberguard.org_events (
	id VARCHAR(36) NOT NULL, 
	project_id VARCHAR(36) NOT NULL, 
	organization_id VARCHAR(36) NOT NULL, 
	event_type VARCHAR(32) NOT NULL, 
	severity VARCHAR(20) NOT NULL, 
	source VARCHAR(20) NOT NULL, 
	raw_data JSONB NOT NULL, 
	analysis_result JSONB NOT NULL, 
	verdict VARCHAR(32) NOT NULL, 
	user_action VARCHAR(32), 
	acted_by VARCHAR(64), 
	acted_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES cyberguard.org_projects (id) ON DELETE CASCADE, 
	FOREIGN KEY(organization_id) REFERENCES cyberguard.org_organizations (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_events_organization_id ON cyberguard.org_events (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_events_project_id ON cyberguard.org_events (project_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_org_events_created_at ON cyberguard.org_events (created_at)"""))
    # MEMBER-INVITE-P1 (mirrors 0026_org_member_invitations): fresh DBs stop at
    # this squash baseline (alembic env.py fresh-DB optimization), so the
    # invitations table must exist here too.
    bind.execute(text("""CREATE TABLE cyberguard.organization_invitations (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	email VARCHAR(255) NOT NULL,
	role VARCHAR(20) NOT NULL,
	token_hash VARCHAR(128) NOT NULL,
	invited_by VARCHAR(64) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (now() + interval '7 days'),
	accepted_at TIMESTAMP WITH TIME ZONE,
	status VARCHAR(20) NOT NULL DEFAULT 'pending',
	created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
	PRIMARY KEY (id),
	CONSTRAINT organization_invitations_role_check CHECK (role IN ('admin', 'analyst', 'viewer')),
	CONSTRAINT organization_invitations_status_check CHECK (status IN ('pending', 'accepted', 'expired', 'revoked')),
	CONSTRAINT organization_invitations_token_hash_key UNIQUE (token_hash),
	FOREIGN KEY(organization_id) REFERENCES cyberguard.org_organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(invited_by) REFERENCES cyberguard.users (id) ON DELETE CASCADE
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_organization_invitations_org_email ON cyberguard.organization_invitations (organization_id, email)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_organization_invitations_token_hash ON cyberguard.organization_invitations (token_hash)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_organization_invitations_organization_id ON cyberguard.organization_invitations (organization_id)"""))
    bind.execute(text("""CREATE TABLE cyberguard.security_events (
	project_id VARCHAR(36), 
	id VARCHAR(36) NOT NULL, 
	owner_user_id VARCHAR(64) NOT NULL, 
	organization_id VARCHAR(36), 
	event_type VARCHAR(48) NOT NULL, 
	connector_id VARCHAR(36), 
	provider VARCHAR(32), 
	provider_message_id VARCHAR(128), 
	sender_email VARCHAR(255), 
	subject VARCHAR(255), 
	severity VARCHAR(32), 
	score FLOAT, 
	explanation TEXT, 
	indicators JSONB, 
	action_requested VARCHAR(64), 
	action_performed VARCHAR(64), 
	actor_type VARCHAR(16) NOT NULL, 
	operation_status VARCHAR(32), 
	operation_detail TEXT, 
	quarantined_item_id VARCHAR(36), 
	blocked_sender_id VARCHAR(36), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_user_id) REFERENCES cyberguard.users (id) ON DELETE CASCADE, 
	FOREIGN KEY(connector_id) REFERENCES cyberguard.email_connector_accounts (id) ON DELETE SET NULL, 
	FOREIGN KEY(quarantined_item_id) REFERENCES cyberguard.quarantined_items (id) ON DELETE SET NULL, 
	FOREIGN KEY(blocked_sender_id) REFERENCES cyberguard.blocked_senders (id) ON DELETE SET NULL
)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_security_events_project_id ON cyberguard.security_events (project_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_security_events_provider_message_id ON cyberguard.security_events (provider_message_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_security_events_created_at ON cyberguard.security_events (created_at)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_security_events_organization_id ON cyberguard.security_events (organization_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_security_events_actor_type ON cyberguard.security_events (actor_type)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_security_events_owner_user_id ON cyberguard.security_events (owner_user_id)"""))
    bind.execute(text("""CREATE INDEX ix_cyberguard_security_events_event_type ON cyberguard.security_events (event_type)"""))

    if not is_pg:
        return

    # 3. Helper Functions
    bind.execute(text(f"""
        CREATE OR REPLACE FUNCTION {SCHEMA}.org_member_role(p_org text, p_user text)
        RETURNS text
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = {SCHEMA}, pg_temp
        AS $$
            SELECT coalesce(
                (SELECT m.role
                 FROM {SCHEMA}.org_members m
                 WHERE m.organization_id = p_org
                   AND m.user_id = p_user
                 LIMIT 1),
                (SELECT 'admin'
                 WHERE EXISTS (
                     SELECT 1 FROM {SCHEMA}.org_organizations o
                     WHERE o.id = p_org AND o.owner_id = p_user))
            )
        $$;
    """))

    bind.execute(text(f"""
        CREATE OR REPLACE FUNCTION {SCHEMA}.validate_org_api_key(p_hash text)
        RETURNS TABLE (
            key_id text,
            project_id text,
            organization_id text,
            role text,
            owner_user_id text,
            status text
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = {SCHEMA}, pg_catalog
        AS $$
            SELECT k.id::text, k.project_id::text, k.organization_id::text, k.role,
                   o.owner_id::text, k.status
            FROM {SCHEMA}.org_api_keys k
            JOIN {SCHEMA}.org_organizations o ON o.id = k.organization_id
            WHERE k.key_hash = p_hash
        $$;
    """))

    # 4. Roles & Grants
    for role_name in ('cyberguard_api', 'authenticated', 'service_role'):
        bind.execute(text(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role_name}') THEN
                    CREATE ROLE {role_name} WITH NOBYPASSRLS;
                END IF;
            END $$;
        """))
        bind.execute(text(f"GRANT USAGE ON SCHEMA {SCHEMA} TO {role_name}"))
        bind.execute(text(f"GRANT ALL ON ALL TABLES IN SCHEMA {SCHEMA} TO {role_name}"))
        bind.execute(text(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA {SCHEMA} TO {role_name}"))
        bind.execute(text(f"GRANT ALL ON ALL FUNCTIONS IN SCHEMA {SCHEMA} TO {role_name}"))
        bind.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON TABLES TO {role_name}"))
        bind.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON SEQUENCES TO {role_name}"))
        bind.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON FUNCTIONS TO {role_name}"))

    bind.execute(text(f"GRANT EXECUTE ON FUNCTION {SCHEMA}.org_member_role(text, text) TO cyberguard_api, authenticated"))
    bind.execute(text(f"GRANT EXECUTE ON FUNCTION {SCHEMA}.validate_org_api_key(text) TO cyberguard_api, authenticated"))

    # 5. Enable Row Level Security (RLS) on all tables
    ALL_TABLES = [
        "action_executions", "alerts", "audit_logs", "blocked_senders",
        "connector_oauth_states", "connector_operation_logs", "connector_settings",
        "email_connector_accounts", "enforcement_policies", "events",
        "gmail_accounts", "incident_alerts", "incident_events", "incidents",
        "job_queue", "media_files", "notification_logs", "organization_invitations",
        "org_api_keys",
        "org_blocked_indicators", "org_events", "org_members", "org_organizations",
        "org_projects", "processed_emails", "quarantined_items", "recommended_actions",
        "response_catalog", "response_executions", "scan_results", "security_events",
        "trusted_senders", "users",
    ]
    for tbl in ALL_TABLES:
        bind.execute(text(f"ALTER TABLE {SCHEMA}.{tbl} ENABLE ROW LEVEL SECURITY"))
        bind.execute(text(f"ALTER TABLE {SCHEMA}.{tbl} FORCE ROW LEVEL SECURITY"))

    # 6. RLS Policies
    def _exec_policy(sql_block: str) -> None:
        for stmt in sql_block.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                bind.execute(text(stmt))

    target_roles = "authenticated, cyberguard_api"

    # cyberguard.users
    _exec_policy(f"""
        CREATE POLICY users_select ON {SCHEMA}.users FOR SELECT TO cyberguard_api USING (id = {_GUC});
        CREATE POLICY users_insert ON {SCHEMA}.users FOR INSERT TO cyberguard_api WITH CHECK (id = {_GUC});
        CREATE POLICY users_update ON {SCHEMA}.users FOR UPDATE TO cyberguard_api USING (id = {_GUC}) WITH CHECK (id = {_GUC});
        CREATE POLICY users_delete ON {SCHEMA}.users FOR DELETE TO cyberguard_api USING (id = {_GUC});
    """)

    # Rebuilt Organization Tables
    _exec_policy(f"""
        CREATE POLICY org_organizations_member_select ON {SCHEMA}.org_organizations FOR SELECT TO {target_roles} USING ({SCHEMA}.org_member_role(id, {_GUC}) IS NOT NULL);
        CREATE POLICY org_organizations_creator_insert ON {SCHEMA}.org_organizations FOR INSERT TO {target_roles} WITH CHECK (owner_id = {_GUC});
        CREATE POLICY org_organizations_admin_update ON {SCHEMA}.org_organizations FOR UPDATE TO {target_roles} USING ({SCHEMA}.org_member_role(id, {_GUC}) = 'admin') WITH CHECK ({SCHEMA}.org_member_role(id, {_GUC}) = 'admin');
        CREATE POLICY org_organizations_admin_delete ON {SCHEMA}.org_organizations FOR DELETE TO {target_roles} USING ({SCHEMA}.org_member_role(id, {_GUC}) = 'admin');

        CREATE POLICY org_members_member_select ON {SCHEMA}.org_members FOR SELECT TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL);
        CREATE POLICY org_members_admin_insert ON {SCHEMA}.org_members FOR INSERT TO {target_roles} WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_members_admin_update ON {SCHEMA}.org_members FOR UPDATE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin') WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_members_admin_delete ON {SCHEMA}.org_members FOR DELETE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');

        CREATE POLICY org_projects_member_select ON {SCHEMA}.org_projects FOR SELECT TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL);
        CREATE POLICY org_projects_admin_insert ON {SCHEMA}.org_projects FOR INSERT TO {target_roles} WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_projects_admin_update ON {SCHEMA}.org_projects FOR UPDATE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin') WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_projects_admin_delete ON {SCHEMA}.org_projects FOR DELETE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');

        CREATE POLICY org_api_keys_admin_select ON {SCHEMA}.org_api_keys FOR SELECT TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_api_keys_admin_insert ON {SCHEMA}.org_api_keys FOR INSERT TO {target_roles} WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_api_keys_admin_update ON {SCHEMA}.org_api_keys FOR UPDATE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin') WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_api_keys_admin_delete ON {SCHEMA}.org_api_keys FOR DELETE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');

        CREATE POLICY org_events_member_select ON {SCHEMA}.org_events FOR SELECT TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL);
        CREATE POLICY org_events_member_insert ON {SCHEMA}.org_events FOR INSERT TO {target_roles} WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL);
        CREATE POLICY org_events_member_update ON {SCHEMA}.org_events FOR UPDATE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL) WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL);

        CREATE POLICY org_blocked_indicators_member_select ON {SCHEMA}.org_blocked_indicators FOR SELECT TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL);
        CREATE POLICY org_blocked_indicators_admin_insert ON {SCHEMA}.org_blocked_indicators FOR INSERT TO {target_roles} WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_blocked_indicators_admin_update ON {SCHEMA}.org_blocked_indicators FOR UPDATE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin') WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_blocked_indicators_admin_delete ON {SCHEMA}.org_blocked_indicators FOR DELETE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');

        CREATE POLICY org_invitations_admin_select ON {SCHEMA}.organization_invitations FOR SELECT TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_invitations_admin_insert ON {SCHEMA}.organization_invitations FOR INSERT TO {target_roles} WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_invitations_admin_update ON {SCHEMA}.organization_invitations FOR UPDATE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin') WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
        CREATE POLICY org_invitations_admin_delete ON {SCHEMA}.organization_invitations FOR DELETE TO {target_roles} USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin');
    """)

    # Security Plane (Owner OR Org-member)
    for tbl in ('events', 'alerts', 'action_executions', 'security_events', 'audit_logs'):
        _exec_policy(f"""
            CREATE POLICY {tbl}_select ON {SCHEMA}.{tbl} FOR SELECT TO cyberguard_api USING (owner_user_id = {_GUC} OR (organization_id IS NOT NULL AND {SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL));
            CREATE POLICY {tbl}_insert ON {SCHEMA}.{tbl} FOR INSERT TO cyberguard_api WITH CHECK (owner_user_id = {_GUC} OR (organization_id IS NOT NULL AND {SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL));
            CREATE POLICY {tbl}_update ON {SCHEMA}.{tbl} FOR UPDATE TO cyberguard_api USING (owner_user_id = {_GUC} OR (organization_id IS NOT NULL AND {SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL));
            CREATE POLICY {tbl}_delete ON {SCHEMA}.{tbl} FOR DELETE TO cyberguard_api USING (owner_user_id = {_GUC});
        """)

    # Personal Owner-Scoped Tables
    for tbl in ('gmail_accounts', 'processed_emails', 'scan_results', 'job_queue', 'blocked_senders', 'trusted_senders', 'quarantined_items', 'notification_logs', 'connector_settings', 'connector_oauth_states', 'connector_operation_logs', 'email_connector_accounts'):
        bind.execute(text(f"""
            CREATE POLICY {tbl}_all ON {SCHEMA}.{tbl} FOR ALL TO cyberguard_api USING (owner_user_id = {_GUC}) WITH CHECK (owner_user_id = {_GUC})
        """))

    # Catalogs, Incidents, Policies
    _exec_policy(f"""
        CREATE POLICY response_catalog_select ON {SCHEMA}.response_catalog FOR SELECT TO cyberguard_api, authenticated USING (true);
        CREATE POLICY response_catalog_admin ON {SCHEMA}.response_catalog FOR ALL TO cyberguard_api USING (true) WITH CHECK (true);
        CREATE POLICY response_executions_all ON {SCHEMA}.response_executions FOR ALL TO cyberguard_api USING (true) WITH CHECK (true);
        CREATE POLICY enforcement_policies_all ON {SCHEMA}.enforcement_policies FOR ALL TO cyberguard_api USING (owner_user_id = {_GUC} OR (organization_id IS NOT NULL AND {SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL)) WITH CHECK (owner_user_id = {_GUC} OR (organization_id IS NOT NULL AND {SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin'));
        CREATE POLICY incidents_all ON {SCHEMA}.incidents FOR ALL TO cyberguard_api USING (owner_user_id = {_GUC}) WITH CHECK (owner_user_id = {_GUC});
        CREATE POLICY incident_events_all ON {SCHEMA}.incident_events FOR ALL TO cyberguard_api USING (EXISTS (SELECT 1 FROM {SCHEMA}.incidents i WHERE i.id = incident_id AND i.owner_user_id = {_GUC}));
        CREATE POLICY incident_alerts_all ON {SCHEMA}.incident_alerts FOR ALL TO cyberguard_api USING (EXISTS (SELECT 1 FROM {SCHEMA}.incidents i WHERE i.id = incident_id AND i.owner_user_id = {_GUC}));
        CREATE POLICY recommended_actions_all ON {SCHEMA}.recommended_actions FOR ALL TO cyberguard_api USING (EXISTS (SELECT 1 FROM {SCHEMA}.alerts a WHERE a.id = alert_id AND (a.owner_user_id = {_GUC} OR (a.organization_id IS NOT NULL AND {SCHEMA}.org_member_role(a.organization_id, {_GUC}) IS NOT NULL))));
        CREATE POLICY media_files_all ON {SCHEMA}.media_files FOR ALL TO cyberguard_api USING (true) WITH CHECK (true);
    """)

    # 7. Realtime Publication Membership
    bind.execute(text(f"ALTER TABLE {SCHEMA}.org_events REPLICA IDENTITY FULL"))
    bind.execute(text(f"ALTER TABLE {SCHEMA}.alerts REPLICA IDENTITY FULL"))
    bind.execute(text(f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
                BEGIN
                    ALTER PUBLICATION supabase_realtime ADD TABLE {SCHEMA}.alerts;
                EXCEPTION WHEN duplicate_object THEN
                    NULL;
                END;
                BEGIN
                    ALTER PUBLICATION supabase_realtime ADD TABLE {SCHEMA}.org_events;
                EXCEPTION WHEN duplicate_object THEN
                    NULL;
                END;
            END IF;
        END $$;
    """))

    bind.execute(text(f"""
        DO $$
        BEGIN
            IF to_regprocedure('auth.uid()') IS NOT NULL THEN
                IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = '{SCHEMA}' AND policyname = 'org_events_realtime_select') THEN
                    CREATE POLICY org_events_realtime_select ON {SCHEMA}.org_events FOR SELECT TO authenticated USING ({SCHEMA}.org_member_role(organization_id, auth.uid()::text) IS NOT NULL);
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = '{SCHEMA}' AND policyname = 'alerts_realtime_select') THEN
                    CREATE POLICY alerts_realtime_select ON {SCHEMA}.alerts FOR SELECT TO authenticated USING ((organization_id IS NOT NULL AND {SCHEMA}.org_member_role(organization_id, auth.uid()::text) IS NOT NULL) OR (organization_id IS NULL AND owner_user_id = auth.uid()::text));
                END IF;
            END IF;
        END $$;
    """))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(text("DROP SCHEMA IF EXISTS cyberguard CASCADE"))
