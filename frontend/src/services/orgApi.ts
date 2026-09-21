/**
 * ORG-1 Foundation API: organizations with name salting, API key management,
 * org settings, members (RBAC), and the org-scoped gateway.
 *
 * Endpoints are always-on server-side (unlike the frozen /organizations
 * router). See backend/docs/org_foundation.md.
 */

import { apiFetch } from './http';

// --- Types ---

export interface OrgCreated {
  id: string;
  name: string;
  displayName?: string | null;
  slug: string;
  isPersonal: boolean;
  ownerId: string;
  role?: string | null;
}

export interface OrgApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  lastUsedAt: string | null;
  expiresAt: string | null;
  status: string;
  createdAt?: string;
}

export interface OrgApiKeyCreated extends OrgApiKey {
  /** Plaintext — returned EXACTLY ONCE by the create endpoint. */
  key: string;
}

export interface OrgSetting {
  key: string;
  value: Record<string, unknown>;
  updatedAt?: string;
}

export interface OrgMember {
  id: string;
  organizationId: string;
  userId: string;
  email?: string | null;
  fullName?: string | null;
  role: 'admin' | 'analyst' | 'viewer';
  joinedAt?: string;
}

export interface GatewayResult {
  status: string;
  action: string;
  result: Record<string, unknown>;
}

// --- Organizations ---

export function createOrg(name: string): Promise<OrgCreated> {
  return apiFetch('/orgs', { method: 'POST', body: JSON.stringify({ name }) });
}

// --- API keys ---

export function listApiKeys(orgId: string): Promise<OrgApiKey[]> {
  return apiFetch(`/orgs/${orgId}/api-keys`);
}

export function createApiKey(
  orgId: string,
  name: string,
  expiresAt?: string | null,
): Promise<OrgApiKeyCreated> {
  return apiFetch(`/orgs/${orgId}/api-keys`, {
    method: 'POST',
    body: JSON.stringify({ name, expires_at: expiresAt ?? null }),
  });
}

export function revokeApiKey(orgId: string, keyId: string): Promise<OrgApiKey> {
  return apiFetch(`/orgs/${orgId}/api-keys/${keyId}`, { method: 'DELETE' });
}

// --- Monitored event streams (ORG-LIVE-VIEWS) ---

export type StreamFeature =
  | 'phishing'
  | 'url'
  | 'impersonation'
  | 'deepfake'
  | 'logs'
  | 'network'
  | 'ato';

export interface StreamRow {
  id: string;
  ts: string | null;
  event_type: string;
  feature: string;
  severity: string | null;
  source: 'gateway' | 'connector' | 'pipeline' | 'manual-org';
  summary: string | null;
  risk_score: number | null;
  status: string | null;
  project_id: string | null;
  organization_id: string | null;
}

export interface StreamResponse {
  feature: string;
  project_slug: string;
  rows: StreamRow[];
  next_cursor?: string | null;
}

export interface StreamDetail {
  row: StreamRow;
  analysis: {
    title?: string;
    summary?: string;
    explanation?: string;
    indicators?: Record<string, unknown>[];
    mitre?: Record<string, unknown>[];
    analysis_result?: Record<string, unknown>;
    raw_data?: Record<string, unknown>;
  };
}

export interface StreamQuery {
  severity?: string;
  source?: string;
  q?: string;
  /** preset: 1h | 24h | 7d | all */
  range?: string;
  limit?: number;
  cursor?: string;
}

export function getOrgStream(
  orgId: string,
  projectSlug: string | null,
  feature: StreamFeature,
  query: StreamQuery = {},
): Promise<StreamResponse> {
  const slug = projectSlug ?? '__all__';
  const qs = new URLSearchParams();
  if (query.severity) qs.set('severity', query.severity);
  if (query.source) qs.set('source', query.source);
  if (query.q) qs.set('q', query.q);
  if (query.range) qs.set('range', query.range);
  if (query.limit) qs.set('limit', String(query.limit));
  if (query.cursor) qs.set('cursor', query.cursor);
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return apiFetch(`/org/${orgId}/projects/${slug}/streams/${feature}${suffix}`);
}

export function getOrgStreamDetail(
  orgId: string,
  projectSlug: string | null,
  feature: StreamFeature,
  eventId: string,
): Promise<StreamDetail> {
  const slug = projectSlug ?? '__all__';
  return apiFetch(`/org/${orgId}/projects/${slug}/streams/${feature}/${eventId}`);
}

// --- Projects (ORG-REDESIGN) ---

export interface Project {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  status: string;
  created_at?: string;
}

export interface ProjectApiKey {
  id: string;
  project_id: string;
  name: string;
  role: 'master' | 'viewer';
  key_prefix: string;
  last_used_at: string | null;
  status: string;
  created_at?: string;
}

export interface ProjectApiKeyCreated extends ProjectApiKey {
  /** Plaintext — returned EXACTLY ONCE by the create endpoint. */
  key: string;
}

export function listProjects(orgId: string): Promise<Project[]> {
  return apiFetch(`/orgs/${orgId}/projects`);
}

export function createProject(orgId: string, name: string): Promise<Project> {
  return apiFetch(`/orgs/${orgId}/projects`, {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
}

export function archiveProject(orgId: string, projectId: string): Promise<{ message: string }> {
  return apiFetch(`/orgs/${orgId}/projects/${projectId}`, { method: 'DELETE' });
}

export function listProjectKeys(orgId: string, projectId: string): Promise<ProjectApiKey[]> {
  return apiFetch(`/orgs/${orgId}/projects/${projectId}/keys`);
}

export function createProjectKey(
  orgId: string,
  projectId: string,
  role: 'master' | 'viewer',
  name: string,
): Promise<ProjectApiKeyCreated> {
  return apiFetch(`/orgs/${orgId}/projects/${projectId}/keys`, {
    method: 'POST',
    body: JSON.stringify({ role, name }),
  });
}

export function revokeProjectKey(
  orgId: string,
  projectId: string,
  keyId: string,
): Promise<{ message: string }> {
  return apiFetch(`/orgs/${orgId}/projects/${projectId}/keys/${keyId}`, { method: 'DELETE' });
}

// --- Settings ---

export function listSettings(orgId: string): Promise<OrgSetting[]> {
  return apiFetch(`/orgs/${orgId}/settings`);
}

export function upsertSetting(
  orgId: string,
  key: string,
  value: Record<string, unknown>,
): Promise<OrgSetting> {
  return apiFetch(`/orgs/${orgId}/settings/${encodeURIComponent(key)}`, {
    method: 'PUT',
    body: JSON.stringify({ value }),
  });
}

// --- Members ---

export function listMembers(orgId: string): Promise<OrgMember[]> {
  return apiFetch(`/orgs/${orgId}/members`);
}

export function addMember(
  orgId: string,
  email: string,
  role: OrgMember['role'],
): Promise<OrgMember> {
  return apiFetch(`/orgs/${orgId}/members`, {
    method: 'POST',
    body: JSON.stringify({ email, role }),
  });
}

export function updateMemberRole(
  orgId: string,
  userId: string,
  role: OrgMember['role'],
): Promise<OrgMember> {
  return apiFetch(`/orgs/${orgId}/members/${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({ role }),
  });
}

export function removeMember(orgId: string, userId: string): Promise<{ message: string }> {
  return apiFetch(`/orgs/${orgId}/members/${userId}`, { method: 'DELETE' });
}

// --- Gateway (used for diagnostics / integration snippets) ---

export function callGateway(
  orgId: string,
  apiKey: string,
  action: 'scan_email' | 'scan_url' | 'ingest_log',
  data: Record<string, unknown>,
): Promise<GatewayResult> {
  return fetch(
    `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'}/org/${orgId}/gateway`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', org_authorization: apiKey },
      body: JSON.stringify({ action, data }),
    },
  ).then(async (res) => {
    if (!res.ok) throw new Error(`Gateway error ${res.status}`);
    return res.json();
  });
}

// ---------------------------------------------------------------------------
// ORG-2: dashboards + live log analysis
// ---------------------------------------------------------------------------

export type DashboardFeature = 'phishing' | 'url' | 'deepfake' | 'impersonation';
export type LogType = 'auth' | 'network' | 'app';
export type LogAction =
  | 'block_ip'
  | 'revoke_session'
  | 'escalate_incident'
  | 'mark_safe'
  | 'isolate_host';

export interface FeatureAggregate {
  total: number;
  /** critical/high/medium/low/other — event features only. */
  severity?: Record<string, number>;
  /** Mail servers only. */
  by_status?: Record<string, number>;
}

export interface DashboardSummary {
  organization_id: string;
  total_scans: number;
  threats_detected: number;
  quarantined_emails: number;
  blocked_senders: number;
  critical_alerts: number;
  last_scan_at: string | null;
  project_id?: string | null;
  features?: Record<string, FeatureAggregate>;
  ingestion?: IngestionStatus;
}

export interface IngestionStatus {
  gateway_last_event_ts: string | null;
  gateway_event_count_24h: number;
  connectors_connected: number;
  connectors_total: number;
  pipeline_last_sync_ts: string | null;
}

export interface FeatureScanRow {
  alert_id: string;
  timestamp: string | null;
  severity: string;
  score: number;
  title: string;
  target: string | null;
  indicators: Array<Record<string, unknown>>;
  explanation: string | null;
  action_taken: string | null;
}

export interface FeatureDashboard {
  feature: string;
  total: number;
  limit: number;
  offset: number;
  rows: FeatureScanRow[];
}

export interface OrgLogEvent {
  id: string;
  log_type: LogType;
  severity: string;
  raw_data: Record<string, unknown>;
  analysis_result: Record<string, unknown>;
  manual_action_taken: string | null;
  acted_by: string | null;
  acted_at: string | null;
  created_at: string | null;
}

export interface DashboardFeedParams {
  limit?: number;
  offset?: number;
  severity?: string | null;
  from_date?: string | null;
  to_date?: string | null;
}

function qs(params: Record<string, string | number | null | undefined>): string {
  const pairs = Object.entries(params)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`);
  return pairs.length ? `?${pairs.join('&')}` : '';
}

export function getDashboardSummary(orgId: string, projectId?: string | null): Promise<DashboardSummary> {
  return apiFetch(
    `/org/${orgId}/dashboard/summary${projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''}`,
  );
}

export function getFeatureDashboard(
  orgId: string,
  feature: DashboardFeature,
  params: DashboardFeedParams = {},
): Promise<FeatureDashboard> {
  return apiFetch(
    `/org/${orgId}/dashboard/${feature}${qs({
      limit: params.limit,
      offset: params.offset,
      severity: params.severity,
      from_date: params.from_date,
      to_date: params.to_date,
    })}`,
  );
}

export function getLogStream(
  orgId: string,
  params: { limit?: number; severity?: string | null; log_type?: string | null } = {},
): Promise<OrgLogEvent[]> {
  return apiFetch(`/org/${orgId}/logs/stream${qs({ ...params })}`);
}

export function takeLogAction(
  orgId: string,
  logId: string,
  action: LogAction,
  target?: string,
  note?: string,
): Promise<{ log_id: string; action: string; taken_by: string; taken_at: string }> {
  return apiFetch(`/org/${orgId}/logs/${logId}/action`, {
    method: 'POST',
    body: JSON.stringify({ action, target, note }),
  });
}

// ---------------------------------------------------------------------------
// ORG-3: org mail server connectors (server-to-server infrastructure)
// ---------------------------------------------------------------------------

export type MailProviderType = 'google_workspace' | 'microsoft_365' | 'imap_smtp';

export interface MailServer {
  id: string;
  name: string;
  provider_type: MailProviderType;
  status: 'connected' | 'disconnected' | 'error';
  last_connected_at: string | null;
  last_error: string | null;
  has_credentials: boolean;
  created_at?: string;
}

export interface MailServerLog {
  id: string;
  mail_server_id: string;
  log_type: 'connection' | 'scan' | 'quarantine' | 'error';
  message: string;
  metadata: Record<string, unknown> | null;
  created_at: string | null;
}

export interface MailServerCredentialDraft {
  service_account_key?: string;
  delegated_user?: string;
  client_id?: string;
  client_secret?: string;
  tenant_id?: string;
  host?: string;
  port?: number;
  username?: string;
  password?: string;
}

export function listMailServers(orgId: string): Promise<MailServer[]> {
  return apiFetch(`/org/${orgId}/mail-servers`);
}

export function createMailServer(
  orgId: string,
  name: string,
  provider_type: MailProviderType,
  credentials?: MailServerCredentialDraft,
): Promise<MailServer> {
  return apiFetch(`/org/${orgId}/mail-servers`, {
    method: 'POST',
    body: JSON.stringify({ name, provider_type, credentials }),
  });
}

export function connectMailServer(
  orgId: string,
  serverId: string,
  credentials?: MailServerCredentialDraft,
): Promise<{ id: string; status: string }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/connect`, {
    method: 'POST',
    body: JSON.stringify(credentials ? { credentials } : {}),
  });
}

export function disconnectMailServer(orgId: string, serverId: string): Promise<{ id: string; status: string }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/disconnect`, { method: 'POST', body: JSON.stringify({}) });
}

export function deleteMailServer(orgId: string, serverId: string): Promise<{ message: string }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}`, { method: 'DELETE' });
}

export function listMailServerLogs(
  orgId: string,
  serverId: string,
  params: { limit?: number; log_type?: string | null; from_date?: string | null; to_date?: string | null } = {},
): Promise<MailServerLog[]> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/logs${qs({ ...params })}`);
}

export function getMailServerSettings(
  orgId: string,
  serverId: string,
): Promise<{ mail_server_id: string; settings: Record<string, unknown> }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/settings`);
}

export function updateMailServerSettings(
  orgId: string,
  serverId: string,
  settings: Record<string, unknown>,
): Promise<{ mail_server_id: string; settings: Record<string, unknown> }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/settings`, {
    method: 'PUT',
    body: JSON.stringify({ settings }),
  });
}

// ---------------------------------------------------------------------------
// ORG-4: org email notification groups
// ---------------------------------------------------------------------------

export type RoleGroup = 'admin' | 'analyst' | 'viewer';
export type OrgEventType = 'server_down' | 'mail_server_down' | 'critical_log' | 'impersonation';

export interface NotificationEmail {
  id: string;
  email: string;
  role: RoleGroup;
  is_enabled: boolean;
  created_at?: string;
}

export interface NotificationSetting {
  event_type: string;
  min_role: RoleGroup;
  is_enabled: boolean;
  updated_at?: string;
}

export interface NotificationLogEntry {
  id: string;
  event_type: string;
  recipients: Array<{ email: string; role: string; status: string; error_detail?: string | null }>;
  subject: string;
  event_metadata: Record<string, unknown> | null;
  status: 'sent' | 'failed' | 'skipped';
  error_detail: string | null;
  created_at: string | null;
}

export function listNotificationEmails(orgId: string): Promise<NotificationEmail[]> {
  return apiFetch(`/org/${orgId}/notifications/emails`);
}

export function addNotificationEmail(
  orgId: string,
  email: string,
  role: RoleGroup,
): Promise<NotificationEmail> {
  return apiFetch(`/org/${orgId}/notifications/emails`, {
    method: 'POST',
    body: JSON.stringify({ email, role }),
  });
}

export function updateNotificationEmail(
  orgId: string,
  emailId: string,
  patch: { role?: RoleGroup; is_enabled?: boolean },
): Promise<NotificationEmail> {
  return apiFetch(`/org/${orgId}/notifications/emails/${emailId}`, {
    method: 'PUT',
    body: JSON.stringify(patch),
  });
}

export function deleteNotificationEmail(orgId: string, emailId: string): Promise<{ message: string }> {
  return apiFetch(`/org/${orgId}/notifications/emails/${emailId}`, { method: 'DELETE' });
}

export function listNotificationSettings(orgId: string): Promise<NotificationSetting[]> {
  return apiFetch(`/org/${orgId}/notifications/settings`);
}

export function updateNotificationSetting(
  orgId: string,
  eventType: string,
  patch: { min_role?: RoleGroup; is_enabled?: boolean },
): Promise<NotificationSetting> {
  return apiFetch(`/org/${orgId}/notifications/settings/${eventType}`, {
    method: 'PUT',
    body: JSON.stringify(patch),
  });
}

export function listNotificationLogs(
  orgId: string,
  params: { limit?: number; event_type?: string | null; status?: string | null;
            from_date?: string | null; to_date?: string | null } = {},
): Promise<NotificationLogEntry[]> {
  return apiFetch(`/org/${orgId}/notifications/logs${qs({ ...params })}`);
}
