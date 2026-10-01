import type {
  ActionExecution,
  ActionListResponse,
  Alert,
  AnalysisResult,
  AuditLog,
  DashboardSummary,
  EnforcementPolicy,
  Incident,
  IncidentStatus,
  PolicyListResponse,
  PolicyUpdatePayload,
  ResponseActionCatalog,
  ResponseExecution,
  Severity,
  ThreatModule,
  User,
  UserContext,

  EmailConnectorAccount,
  EmailProviderRegistryEntry,
  ConnectorOperationLog,
  MailMessageSummary,
  ScanResult,
  MessageAnalysis,
  ConnectorSettings,
  QuarantinedItem,
  BlockedSender,
  SecurityEventRecord,
  QuarantineReview,
  NotificationLogEntry,
  TrustedSender,
  ReleaseAndTrustResult,} from '../types';
import { ApiError, apiFetch } from './http';
import {
  mapAlert,
  mapAnalysisResult,
  mapAuditLog,
  mapDashboardSummary,
  mapIncident,
  mapResponseCatalog,
  mapResponseExecution,
} from './mappers';
import { useAuthStore } from '../store/authStore';

// ---------------------------------------------------------------------------
// Service facade — the ONLY module pages import. Every call goes to the live
// backend at VITE_API_BASE_URL (Supabase Auth handled by the auth store).
// ---------------------------------------------------------------------------

export async function login(email: string, password: string): Promise<{ user: User; token: string }> {
  // Real login is performed by the auth store via Supabase Auth.
  await useAuthStore.getState().login(email, password);
  const state = useAuthStore.getState();
  return { user: state.user as User, token: state.accessToken ?? '' };
}

export async function loginWithOAuth(provider: 'google' | 'github'): Promise<void> {
  await useAuthStore.getState().loginWithOAuth(provider);
}

export async function logout(): Promise<void> {
  await useAuthStore.getState().logout();
}

export async function getUserProfile(): Promise<UserContext> {
  return apiFetch('/auth/me');
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const row = await apiFetch('/dashboard/summary');
  return mapDashboardSummary(row);
}

export async function listAlerts(filters?: {
  severity?: Severity;
  module?: ThreatModule;
  status?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<Alert[]> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.module) params.set('module', filters.module);
  if (filters?.status) params.set('status', filters.status);
  if (filters?.search) params.set('search', filters.search);
  if (filters?.limit !== undefined) params.set('limit', String(filters.limit));
  if (filters?.offset !== undefined) params.set('offset', String(filters.offset));
  const rows = await apiFetch(`/alerts?${params.toString()}`);
  return (Array.isArray(rows) ? rows : []).map(mapAlert);
}

export async function getAlert(id: string): Promise<Alert | null> {
  try {
    const row = await apiFetch(`/alerts/${id}`);
    return row ? mapAlert(row) : null;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export async function updateAlertStatus(id: string, status: Alert['status']): Promise<Alert> {
  const row = await apiFetch(`/alerts/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
  return mapAlert(row);
}

// ---------------------------------------------------------------------------
// Analysis pipelines (Part 3-5 backend endpoints)
// ---------------------------------------------------------------------------

export async function analyzeEmail(
  sender: string,
  subject: string,
  body: string,
  rawHeaders?: string
): Promise<AnalysisResult> {
  // raw_headers is optional: the backend only runs SPF/DKIM/DMARC verification
  // when full RFC 5322 headers are supplied.
  const payloadBody: Record<string, unknown> = { sender, subject, body };
  if (rawHeaders?.trim()) payloadBody.raw_headers = rawHeaders;
  const row = await apiFetch('/analysis/email', {
    method: 'POST',
    body: JSON.stringify(payloadBody),
  });
  return mapAnalysisResult(row);
}

export async function analyzeEmailWithAttachment(
  sender: string,
  subject: string,
  body: string,
  attachment: File | null
): Promise<AnalysisResult> {
  // Multipart upload: no Content-Type header so the browser sets the boundary.
  const formData = new FormData();
  formData.append('sender', sender);
  formData.append('subject', subject);
  formData.append('body', body);
  if (attachment) formData.append('file', attachment);
  const row = await apiFetch('/analysis/email-attachment', { method: 'POST', body: formData });
  return mapAnalysisResult(row);
}

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  const row = await apiFetch('/analysis/url', { method: 'POST', body: JSON.stringify({ url }) });
  return mapAnalysisResult(row);
}

export async function analyzeImpersonation(message: string, claimedIdentity: string): Promise<AnalysisResult> {
  const row = await apiFetch('/analysis/impersonation', {
    method: 'POST',
    body: JSON.stringify({ message, claimed_identity: claimedIdentity }),
  });
  return mapAnalysisResult(row);
}

export async function analyzeMedia(file: File): Promise<AnalysisResult> {
  // Multipart upload: no Content-Type header so the browser sets the boundary.
  const formData = new FormData();
  formData.append('file', file);
  const row = await apiFetch('/analysis/media', { method: 'POST', body: formData });
  return mapAnalysisResult(row);
}

export async function analyzeAuthLog(
  events: Array<{ user: string; ip: string; location: string; device: string; status: string; timestamp: string }>
): Promise<AnalysisResult> {
  const row = await apiFetch('/analysis/account-takeover', {
    method: 'POST',
    body: JSON.stringify({ events }),
  });
  return mapAnalysisResult(row);
}

export async function analyzeNetworkFlow(
  flows: Array<{ sourceIp: string; destIp: string; port: number; bytesOut: number; protocol: string }>,
  apiLogs: Array<{ endpoint: string; method: string; statusCode: number; sourceIp: string }> = []
): Promise<AnalysisResult> {
  const row = await apiFetch('/analysis/network', {
    method: 'POST',
    body: JSON.stringify({ flows, api_logs: apiLogs }),
  });
  return mapAnalysisResult(row);
}

export async function analyzeApiLog(
  logs: Array<{ endpoint: string; method: string; statusCode: number; sourceIp: string }>
): Promise<AnalysisResult> {
  const row = await apiFetch('/analysis/network', {
    method: 'POST',
    body: JSON.stringify({ flows: [], api_logs: logs }),
  });
  return mapAnalysisResult(row);
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

export async function listIncidents(): Promise<Incident[]> {
  const rows = await apiFetch('/incidents');
  return (Array.isArray(rows) ? rows : []).map(mapIncident);
}

export async function getIncident(id: string): Promise<Incident | null> {
  try {
    const row = await apiFetch(`/incidents/${id}`);
    return row ? mapIncident(row) : null;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export async function createIncident(alertId: string): Promise<Incident> {
  // The incidents endpoint derives its title/severity from the linked alert.
  const alert = await getAlert(alertId).catch(() => null);
  const row = await apiFetch('/incidents', {
    method: 'POST',
    body: JSON.stringify({
      title: alert?.title ?? `Incident from alert ${alertId}`,
      severity: alert?.severity ?? 'medium',
      linked_alert_ids: [alertId],
    }),
  });
  return mapIncident(row);
}

export async function updateIncidentStatus(id: string, status: IncidentStatus): Promise<Incident> {
  const row = await apiFetch(`/incidents/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
  return mapIncident(row);
}

export async function assignIncident(id: string, analyst: string): Promise<Incident> {
  const row = await apiFetch(`/incidents/${id}/assign`, {
    method: 'PATCH',
    body: JSON.stringify({ assigned_to: analyst }),
  });
  return mapIncident(row);
}

export async function escalateIncident(id: string, reason?: string): Promise<Incident> {
  const row = await apiFetch(`/incidents/${id}/escalate`, {
    method: 'POST',
    body: JSON.stringify({ reason: reason ?? 'Escalated from the SOC console' }),
  });
  return mapIncident(row);
}

// ---------------------------------------------------------------------------
// Response actions
// ---------------------------------------------------------------------------

export async function listResponseCatalog(): Promise<ResponseActionCatalog[]> {
  const rows = await apiFetch('/responses/catalog');
  return (Array.isArray(rows) ? rows : []).map(mapResponseCatalog);
}

export async function executeResponse(actionId: string, target: string, approved: boolean): Promise<ResponseExecution> {
  const row = await apiFetch('/responses/execute', {
    method: 'POST',
    body: JSON.stringify({ catalog_id: actionId, target, approved }),
  });
  return mapResponseExecution(row);
}

export async function listResponseHistory(): Promise<ResponseExecution[]> {
  const rows = await apiFetch('/responses/history');
  return (Array.isArray(rows) ? rows : []).map(mapResponseExecution);
}

// ---------------------------------------------------------------------------
// Audit logs
// ---------------------------------------------------------------------------

export async function listAuditLogs(actorType?: string): Promise<AuditLog[]> {
  const suffix = actorType ? `&actor_type=${encodeURIComponent(actorType)}` : '';
  const rows = await apiFetch(`/audit/logs?limit=200${suffix}`);
  return (Array.isArray(rows) ? rows : []).map(mapAuditLog);
}

async function notAvailable(functionName: string): Promise<never> {
  throw new Error(`${functionName} has no backend endpoint yet`);
}

export async function listLoginEvents(): Promise<import('../types').LoginEvent[]> {
  return notAvailable('listLoginEvents');
}

export async function listNetworkFlows(): Promise<import('../types').NetworkFlow[]> {
  return notAvailable('listNetworkFlows');
}

export async function listApiLogs(): Promise<import('../types').ApiLogEntry[]> {
  return notAvailable('listApiLogs');
}

// ---------------------------------------------------------------------------
// SOC assistant
// ---------------------------------------------------------------------------

export async function assistantChat(message: string): Promise<string> {
  const row = await apiFetch('/assistant/chat', {
    method: 'POST',
    body: JSON.stringify({ message }),
  });
  const record = row && typeof row === 'object' ? (row as Record<string, unknown>) : {};
  return String(record.reply ?? 'The assistant is temporarily unable to generate a response.');
}

export async function addAlert(_alert: Alert): Promise<void> {
  return notAvailable('addAlert');
}



// ---------------------------------------------------------------------------
// Email Connectors (Phase 1-2: Gmail only)
// ---------------------------------------------------------------------------

export async function listConnectorCapabilities(): Promise<EmailProviderRegistryEntry[]> {
  const res = await apiFetch('/connectors/capabilities');
  return res.items as EmailProviderRegistryEntry[];
}

export async function listEmailConnectors(): Promise<EmailConnectorAccount[]> {
  const res = await apiFetch('/connectors');
  return res.items as EmailConnectorAccount[];
}

export interface GmailAccountItem {
  id: string;
  email: string;
  status: 'connected' | 'paused' | 'disconnected' | 'purged' | string;
  disconnected_at?: string | null;
  paused_at?: string | null;
  last_push_at?: string | null;
  removes_at?: string | null;
  created_at?: string | null;
  last_sync_at?: string | null;
  sync_status?: string | null;
  last_error?: string | null;
}

export interface GmailAccountsResponse {
  connected: GmailAccountItem[];
  recent: GmailAccountItem[];
}

export async function listGmailAccounts(now?: string): Promise<GmailAccountsResponse> {
  const query = now ? `?now=${encodeURIComponent(now)}` : '';
  const res = await apiFetch(`/connectors/gmail/accounts${query}`);
  return res as GmailAccountsResponse;
}

export async function earlyRemoveGmailAccount(id: string): Promise<void> {
  await apiFetch(`/connectors/gmail/accounts/${id}`, { method: 'DELETE' });
}

export async function disconnectGmailAccount(id: string): Promise<void> {
  await apiFetch(`/connectors/gmail/accounts/${id}/disconnect`, { method: 'POST' });
}

export async function pauseGmailAccount(id?: string): Promise<{ success: boolean; status: string; message: string }> {
  const path = id ? `/connectors/gmail/accounts/${id}/pause` : '/connectors/gmail/pause';
  return (await apiFetch(path, { method: 'POST' })) as { success: boolean; status: string; message: string };
}

export async function resumeGmailAccount(id?: string): Promise<{ success: boolean; status: string; message: string }> {
  const path = id ? `/connectors/gmail/accounts/${id}/resume` : '/connectors/gmail/resume';
  return (await apiFetch(path, { method: 'POST' })) as { success: boolean; status: string; message: string };
}

export async function authorizeGmailConnector(redirectAfter?: string, reconnect?: string): Promise<string> {
  const body: { redirect_after?: string; reconnect?: string } = {};
  if (redirectAfter) body.redirect_after = redirectAfter;
  if (reconnect) body.reconnect = reconnect;
  const res = await apiFetch('/connectors/gmail/authorize', {
    method: 'POST',
    body: JSON.stringify(body),
  });
  return res.authorization_url as string;
}

export async function testEmailConnector(
  id: string,
): Promise<{ ok: boolean; email_address?: string; messages_total?: number; message?: string }> {
  return (await apiFetch(`/connectors/${id}/test`, { method: 'POST' })) as {
    ok: boolean;
    message?: string;
  };
}

export async function disconnectEmailConnector(id: string): Promise<void> {
  await apiFetch(`/connectors/${id}`, { method: 'DELETE' });
}

export async function listConnectorOperations(): Promise<ConnectorOperationLog[]> {
  const res = await apiFetch('/connectors/operations');
  return res.items as ConnectorOperationLog[];
}


// --- Mailbox scanning (Phase 3) — analysis only; enforcement is Phase 4 ---

export async function listConnectorMessages(
  connectorId: string,
  limit = 20,
): Promise<MailMessageSummary[]> {
  return (await apiFetch(`/connectors/${connectorId}/messages?limit=${limit}`)) as MailMessageSummary[];
}

export async function scanConnectorMessages(
  connectorId: string,
  body: { message_ids?: string[]; scan_recent?: number },
): Promise<ScanResult[]> {
  return (await apiFetch(`/connectors/${connectorId}/scan`, {
    method: 'POST',
    body: JSON.stringify(body),
  })) as ScanResult[];
}

export async function getMessageAnalysis(
  connectorId: string,
  messageId: string,
): Promise<MessageAnalysis> {
  return (await apiFetch(`/connectors/${connectorId}/messages/${messageId}/analysis`)) as MessageAnalysis;
}


// --- Enforcement (Phase 4) — real provider-backed actions ---

export async function getConnectorSettings(connectorId: string): Promise<ConnectorSettings> {
  return (await apiFetch(`/connectors/${connectorId}/settings`)) as ConnectorSettings;
}

export async function updateConnectorSettings(
  connectorId: string,
  patch: {
    quarantine_expiry_hours?: number | null;
    expiry_mode?: 'hours' | 'manual';
    permanent_delete_enabled?: boolean;
    auto_quarantine_enabled?: boolean;
  },
): Promise<ConnectorSettings> {
  return (await apiFetch(`/connectors/${connectorId}/settings`, {
    method: 'PUT',
    body: JSON.stringify(patch),
  })) as ConnectorSettings;
}

export async function listQuarantined(): Promise<QuarantinedItem[]> {
  const res = await apiFetch('/enforcement/quarantine');
  return res.items as QuarantinedItem[];
}

export async function releaseQuarantined(itemId: string): Promise<string> {
  const res = await apiFetch(`/enforcement/quarantine/${itemId}/release`, { method: 'POST' });
  return res.status as string;
}

export async function deleteQuarantined(itemId: string): Promise<{ status: string; message?: string }> {
  return (await apiFetch(`/enforcement/quarantine/${itemId}/delete`, { method: 'POST' })) as {
    status: string;
    message?: string;
  };
}

export async function listBlockedSenders(): Promise<BlockedSender[]> {
  const res = await apiFetch('/enforcement/blocked-senders');
  return res.items as BlockedSender[];
}

export async function unblockSender(blockId: string): Promise<string> {
  const res = await apiFetch(`/enforcement/blocked-senders/${blockId}/release`, { method: 'POST' });
  return res.status as string;
}

export async function releaseAndTrustQuarantined(itemId: string): Promise<ReleaseAndTrustResult> {
  return (await apiFetch(`/enforcement/quarantine/${itemId}/release-and-trust`, {
    method: 'POST',
  })) as ReleaseAndTrustResult;
}

export async function listTrustedSenders(): Promise<TrustedSender[]> {
  const res = await apiFetch('/enforcement/trusted-senders');
  return res.items as TrustedSender[];
}

export async function trustSender(senderEmail: string, reason: string): Promise<TrustedSender> {
  return (await apiFetch('/enforcement/trusted-senders', {
    method: 'POST',
    body: JSON.stringify({ sender_email: senderEmail, reason }),
  })) as TrustedSender;
}

export async function removeTrustedSender(senderId: string): Promise<string> {
  const res = await apiFetch(`/enforcement/trusted-senders/${senderId}`, { method: 'DELETE' });
  return res.status as string;
}

export interface ProcessedEmailActivity {
  id: string;
  gmail_message_id: string;
  sender: string | null;
  subject: string | null;
  received_at: string | null;
  processing_status: string;
  risk_score: number | null;
  classification: string | null;
  enforcement_status: string | null;
  enforcement_detail: string | null;
  created_at: string;
  updated_at: string;
}

export interface IngestionActivity {
  connected_mailboxes: Array<{
    id: string;
    email: string;
    provider: string;
    status: string;
    last_sync_at: string | null;
    last_error: string | null;
  }>;
  recent_emails: ProcessedEmailActivity[];
  recent_jobs: Array<{
    id: string;
    job_id: string;
    job_type: string;
    status: string;
    error: string | null;
    created_at: string;
    updated_at: string;
  }>;
  summary: {
    total_processed: number;
    threats_detected: number;
    quarantined: number;
  };
}

export async function getIngestionActivity(limit: number = 20): Promise<IngestionActivity> {
  return (await apiFetch(`/connectors/activity?limit=${limit}`)) as IngestionActivity;
}


// --- Security history (Phase 5) ---

export interface SecurityHistoryFilters {
  event_type?: string;
  actor_type?: string;
  severity?: string;
  sender_email?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export async function listSecurityHistory(
  filters: SecurityHistoryFilters = {},
): Promise<{ items: SecurityEventRecord[]; total: number; limit: number; offset: number }> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
  }
  return (await apiFetch(`/security-history?${params.toString()}`)) as {
    items: SecurityEventRecord[];
    total: number;
    limit: number;
    offset: number;
  };
}

export async function getQuarantineReview(itemId: string): Promise<QuarantineReview> {
  return (await apiFetch(`/quarantine/${itemId}/review`)) as QuarantineReview;
}

export async function keepQuarantined(itemId: string): Promise<string> {
  const res = await apiFetch(`/enforcement/quarantine/${itemId}/keep`, { method: 'POST' });
  return res.status as string;
}

// --- Notifications (Phase 7) ---

export async function listNotificationLogs(): Promise<NotificationLogEntry[]> {
  const res = await apiFetch('/notifications');
  return res.items as NotificationLogEntry[];
}

export async function updateNotificationEmail(email: string | null): Promise<string | null> {
  const res = await apiFetch('/auth/notification-email', {
    method: 'PUT',
    body: JSON.stringify({ notification_email: email }),
  });
  return res.notification_email as string | null;
}

// ---------------------------------------------------------------------------
// Dual-Mode Enforcement — action executions, quarantine, blocklist, policies
// ---------------------------------------------------------------------------

export async function listActions(params?: {
  status?: string;
  action_type?: string;
  module?: string;
  severity?: string;
  page?: number;
  page_size?: number;
}): Promise<ActionListResponse> {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.action_type) query.set('action_type', params.action_type);
  if (params?.module) query.set('module', params.module);
  if (params?.severity) query.set('severity', params.severity);
  if (params?.page) query.set('page', String(params.page));
  if (params?.page_size) query.set('page_size', String(params.page_size));
  return apiFetch(`/actions?${query.toString()}`);
}

export async function getAction(id: string): Promise<ActionExecution> {
  return apiFetch(`/actions/${id}`);
}

export async function approveAction(id: string, comment?: string): Promise<ActionExecution> {
  return apiFetch(`/actions/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify({ comment: comment ?? null }),
  });
}

export async function rejectAction(id: string, reason: string): Promise<ActionExecution> {
  return apiFetch(`/actions/${id}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export async function listQuarantine(page?: number, pageSize?: number): Promise<ActionListResponse> {
  const query = new URLSearchParams();
  if (page) query.set('page', String(page));
  if (pageSize) query.set('page_size', String(pageSize));
  return apiFetch(`/actions/quarantine/list?${query.toString()}`);
}

export async function releaseQuarantine(id: string): Promise<ActionExecution> {
  return apiFetch(`/actions/quarantine/${id}/release`, { method: 'POST' });
}

export async function listBlocklist(page?: number, pageSize?: number): Promise<ActionListResponse> {
  const query = new URLSearchParams();
  if (page) query.set('page', String(page));
  if (pageSize) query.set('page_size', String(pageSize));
  return apiFetch(`/actions/blocklist/list?${query.toString()}`);
}

export async function unblockItem(id: string): Promise<ActionExecution> {
  return apiFetch(`/actions/blocklist/${id}/unblock`, { method: 'POST' });
}

export async function listPolicies(): Promise<PolicyListResponse> {
  return apiFetch('/policies');
}

export async function getPolicy(id: string): Promise<EnforcementPolicy> {
  return apiFetch(`/policies/${id}`);
}

export async function updatePolicy(id: string, updates: PolicyUpdatePayload): Promise<EnforcementPolicy> {
  return apiFetch(`/policies/${id}`, {
    method: 'PUT',
    body: JSON.stringify(updates),
  });
}

export async function activatePolicy(id: string): Promise<EnforcementPolicy> {
  return apiFetch(`/policies/${id}/activate`, { method: 'POST' });
}

// ---------------------------------------------------------------------------
// Dead Letter Queue (DLQ) Ops (RT-10)
// ---------------------------------------------------------------------------

export async function getDlqStats(): Promise<import('../types').DlqStats> {
  return apiFetch('/dlq/stats');
}

export async function getDlqJobs(params?: {
  job_type?: string;
  from_date?: string;
  to_date?: string;
  owner_user_id?: string;
  limit?: number;
  offset?: number;
}): Promise<import('../types').DlqJobsResponse> {
  const query = new URLSearchParams();
  if (params?.job_type) query.set('job_type', params.job_type);
  if (params?.from_date) query.set('from_date', params.from_date);
  if (params?.to_date) query.set('to_date', params.to_date);
  if (params?.owner_user_id) query.set('owner_user_id', params.owner_user_id);
  if (params?.limit !== undefined) query.set('limit', String(params.limit));
  if (params?.offset !== undefined) query.set('offset', String(params.offset));
  const qs = query.toString();
  return apiFetch(`/dlq/jobs${qs ? `?${qs}` : ''}`);
}

export async function getDlqJob(jobId: string): Promise<import('../types').DlqJob> {
  return apiFetch(`/dlq/jobs/${jobId}`);
}

export async function retryDlqJob(jobId: string): Promise<{ success: boolean; message: string }> {
  return apiFetch(`/dlq/jobs/${jobId}/retry`, { method: 'POST' });
}

export async function deleteDlqJob(jobId: string): Promise<{ success: boolean; message: string }> {
  return apiFetch(`/dlq/jobs/${jobId}`, { method: 'DELETE' });
}
