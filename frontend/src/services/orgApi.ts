import { apiFetch } from './http';
import type { Organization, Project, ProjectStatus } from '../types';

export interface CreateOrgPayload {
  name: string;
}

export interface CreateProjectPayload {
  name: string;
  slug?: string;
}

export interface UpdateProjectPayload {
  name?: string;
  status?: ProjectStatus;
}

export interface OrgInfo {
  id: string;
  name: string;
  owner_id: string;
  status: string;
  role: 'admin' | 'analyst' | 'viewer';
  projects_count: number;
  members_count: number;
  created_at: string;
}

export interface OrgMemberRow {
  id: string;
  organization_id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: 'admin' | 'analyst' | 'viewer';
  joined_at: string;
}

export type ApiKeyRole = 'master' | 'viewer';

/** MEMBER-INVITE-P2: row of GET /orgs/{id}/invitations (token_hash never leaves the backend). */
export interface Invitation {
  id: string;
  organization_id: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  status: 'pending' | 'accepted' | 'expired' | 'revoked';
  invited_by: string;
  expires_at: string;
  accepted_at: string | null;
  created_at: string;
}

/** MEMBER-INVITE-P1: POST /orgs/{id}/members response — the raw token is
 * returned exactly once and only ever lives in this payload. */
export interface CreatedInvitation extends Invitation {
  token: string;
}

/** POST /invitations/accept response. */
export interface AcceptanceResult {
  organization_id: string;
  organization_name: string;
  role: 'admin' | 'analyst' | 'viewer';
  member_id: string;
  joined_at: string;
}

/** ORG-DASHBOARD-P1: seed shape of GET .../counters/initial (then realtime-only deltas). */
export interface OrgCounters {
  total_24h: number;
  by_severity: { critical: number; high: number; medium: number; low: number };
  by_type: { log: number; ato: number; network: number };
  pending_review: number;
  blocked_indicators_count: number;
}

/** Row of GET .../events (subset used by the dashboard overview table). */
export interface OrgEventRow {
  id: string;
  event_type: string;
  severity: string;
  verdict: string;
  source: string;
  created_at: string;
  analysis_result?: { risk_score?: number } | null;
}

/** ORG-DASHBOARD-P2: full event inspection payload. */
export interface OrgEventDetail {
  id: string;
  project_id: string;
  organization_id: string;
  event_type: string;
  severity: string;
  source: string;
  raw_data: unknown;
  analysis_result: {
    risk_score?: number;
    severity?: string;
    indicators?: Array<Record<string, unknown>>;
    mitre?: Array<{ id?: string; name?: string }>;
    engine?: string;
    available?: boolean;
    explanation?: string | null;
  } | null;
  verdict: string;
  user_action: string | null;
  acted_by: string | null;
  acted_at: string | null;
  created_at: string;
  indicator_blocked: boolean;
}

/** Row of GET /org/{org}/blocked-indicators. */
export interface OrgBlockedIndicatorRow {
  id: string;
  indicator_type: string;
  indicator_value: string;
  reason: string;
  blocked_by: string | null;
  blocked_at: string;
}

/** ORG-DASHBOARD-P3: events-list filter set (server contract names). Pure
 * implementations live in eventsListHelpers (node:test importable);
 * re-exported for service-layer consumers. */
import { eventsQueryParams, type EventsListFilters } from '../pages/eventsListHelpers';
export { appendEvents, eventsQueryParams, type EventsListFilters } from '../pages/eventsListHelpers';

export interface ProjectApiKey {
  id: string;
  project_id: string;
  organization_id: string;
  name: string;
  role: ApiKeyRole;
  key_prefix: string;
  status: 'active' | 'revoked';
  last_used_at: string | null;
  created_at: string;
}

/** Create-key response — api_key (plaintext) is returned exactly once. */
export interface CreatedProjectKey extends ProjectApiKey {
  api_key: string;
}

/** SCENARIO-3: baseline profile submitted with the ATO analysis. */
export interface AtoBaseline {
  user?: string;
  role?: string;
  typical_login_start?: string;
  typical_login_end?: string;
  home_country?: string;
  known_ips?: string[];
  known_devices?: string[];
}

/** SCENARIO-3: one suspicious activity event in the attack timeline. */
export interface AtoSuspiciousEvent {
  timestamp?: string;
  event_type?: string;
  source_ip?: string;
  country?: string;
  device_id?: string;
  failed_attempts?: number;
  files_accessed?: number;
  detail?: string;
  [key: string]: unknown;
}

/** POST /analysis/account-takeover response (org flow). The organization is
 * resolved server-side from the credential — never from the request body. */
export interface AtoAnalysisResult {
  verdict: string;
  risk_level: string;
  risk_score: number;
  account_id?: string | null;
  indicators: Array<{
    type: string;
    severity: string;
    description: string;
    signal: string;
    source?: string;
  }>;
  suspicious_events: Array<AtoSuspiciousEvent & { flagged?: string[]; event_score?: number }>;
  recommended_actions: string[];
  threat_intel?: { watchlist_size: number; hits: string[] };
  explanation?: string | null;
  organization: { id: string; name: string };
  project: { id: string } | null;
  event_id: string;
  alert_id: string;
}

/** SCENARIO-3 request body: baseline + abnormal timeline. orgId only rides
 * the validated X-Organization-Id header (membership-checked server-side),
 * never the body. */
export interface AtoAnalysisPayload {
  source?: string;
  account_id?: string;
  baseline_profile?: AtoBaseline;
  suspicious_events?: AtoSuspiciousEvent[];
}

export const orgApi = {
  // SCENARIO-3: org-scoped account-takeover analysis. The org scope is
  // resolved server-side from the JWT (X-Organization-Id is membership-
  // validated like every other org endpoint); the body carries no org id.
  async analyzeAccountTakeover(
    orgId: string,
    payload: AtoAnalysisPayload
  ): Promise<AtoAnalysisResult> {
    return apiFetch('/analysis/account-takeover', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers: { 'X-Organization-Id': orgId },
    });
  },

  // List organizations for current user
  async listOrgs(): Promise<Organization[]> {
    const data = await apiFetch('/orgs');
    return data.organizations || [];
  },

  // Create organization
  async createOrg(name: string): Promise<Organization> {
    return apiFetch('/orgs', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  },

  // ORG-DASHBOARD-P1: one-time seed fetch for live counters (then realtime only)
  async getInitialCounters(orgId: string, projectId: string): Promise<OrgCounters> {
    return apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/counters/initial`
    );
  },

  // ORG-DASHBOARD-P1: recent events for the dashboard overview table
  async listRecentEvents(orgId: string, projectId: string, limit = 10): Promise<OrgEventRow[]> {
    const data = await apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/events?limit=${limit}`
    );
    return data.events || [];
  },

  // ORG-DASHBOARD-P2: full event inspection
  async getEventDetail(orgId: string, projectId: string, eventId: string): Promise<OrgEventDetail> {
    return apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/events/${encodeURIComponent(eventId)}`
    );
  },

  // ORG-DASHBOARD-P2: triage action (backend contract: {action}, not {user_action})
  async updateEventVerdict(
    orgId: string,
    projectId: string,
    eventId: string,
    action: 'released' | 'blocked_permanently' | 'false_positive'
  ): Promise<{ id: string; verdict: string; user_action: string | null; acted_by: string | null; acted_at: string | null }> {
    return apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/events/${encodeURIComponent(eventId)}`,
      { method: 'PATCH', body: JSON.stringify({ action }) }
    );
  },

  // ORG-DASHBOARD-P2: blocked-indicator lookup (q is substring; exact-match client-side)
  async listBlockedIndicators(orgId: string, q?: string): Promise<OrgBlockedIndicatorRow[]> {
    const query = q ? `?q=${encodeURIComponent(q)}` : '';
    const data = await apiFetch(`/orgs/${encodeURIComponent(orgId)}/blocked-indicators${query}`);
    return data.indicators || [];
  },

  // ORG-DASHBOARD-P3: filtered event list (offset pagination; server contract:
  // event_type/severity/verdict/q + limit(1..200)/offset -> {total, events})
  async listEvents(
    orgId: string,
    projectId: string,
    filters: EventsListFilters = {},
  ): Promise<{ total: number; events: OrgEventRow[] }> {
    const params = eventsQueryParams(filters);
    const data = await apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/events${params}`
    );
    return { total: Number(data.total ?? 0), events: data.events || [] };
  },

  // List projects for an organization
  async listProjects(orgId: string, status?: string): Promise<Project[]> {
    const query = status && status !== 'all' ? `?status=${encodeURIComponent(status)}` : '';
    const data = await apiFetch(`/orgs/${encodeURIComponent(orgId)}/projects${query}`);
    return data.projects || [];
  },

  // Get a single project (403 for non-members, 404 for missing)
  async getProject(orgId: string, projectId: string): Promise<Project> {
    return apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}`
    );
  },

  // Get organization info (includes viewer's role + member count)
  async getOrg(orgId: string): Promise<OrgInfo> {
    return apiFetch(`/orgs/${encodeURIComponent(orgId)}`);
  },

  // List organization members
  async listMembers(orgId: string): Promise<OrgMemberRow[]> {
    const data = await apiFetch(`/orgs/${encodeURIComponent(orgId)}/members`);
    return data.members || [];
  },

  // Invite a member (admin only) — MEMBER-INVITE-P1: issues a single-use
  // token invitation; the raw `token` in the response is plaintext-once.
  async inviteMember(orgId: string, email: string, role: string): Promise<CreatedInvitation> {
    return apiFetch(`/orgs/${encodeURIComponent(orgId)}/members`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    });
  },

  // List organization invitations (admin only)
  async listInvitations(orgId: string): Promise<Invitation[]> {
    const data = await apiFetch(`/orgs/${encodeURIComponent(orgId)}/invitations`);
    return data.invitations || [];
  },

  // Revoke a pending invitation (admin only)
  async revokeInvitation(orgId: string, invitationId: string): Promise<void> {
    await apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/invitations/${encodeURIComponent(invitationId)}`,
      { method: 'DELETE' }
    );
  },

  // Redeem an invitation token (authenticated; email must match the invite)
  async acceptInvitation(token: string): Promise<AcceptanceResult> {
    return apiFetch('/invitations/accept', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  },

  // Change a member's role (admin only)
  async updateMemberRole(orgId: string, memberId: string, role: string): Promise<void> {
    await apiFetch(`/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  },

  // Remove a member (admin only)
  async removeMember(orgId: string, memberId: string): Promise<void> {
    await apiFetch(`/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}`, {
      method: 'DELETE',
    });
  },

  // Delete a project (admin only; exact confirm_name required, 409 on mismatch)
  async deleteProject(orgId: string, projectId: string, confirmName: string): Promise<void> {
    await apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}`,
      { method: 'DELETE', body: JSON.stringify({ confirm_name: confirmName }) }
    );
  },

  // List project API keys (admin only; plaintext and hash are never returned)
  async listKeys(orgId: string, projectId: string): Promise<ProjectApiKey[]> {
    const data = await apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/keys`
    );
    return data.keys || [];
  },

  // Generate a project key (admin only). Response carries the plaintext
  // `api_key` exactly once; the slot model allows one active key per role.
  async createKey(
    orgId: string,
    projectId: string,
    name: string,
    role: ApiKeyRole
  ): Promise<CreatedProjectKey> {
    return apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/keys`,
      { method: 'POST', body: JSON.stringify({ name, role }) }
    );
  },

  // Revoke a project key (admin only); revoking frees the role's slot
  async revokeKey(orgId: string, projectId: string, keyId: string): Promise<void> {
    await apiFetch(
      `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/keys/${encodeURIComponent(keyId)}/revoke`,
      { method: 'POST' }
    );
  },

  // Create project in organization
  async createProject(orgId: string, payload: CreateProjectPayload): Promise<Project> {
    return apiFetch(`/orgs/${encodeURIComponent(orgId)}/projects`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Update project status or name
  async updateProject(
    orgId: string,
    projectId: string,
    payload: UpdateProjectPayload
  ): Promise<Project> {
    return apiFetch(`/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  // Switch active organization
  async switchOrg(orgId: string): Promise<void> {
    try {
      await apiFetch('/auth/switch-org', {
        method: 'POST',
        body: JSON.stringify({ organization_id: orgId }),
      });
    } catch {
      // Backend handles fallback
    }
  },

  // Switch active project
  async switchProject(projectId: string): Promise<void> {
    try {
      await apiFetch('/auth/switch-project', {
        method: 'POST',
        body: JSON.stringify({ project_id: projectId }),
      });
    } catch {
      // Backend handles fallback
    }
  },
};
