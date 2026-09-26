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

export const orgApi = {
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

  // Add/invite a member (admin only)
  async addMember(orgId: string, email: string, role: string): Promise<OrgMemberRow> {
    return apiFetch(`/orgs/${encodeURIComponent(orgId)}/members`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
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
