/**
 * Organization APIs client (B4 endpoints).
 * Connects to session-scoped org endpoints with JWT authentication.
 */

import { apiFetch } from './http';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export interface OrgOrganization {
  id: string;
  name: string;
  owner_id: string;
  status: string;
  role?: string;
  created_at: string;
  projects_count?: number;
  members_count?: number;
}

export interface OrgProject {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  status: string;
  created_at: string;
}

export interface OrgApiKey {
  id: string;
  project_id: string;
  organization_id: string;
  name: string;
  role: 'master' | 'viewer';
  key_prefix: string;
  status: string;
  last_used_at: string | null;
  created_at: string;
}

export interface OrgApiKeyCreated extends OrgApiKey {
  /** Plaintext token returned exactly ONCE upon generation */
  api_key: string;
}

export interface OrgMember {
  id: string;
  organization_id: string;
  user_id: string;
  email: string;
  full_name?: string;
  role: 'admin' | 'analyst' | 'viewer';
  joined_at: string;
}

export interface OrgEvent {
  id: string;
  project_id: string;
  organization_id: string;
  event_type: string;
  severity: string;
  source: string;
  raw_data: Record<string, unknown> | unknown;
  analysis_result: Record<string, unknown> | unknown;
  verdict: 'pending_review' | 'released' | 'blocked_permanently' | 'false_positive';
  user_action?: string | null;
  acted_by?: string | null;
  acted_at?: string | null;
  created_at: string;
  indicator_blocked?: boolean;
}

export interface OrgBlockedIndicator {
  id: string;
  organization_id: string;
  project_id?: string | null;
  indicator_type: 'ip' | 'domain' | 'email' | 'hash' | 'actor';
  indicator_value: string;
  reason?: string | null;
  blocked_by?: string | null;
  blocked_at: string;
}

export interface OrgLiveCountersData {
  total_24h: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  by_type: {
    log: number;
    ato: number;
    network: number;
  };
  pending_review: number;
  blocked_indicators_count: number;
}

export interface AnalyzerSummary {
  name: string;
  engine: string;
  available: boolean;
  count_24h: number;
}

export interface OrgDashboardData {
  analyzers: {
    log: AnalyzerSummary;
    ato: AnalyzerSummary;
    network: AnalyzerSummary;
  };
  total_24h: number;
  severity_mix: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  pending_review: number;
  blocked_indicators_count: number;
  last_event_at: string | null;
  recent_events: Array<{
    id: string;
    project_id: string;
    event_type: string;
    severity: string;
    verdict: string;
    created_at: string;
  }>;
}

// ─────────────────────────────────────────────────────────────
// API Methods
// ─────────────────────────────────────────────────────────────

export const orgApi = {
  // --- Organizations & Members ---
  async getOrganizations(): Promise<OrgOrganization[]> {
    const data = await apiFetch('/orgs');
    return Array.isArray(data) ? data : data.organizations ?? [];
  },

  async getOrganization(orgId: string): Promise<OrgOrganization> {
    return apiFetch(`/orgs/${orgId}`);
  },

  async createOrganization(name: string): Promise<OrgOrganization> {
    return apiFetch('/orgs', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  },

  async updateOrganization(orgId: string, name: string): Promise<{ id: string; name: string }> {
    return apiFetch(`/orgs/${orgId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name }),
    });
  },

  async listMembers(orgId: string): Promise<OrgMember[]> {
    const data = await apiFetch(`/orgs/${orgId}/members`);
    return data.members ?? [];
  },

  async addMember(orgId: string, email: string, role: string): Promise<OrgMember> {
    return apiFetch(`/orgs/${orgId}/members`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    });
  },

  async updateMemberRole(orgId: string, memberId: string, role: string): Promise<{ id: string; role: string }> {
    return apiFetch(`/orgs/${orgId}/members/${memberId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  },

  async removeMember(orgId: string, memberId: string): Promise<{ status: string }> {
    return apiFetch(`/orgs/${orgId}/members/${memberId}`, {
      method: 'DELETE',
    });
  },

  // --- Projects ---
  async listProjects(orgId: string, status?: string): Promise<OrgProject[]> {
    const q = status ? `?status=${encodeURIComponent(status)}` : '';
    const data = await apiFetch(`/orgs/${orgId}/projects${q}`);
    return data.projects ?? [];
  },

  async createProject(orgId: string, name: string, slug?: string): Promise<OrgProject> {
    return apiFetch(`/orgs/${orgId}/projects`, {
      method: 'POST',
      body: JSON.stringify({ name, slug: slug || undefined }),
    });
  },

  async getProject(orgId: string, projectId: string): Promise<OrgProject> {
    return apiFetch(`/orgs/${orgId}/projects/${projectId}`);
  },

  async updateProject(
    orgId: string,
    projectId: string,
    payload: { name?: string; status?: string }
  ): Promise<OrgProject> {
    return apiFetch(`/orgs/${orgId}/projects/${projectId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  // --- API Keys ---
  async listProjectApiKeys(orgId: string, projectId: string): Promise<OrgApiKey[]> {
    const data = await apiFetch(`/orgs/${orgId}/projects/${projectId}/keys`);
    return data.keys ?? [];
  },

  async createProjectApiKey(
    orgId: string,
    projectId: string,
    name: string,
    role: 'master' | 'viewer'
  ): Promise<OrgApiKeyCreated> {
    return apiFetch(`/orgs/${orgId}/projects/${projectId}/keys`, {
      method: 'POST',
      body: JSON.stringify({ name, role }),
    });
  },

  async revokeProjectApiKey(
    orgId: string,
    projectId: string,
    keyId: string
  ): Promise<{ status: string; id: string }> {
    return apiFetch(`/orgs/${orgId}/projects/${projectId}/keys/${keyId}/revoke`, {
      method: 'POST',
    });
  },

  // --- Events ---
  async listEvents(
    orgId: string,
    params?: {
      projectId?: string;
      eventType?: string;
      severity?: string;
      verdict?: string;
      q?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ total: number; events: OrgEvent[] }> {
    const search = new URLSearchParams();
    if (params?.projectId) search.set('project_id', params.projectId);
    if (params?.eventType) search.set('event_type', params.eventType);
    if (params?.severity) search.set('severity', params.severity);
    if (params?.verdict) search.set('verdict', params.verdict);
    if (params?.q) search.set('q', params.q);
    if (params?.limit) search.set('limit', String(params.limit));
    if (params?.offset) search.set('offset', String(params.offset));

    const path = params?.projectId
      ? `/orgs/${orgId}/projects/${params.projectId}/events?${search.toString()}`
      : `/orgs/${orgId}/events?${search.toString()}`;
    return apiFetch(path);
  },

  async getEventDetail(orgId: string, projectId: string, eventId: string): Promise<OrgEvent> {
    return apiFetch(`/orgs/${orgId}/projects/${projectId}/events/${eventId}`);
  },

  async updateEventVerdict(
    orgId: string,
    projectId: string,
    eventId: string,
    action: 'released' | 'blocked_permanently' | 'false_positive',
    reason?: string
  ): Promise<{ id: string; verdict: string; user_action: string; acted_by?: string; acted_at?: string }> {
    return apiFetch(`/orgs/${orgId}/projects/${projectId}/events/${eventId}`, {
      method: 'PATCH',
      body: JSON.stringify({ action, reason }),
    });
  },

  // --- Blocked Indicators ---
  async listBlockedIndicators(
    orgId: string,
    params?: { indicatorType?: string; q?: string }
  ): Promise<OrgBlockedIndicator[]> {
    const search = new URLSearchParams();
    if (params?.indicatorType) search.set('indicator_type', params.indicatorType);
    if (params?.q) search.set('q', params.q);
    const data = await apiFetch(`/orgs/${orgId}/blocked-indicators?${search.toString()}`);
    return data.indicators ?? [];
  },

  async addBlockedIndicator(
    orgId: string,
    payload: {
      indicator_type: 'ip' | 'domain' | 'email' | 'hash' | 'actor';
      indicator_value: string;
      reason?: string;
      project_id?: string;
    }
  ): Promise<OrgBlockedIndicator> {
    return apiFetch(`/orgs/${orgId}/blocked-indicators`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async deleteBlockedIndicator(
    orgId: string,
    indicatorId: string
  ): Promise<{ status: string; id: string }> {
    return apiFetch(`/orgs/${orgId}/blocked-indicators/${indicatorId}`, {
      method: 'DELETE',
    });
  },

  // --- Counters Initial Seed ---
  async getInitialCounters(orgId: string, projectId: string): Promise<OrgLiveCountersData> {
    return apiFetch(`/orgs/${orgId}/projects/${projectId}/counters/initial`);
  },

  // --- Dashboard Overview ---
  async getDashboardOverview(orgId: string, projectId?: string): Promise<OrgDashboardData> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return apiFetch(`/orgs/${orgId}/dashboard${q}`);
  },
};

// Top-level aliases for flexible imports
export type Project = OrgProject;
export type Organization = OrgOrganization;
export type ApiKey = OrgApiKey;
export type ApiKeyCreated = OrgApiKeyCreated;
export type Member = OrgMember;
export type Event = OrgEvent;
export type BlockedIndicator = OrgBlockedIndicator;
export type LiveCountersData = OrgLiveCountersData;

export const listProjects = orgApi.listProjects.bind(orgApi);
export const getProjects = orgApi.listProjects.bind(orgApi);
export const getOrganizations = orgApi.getOrganizations.bind(orgApi);
export const getOrganization = orgApi.getOrganization.bind(orgApi);
export const createProject = orgApi.createProject.bind(orgApi);
export const listEvents = orgApi.listEvents.bind(orgApi);
export const getDashboardOverview = orgApi.getDashboardOverview.bind(orgApi);

