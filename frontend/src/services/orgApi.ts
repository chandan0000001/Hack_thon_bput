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
