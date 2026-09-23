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
