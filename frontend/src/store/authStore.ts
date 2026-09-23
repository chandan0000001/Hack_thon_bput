import { create } from 'zustand';
import { getSupabase } from '../lib/supabaseClient';
import type { Organization, OrganizationRole, User } from '../types';

const ACTIVE_ORG_KEY = 'cyberguard_active_org';
const ACTIVE_PROJECT_KEY = 'cyberguard_active_project';
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

export type Role = OrganizationRole;
export type Permission = 'analyze' | 'mutate' | 'admin';

const ROLE_LEVELS: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };
const PERMISSION_MIN_ROLE: Record<Permission, Role> = {
  analyze: 'analyst',
  mutate: 'analyst',
  admin: 'admin',
};

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  /** True once hydrate() has finished (session restored or absent). */
  hydrated: boolean;
  role: Role;
  fullName: string | null;
  username: string | null;
  /** Address that receives system notifications (never a connected mailbox). */
  notificationEmail: string | null;
  /** Organization accounts are frozen server-side (ORG_ENABLED=false). */
  orgEnabled: boolean;
  organizations: Organization[];
  activeOrganization: Organization | null;
  activeOrganizationId: string | null;
  /** ORG-REDESIGN: selected project inside the active org (org scope only). */
  activeProjectId: string | null;
  activeProject: { id: string; name: string; slug: string } | null;

  login: (email: string, password: string) => Promise<void>;
  loginWithOAuth: (provider: 'google' | 'github') => Promise<void>;
  signUp: (
    fullName: string,
    email: string,
    password: string,
    username: string,
  ) => Promise<{ confirmationPending: boolean }>;
  registerOrg: (
    email: string,
    password: string,
    orgName: string,
    name?: string,
  ) => Promise<{ confirmationPending: boolean; organization?: any }>;
  requestPasswordReset: (email: string) => Promise<void>;
  completePasswordReset: (newPassword: string) => Promise<void>;
  logout: () => Promise<void>;
  hydrate: () => Promise<void>;
  fetchUserContext: () => Promise<void>;
  switchOrganization: (orgId: string) => Promise<void>;
  /** ORG-REDESIGN: persist + activate the selected project (org scope only). */
  switchProject: (projectId: string | null) => Promise<void>;
  getToken: () => string | null;
  setAccessToken: (token: string | null) => void;
  can: (permission: Permission) => boolean;
}

import { AuthApiError } from '../components/common/authError';
export { AuthApiError };

function toUser(supabaseUser: {
  id: string;
  email?: string | null;
  user_metadata?: Record<string, any>;
}): User {
  const email = supabaseUser.email ?? '';
  const fullName = supabaseUser.user_metadata?.full_name || supabaseUser.user_metadata?.name;
  return {
    id: supabaseUser.id,
    name: fullName || email.split('@')[0] || 'SOC Analyst',
    email,
    role: 'analyst',
    avatar: supabaseUser.user_metadata?.avatar_url,
  };
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  accessToken: null,
  isAuthenticated: false,
  hydrated: false,
  role: 'analyst',
  fullName: null,
  username: null,
  notificationEmail: null,
  orgEnabled: false,
  organizations: [],
  activeOrganization: null,
  activeOrganizationId: localStorage.getItem(ACTIVE_ORG_KEY),
  activeProjectId: localStorage.getItem(ACTIVE_PROJECT_KEY),
  activeProject: null,

  login: async (email, password) => {
    // Backend-mediated sign-in: usernames are resolved to emails server-side.
    const res = await fetch(`${BASE_URL}/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: email, password }),
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const detail = errBody.detail || errBody.message || 'Login failed';
      throw new Error(typeof detail === 'string' ? detail : 'Login failed');
    }
    const auth = await res.json();
    // Install the session into the Supabase client so token refresh in
    // services/http.ts keeps working transparently.
    await getSupabase().auth.setSession({
      access_token: auth.access_token,
      refresh_token: auth.refresh_token,
    });
    const usr = toUser(auth.user);
    set({
      user: usr,
      accessToken: auth.access_token,
      isAuthenticated: true,
      hydrated: true,
      fullName: usr.name,
    });
    await get().fetchUserContext();
  },

  signUp: async (fullName, email, password, username) => {
    // Backend-mediated signup: enforces username uniqueness and creates the
    // project user row with the chosen username.
    const res = await fetch(`${BASE_URL}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, username, full_name: fullName || undefined }),
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const detail = errBody.detail || errBody.message || 'Signup failed';
      throw new AuthApiError(
        typeof detail === 'string' ? detail : 'Signup failed',
        res.status,
        errBody.error,
        errBody.hint
      );
    }
    const auth = await res.json();

    if (auth.confirmation_pending || !auth.session) {
      // Email confirmation is enabled in Supabase: user must confirm before signing in.
      return { confirmationPending: true };
    }

    // Email confirmation disabled: install the active session.
    await getSupabase().auth.setSession({
      access_token: auth.session.access_token,
      refresh_token: auth.session.refresh_token,
    });
    const usr = toUser(auth.user);
    set({
      user: usr,
      accessToken: auth.session.access_token,
      isAuthenticated: true,
      hydrated: true,
      fullName: usr.name,
    });
    await get().fetchUserContext();
    return { confirmationPending: false };
  },

  registerOrg: async (email, password, orgName, name) => {
    const res = await fetch(`${BASE_URL}/auth/register-org`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, org_name: orgName, name: name || undefined }),
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const detail = errBody.detail || errBody.message || 'Organization registration failed';
      throw new AuthApiError(
        typeof detail === 'string' ? detail : 'Organization registration failed',
        res.status,
        errBody.error,
        errBody.hint
      );
    }
    const data = await res.json();

    if (data.confirmation_pending || !data.session) {
      return { confirmationPending: true, organization: data.organization };
    }

    await getSupabase().auth.setSession({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
    });
    const usr = toUser(data.user);
    const org = data.organization;
    const project = data.project;
    if (org?.id) {
      localStorage.setItem(ACTIVE_ORG_KEY, org.id);
    }
    if (project?.id) {
      localStorage.setItem(ACTIVE_PROJECT_KEY, project.id);
    }
    set({
      user: usr,
      accessToken: data.session.access_token,
      isAuthenticated: true,
      hydrated: true,
      fullName: usr.name,
      orgEnabled: true,
      organizations: data.memberships || [org],
      activeOrganization: org || null,
      activeOrganizationId: org?.id ?? null,
      activeProject: project || null,
      activeProjectId: project?.id ?? null,
      role: 'admin',
    });
    return { confirmationPending: false, organization: org };
  },

  requestPasswordReset: async (email) => {
    const { error } = await getSupabase().auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/reset-password`,
    });
    if (error) throw new Error(error.message);
  },

  completePasswordReset: async (newPassword) => {
    const { error } = await getSupabase().auth.updateUser({ password: newPassword });
    if (error) throw new Error(error.message);
  },

  loginWithOAuth: async (provider: 'google' | 'github') => {
    const { error } = await getSupabase().auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: `${window.location.origin}/dashboard`,
      },
    });
    if (error) {
      throw new Error(error.message ?? `Failed to sign in with ${provider}`);
    }
  },

  logout: async () => {
    await getSupabase().auth.signOut().catch(() => undefined);
    localStorage.removeItem(ACTIVE_ORG_KEY);
    set({
      user: null,
      accessToken: null,
      isAuthenticated: false,
      role: 'analyst',
      fullName: null,
      username: null,
      notificationEmail: null,
      orgEnabled: false,
      organizations: [],
      activeOrganization: null,
      activeOrganizationId: null,
      activeProject: null,
      activeProjectId: null,
    });
    localStorage.removeItem(ACTIVE_PROJECT_KEY);
  },

  fetchUserContext: async () => {
    const token = get().accessToken;
    if (!token) return;

    try {
      let res = await fetch(`${BASE_URL}/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
          ...(get().activeOrganizationId ? { 'X-Organization-Id': get().activeOrganizationId! } : {}),
        },
      });
      if ((res.status === 403 || res.status === 404) && get().activeOrganizationId) {
        // Stale organization header: clear it and retry in personal workspace mode
        localStorage.removeItem(ACTIVE_ORG_KEY);
        set({ activeOrganizationId: null, activeOrganization: null });
        res = await fetch(`${BASE_URL}/auth/me`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      }
      if (res.ok) {
        const data = await res.json();
        const orgEnabled = Boolean(data.org_enabled);
        const orgs: Organization[] = orgEnabled ? data.organizations || data.memberships || [] : [];
        const storedOrgId = localStorage.getItem(ACTIVE_ORG_KEY);
        const active = orgEnabled
          ? orgs.find((o) => o.id === storedOrgId) || (data.active_organization as Organization | null)
          : null;
        const activeRole = (data.active_role || active?.role || 'analyst') as Role;
        // ORG-REDESIGN: the server-persisted selection wins; a stale local
        // copy (e.g. from another org) is discarded. Org scope only.
        const meProject = (data.active_project as { id: string; name: string; slug: string } | null) ?? null;
        const projectActive = active && meProject ? meProject : null;
        if (projectActive) {
          localStorage.setItem(ACTIVE_PROJECT_KEY, projectActive.id);
        } else {
          localStorage.removeItem(ACTIVE_PROJECT_KEY);
        }
        set({
          orgEnabled,
          username: data.username ?? null,
          notificationEmail: data.notification_email ?? null,
          organizations: orgs,
          // Personal mode: no active organization; org rows stay frozen.
          activeOrganization: active || null,
          activeOrganizationId: active?.id ?? null,
          activeProject: projectActive,
          activeProjectId: projectActive?.id ?? null,
          role: activeRole,
          fullName: data.full_name || get().user?.name || null,
          user: get().user
            ? {
                ...get().user!,
                role: activeRole,
                name: data.full_name || get().user!.name,
              }
            : null,
        });
        if (active?.id) {
          localStorage.setItem(ACTIVE_ORG_KEY, active.id);
        } else {
          localStorage.removeItem(ACTIVE_ORG_KEY);
        }
      }
    } catch (err) {
      console.error('Failed to fetch user context:', err);
    }
  },

  switchOrganization: async (orgId: string) => {
    const token = get().accessToken;
    if (!token) return;

    try {
      const res = await fetch(`${BASE_URL}/auth/switch-org`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ organization_id: orgId }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || 'Failed to switch organization');
      }
      localStorage.setItem(ACTIVE_ORG_KEY, orgId);
      const org = get().organizations.find((o) => o.id === orgId) || null;
      set({ activeOrganization: org, activeOrganizationId: orgId });
      // Projects are org-scoped: switching workspaces resets the selection.
      localStorage.removeItem(ACTIVE_PROJECT_KEY);
      set({ activeProject: null, activeProjectId: null });
      await get().fetchUserContext();
    } catch (err) {
      console.error('Failed to switch organization:', err);
      throw err;
    }
  },

  switchProject: async (projectId: string | null) => {
    const token = get().accessToken;
    if (!token) return;
    try {
      const res = await fetch(`${BASE_URL}/auth/switch-project`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ project_id: projectId }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || errBody.message || 'Failed to switch project');
      }
      const data = await res.json().catch(() => ({}));
      if (projectId) {
        localStorage.setItem(ACTIVE_PROJECT_KEY, projectId);
        const project =
          (data.project as { id: string; name: string; slug: string } | undefined) ?? null;
        set({ activeProject: project, activeProjectId: projectId });
      } else {
        localStorage.removeItem(ACTIVE_PROJECT_KEY);
        set({ activeProject: null, activeProjectId: null });
      }
    } catch (err) {
      console.error('Failed to switch project:', err);
      throw err;
    }
  },

  hydrate: async () => {
    try {
      const { data } = await getSupabase().auth.getSession();
      const session = data.session;
      if (session) {
        set({
          user: toUser(session.user),
          accessToken: session.access_token,
          isAuthenticated: true,
        });
        await get().fetchUserContext();
      }
    } catch {
      // ignore
    } finally {
      set({ hydrated: true });
    }
  },

  getToken: () => get().accessToken,

  setAccessToken: (token) => set({ accessToken: token }),

  can: (permission: Permission) => {
    const role = get().role || 'analyst';
    return ROLE_LEVELS[role] >= ROLE_LEVELS[PERMISSION_MIN_ROLE[permission]];
  },
}));
