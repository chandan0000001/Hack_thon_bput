import { create } from 'zustand';
import { getSupabase } from '../lib/supabaseClient';
import type { OrganizationRole, User } from '../types';
import { AuthApiError } from '../components/common/authError';

const ACTIVE_ORG_KEY = 'cyberguard_active_org';
const ACTIVE_PROJECT_KEY = 'cyberguard_active_project';
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

// Purge stale-org localStorage keys on module load (ORG-UI-TEARDOWN)
try {
  localStorage.removeItem(ACTIVE_ORG_KEY);
  localStorage.removeItem(ACTIVE_PROJECT_KEY);
} catch {
  // ignore in non-browser environments
}

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

  login: (email: string, password: string) => Promise<void>;
  loginWithOAuth: (provider: 'google' | 'github') => Promise<void>;
  signUp: (
    fullName: string,
    email: string,
    password: string,
    username: string,
  ) => Promise<{ confirmationPending: boolean }>;
  requestPasswordReset: (email: string) => Promise<void>;
  completePasswordReset: (newPassword: string) => Promise<void>;
  logout: () => Promise<void>;
  hydrate: () => Promise<void>;
  fetchUserContext: () => Promise<void>;
  getToken: () => string | null;
  setAccessToken: (token: string | null) => void;
  can: (permission: Permission) => boolean;
}

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
    try {
      localStorage.removeItem(ACTIVE_ORG_KEY);
      localStorage.removeItem(ACTIVE_PROJECT_KEY);
    } catch {
      // ignore
    }
    set({
      user: null,
      accessToken: null,
      isAuthenticated: false,
      role: 'analyst',
      fullName: null,
      username: null,
      notificationEmail: null,
    });
  },

  fetchUserContext: async () => {
    const token = get().accessToken;
    if (!token) return;

    try {
      const res = await fetch(`${BASE_URL}/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (res.ok) {
        const data = await res.json();
        // Parse memberships / organizations if present, ignore gracefully
        void (data.memberships || data.organizations);
        const activeRole = (data.active_role || 'analyst') as Role;
        set({
          username: data.username ?? null,
          notificationEmail: data.notification_email ?? null,
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
      }
    } catch (err) {
      console.error('Failed to fetch user context:', err);
    }
  },

  hydrate: async () => {
    try {
      localStorage.removeItem(ACTIVE_ORG_KEY);
      localStorage.removeItem(ACTIVE_PROJECT_KEY);
    } catch {
      // ignore
    }
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
