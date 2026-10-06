import { Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { Building2, FolderKanban, KeyRound, LayoutDashboard, ScrollText, Settings } from 'lucide-react';
import Topbar from '../components/layout/Topbar';
import { useAuthStore } from '../store/authStore';
import type { Organization, Project } from '../types';

// Same persistence keys the authStore uses for the active org/project picks.
const ACTIVE_ORG_KEY = 'cyberguard_active_org';
const ACTIVE_PROJECT_KEY = 'cyberguard_active_project';

function readPersisted<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

/**
 * ORG-SHELL-1 / ORG-SETTINGS-P4: org shell frame.
 *
 * - frame="workspace" (default): strict identity guard (id mismatch ->
 *   /org/select); children provide the page (dashboard, events list).
 *   The shell itself still fetches nothing.
 * - frame="settings": hosts the ProjectSettings page as children; identity
 *   is resolved leniently (no redirect — the settings page owns its guard
 *   chain) and the sidebar gains the bottom "Project Settings" nav item,
 *   visible only when the active org+project are resolved and the project
 *   is not archived.
 *
 * Identity always comes from the hydrated session state (or persisted
 * selections), never from the API.
 */
export default function OrgWorkspaceShell({
  frame = 'workspace',
  children,
}: {
  frame?: 'workspace' | 'settings';
  children?: React.ReactNode;
}) {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  const location = useLocation();
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const activeProject = useAuthStore((s) => s.activeProject);

  const rawOrg =
    activeOrganization?.id === orgId ? activeOrganization : readPersisted<Organization>(ACTIVE_ORG_KEY);
  const rawProject = activeProject?.id === projectId ? activeProject : readPersisted<Project>(ACTIVE_PROJECT_KEY);
  // Persisted fallbacks must still match the URL ids — a stale selection is
  // not this project's identity.
  const org = rawOrg?.id === orgId ? rawOrg : null;
  const project = rawProject?.id === projectId ? rawProject : null;

  // Strict identity guard on the workspace frame only.
  if (frame === 'workspace' && (!orgId || !projectId || org?.id !== orgId || project?.id !== projectId)) {
    return <Navigate to="/org/select" replace />;
  }

  // N3: settings nav item only with resolved org+project and a live project.
  const workspacePath = `/org/${orgId}/projects/${projectId}/workspace`;
  const eventsPath = `/org/${orgId}/projects/${projectId}/events`;
  const settingsPath = `/org/${orgId}/projects/${projectId}/settings`;
  // SCENARIO-3: Analysis section (org-scoped deep analyses)
  const atoPath = `/org/${orgId}/projects/${projectId}/analysis/account-takeover`;
  const dashboardActive = Boolean(orgId && projectId) && location.pathname.startsWith(workspacePath);
  const eventsActive = Boolean(orgId && projectId) && location.pathname.startsWith(eventsPath);
  const settingsActive = Boolean(orgId && projectId) && location.pathname.startsWith(settingsPath);
  const atoActive = Boolean(orgId && projectId) && location.pathname.startsWith(atoPath);
  const showSettingsItem = Boolean(org && project && project.status !== 'archived');

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      <Topbar />

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar: org identity header + bottom reference-rail settings item */}
        <aside className="flex w-64 shrink-0 flex-col border-r border-zinc-800 bg-zinc-950" data-testid="shell-sidebar">
          {org && project && (
            <div className="border-b border-zinc-800 px-4 py-4">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-red-500/10 text-red-400 ring-1 ring-red-500/30">
                  <Building2 className="h-4 w-4" />
                </div>
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-zinc-100">{org.name}</p>
                  <p className="truncate font-mono text-[11px] text-zinc-500">{org.slug}</p>
                </div>
              </div>

              <div className="mt-3 flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-2.5 py-2">
                <FolderKanban className="h-3.5 w-3.5 shrink-0 text-red-400" />
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-zinc-200">{project.name}</p>
                  <p className="truncate font-mono text-[10px] text-zinc-500">{project.slug}</p>
                </div>
              </div>
            </div>
          )}

          {/* ORG-DASHBOARD-P3: primary nav triad — Dashboard / Events (review
              pages count as the events family via startsWith) */}
          {org && project && (
            <nav className="p-3" data-testid="shell-primary-nav">
              <Link
                to={workspacePath}
                data-testid="shell-dashboard-nav"
                aria-current={dashboardActive ? 'page' : undefined}
                className={`flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs transition ${
                  dashboardActive
                    ? 'bg-zinc-900 font-semibold text-red-400 ring-1 ring-red-500/30'
                    : 'text-zinc-400 hover:bg-zinc-900/60 hover:text-zinc-100'
                }`}
              >
                <LayoutDashboard className="h-4 w-4 shrink-0" />
                <span>Dashboard</span>
              </Link>
              <Link
                to={eventsPath}
                data-testid="shell-events-nav"
                aria-current={eventsActive ? 'page' : undefined}
                className={`mt-1 flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs transition ${
                  eventsActive
                    ? 'bg-zinc-900 font-semibold text-red-400 ring-1 ring-red-500/30'
                    : 'text-zinc-400 hover:bg-zinc-900/60 hover:text-zinc-100'
                }`}
              >
                <ScrollText className="h-4 w-4 shrink-0" />
                <span>Events</span>
              </Link>

              {/* SCENARIO-3: Analysis section — org-scoped deep analyses */}
              <div
                className="mt-4 px-2.5 text-[10px] uppercase tracking-wider text-zinc-600"
                data-testid="shell-analysis-section"
              >
                Analysis
              </div>
              <Link
                to={atoPath}
                data-testid="shell-ato-nav"
                aria-current={atoActive ? 'page' : undefined}
                className={`mt-1 flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs transition ${
                  atoActive
                    ? 'bg-zinc-900 font-semibold text-red-400 ring-1 ring-red-500/30'
                    : 'text-zinc-400 hover:bg-zinc-900/60 hover:text-zinc-100'
                }`}
              >
                <KeyRound className="h-4 w-4 shrink-0" />
                <span>Account Takeover</span>
              </Link>
            </nav>
          )}

          {/* Spacer pushes the reference-rail settings item to the bottom */}
          <div className="flex-1" />

          {showSettingsItem && (
            <nav className="border-t border-zinc-800 p-3">
              <Link
                to={settingsPath}
                data-testid="shell-settings-nav"
                aria-current={settingsActive ? 'page' : undefined}
                className={`flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs transition ${
                  settingsActive
                    ? 'bg-zinc-900 font-semibold text-red-400 ring-1 ring-red-500/30'
                    : 'text-zinc-400 hover:bg-zinc-900/60 hover:text-zinc-100'
                }`}
              >
                <Settings className="h-4 w-4 shrink-0" />
                <span>Project Settings</span>
              </Link>
            </nav>
          )}
        </aside>

        {/* Workspace frame: empty canvas. Settings frame: hosts the page. */}
        <main
          data-testid="shell-main"
          className={frame === 'settings' ? 'flex-1 overflow-y-auto p-6' : 'flex-1 p-6'}
        >
          {children ?? null}
        </main>
      </div>
    </div>
  );
}
