import { Navigate, useParams } from 'react-router-dom';
import { Building2, FolderKanban } from 'lucide-react';
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
 * ORG-SHELL-1: empty org workspace shell rendered after project selection.
 *
 * Theme-matched frame only (Topbar + org identity sidebar + empty main) with
 * ZERO widgets, nav items, or data fetching — identity is resolved from the
 * already-hydrated session state (or the persisted selections), never from
 * the API.
 */
export default function OrgWorkspaceShell() {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const activeProject = useAuthStore((s) => s.activeProject);

  const org =
    activeOrganization?.id === orgId ? activeOrganization : readPersisted<Organization>(ACTIVE_ORG_KEY);
  const project = activeProject?.id === projectId ? activeProject : readPersisted<Project>(ACTIVE_PROJECT_KEY);

  // Session guard: ids that don't match the session's selections go back to
  // the organization selector.
  if (!orgId || !projectId || org?.id !== orgId || project?.id !== projectId) {
    return <Navigate to="/org/select" replace />;
  }

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      <Topbar />

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar: org identity header only — zero nav items (ORG-SHELL-1) */}
        <aside className="flex w-64 shrink-0 flex-col border-r border-zinc-800 bg-zinc-950">
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

          {/* Sidebar body intentionally empty — nav lands in a later phase */}
        </aside>

        {/* Empty main: padding only, no cards/charts/tables/text */}
        <main className="flex-1 p-6" />
      </div>
    </div>
  );
}
