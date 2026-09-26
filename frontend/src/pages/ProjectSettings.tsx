import { useEffect, useState } from 'react';
import { Link, Navigate, useParams } from 'react-router-dom';
import { ArrowLeft, KeyRound, Loader2, Settings as SettingsIcon } from 'lucide-react';
import Topbar from '../components/layout/Topbar';
import { orgApi } from '../services/orgApi';
import { ApiError } from '../services/http';
import type { Project } from '../types';

export type ProjectSettingsSection = 'general' | 'api-keys';

const SECTIONS: { id: ProjectSettingsSection; label: string; icon: typeof SettingsIcon }[] = [
  { id: 'general', label: 'General', icon: SettingsIcon },
  { id: 'api-keys', label: 'API Keys', icon: KeyRound },
];

function sectionPath(orgId: string | undefined, projectId: string | undefined, id: ProjectSettingsSection) {
  return id === 'general'
    ? `/org/${orgId}/projects/${projectId}/settings`
    : `/org/${orgId}/projects/${projectId}/settings/api-keys`;
}

/**
 * ORG-SETTINGS-P2: Project Settings shell — route + two-section sub-sidebar
 * + navigation. Sections render only their title; P3/P4 fill the content.
 * Data-minimal: one GET of the project (guards + name/status); nothing else.
 */
export default function ProjectSettings({ section }: { section: ProjectSettingsSection }) {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  const [project, setProject] = useState<Project | null>(null);
  const [redirect, setRedirect] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      if (!orgId || !projectId) return;
      try {
        const p = await orgApi.getProject(orgId, projectId);
        if (!mounted) return;
        if (p.status === 'archived') {
          setRedirect(`/org/${orgId}/projects`);
          return;
        }
        setProject(p);
      } catch (err) {
        if (!mounted) return;
        const status = err instanceof ApiError ? err.status : undefined;
        // Non-member (or session without access) -> org selector;
        // missing project/org -> project list.
        setRedirect(status === 403 ? '/org/select' : `/org/${orgId}/projects`);
      }
    };
    load();
    return () => {
      mounted = false;
    };
  }, [orgId, projectId]);

  if (redirect) return <Navigate to={redirect} replace />;

  if (!project) {
    return (
      <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
        <Topbar />
        <div className="flex flex-1 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-red-500" />
        </div>
      </div>
    );
  }

  const active = SECTIONS.find((s) => s.id === section) ?? SECTIONS[0];

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      <Topbar />

      <div className="flex flex-1 overflow-hidden">
        {/* Sub-sidebar: Settings nav card only */}
        <aside className="w-64 shrink-0 border-r border-zinc-800 bg-zinc-950 p-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
            <div className="border-b border-zinc-800 px-4 py-3">
              <h2 className="text-sm font-semibold text-zinc-100">Settings</h2>
            </div>
            <nav className="p-2" data-testid="settings-sub-sidebar">
              <p className="px-2 pb-1 pt-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                Configuration
              </p>
              {SECTIONS.map((s) => {
                const isActive = s.id === active.id;
                return (
                  <Link
                    key={s.id}
                    to={sectionPath(orgId, projectId, s.id)}
                    data-testid={`settings-nav-${s.id}`}
                    aria-current={isActive ? 'page' : undefined}
                    className={`flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs transition ${
                      isActive
                        ? 'bg-zinc-800 font-semibold text-red-400'
                        : 'text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-100'
                    }`}
                  >
                    <s.icon className="h-4 w-4 shrink-0" />
                    <span>{s.label}</span>
                  </Link>
                );
              })}
            </nav>
          </div>
        </aside>

        {/* Main: page header + section placeholder (P3/P4 replace) */}
        <main className="flex-1 overflow-y-auto p-6">
          <div className="mb-4">
            <Link
              to={`/org/${orgId}/projects`}
              data-testid="settings-back-to-projects"
              className="inline-flex items-center gap-1.5 font-mono text-xs text-zinc-400 transition hover:text-red-400"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              <span>Back to projects</span>
            </Link>
          </div>

          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">Project Settings</h1>
          <p className="mt-1 text-xs text-zinc-400">General configuration, ownership, and lifecycle</p>

          <section className="mt-6">
            <h2 className="text-base font-semibold text-zinc-100">{active.label}</h2>
          </section>
        </main>
      </div>
    </div>
  );
}
