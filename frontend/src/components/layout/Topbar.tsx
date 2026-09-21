import { useEffect, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Building2, Check, ChevronDown, FolderOpen, LogOut, Radio, Shield, User, Users } from 'lucide-react';
import { useAuthStore } from '../../store/authStore';
import { useUiStore } from '../../store/uiStore';
import * as orgApi from '../../services/orgApi';

const ROUTE_TITLES: [RegExp, string][] = [
  [/^\/dashboard/, 'Security Operations Center'],
  [/^\/phishing/, 'AI-Powered Phishing Detection'],
  [/^\/url-analysis/, 'Malicious URL & Website Detection'],
  [/^\/impersonation/, 'Digital Impersonation Detection'],
  [/^\/deepfake/, 'Deepfake & Manipulated Media Detection'],
  [/^\/account-takeover/, 'Credential Theft & Account Takeover'],
  [/^\/network-threats/, 'Network & API Threat Detection'],
  [/^\/alerts\/.+/, 'Alert Detail'],
  [/^\/alerts/, 'Security Alerts'],
  [/^\/incidents\/.+/, 'Incident Detail'],
  [/^\/incidents/, 'Incident Management'],
  [/^\/response-actions/, 'Response Actions'],
  [/^\/audit-logs/, 'Audit Logs'],
  [/^\/reports/, 'Reports & Export'],
  [/^\/settings/, 'Settings'],
];

export default function Topbar() {
  const location = useLocation();
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const organizations = useAuthStore((s) => s.organizations);
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const orgEnabled = useAuthStore((s) => s.orgEnabled);
  const switchOrganization = useAuthStore((s) => s.switchOrganization);

  const liveSimulation = useUiStore((s) => s.liveSimulation);
  const toggleLiveSimulation = useUiStore((s) => s.toggleLiveSimulation);
  const addToast = useUiStore((s) => s.addToast);

  const [menuOpen, setMenuOpen] = useState(false);
  const [orgMenuOpen, setOrgMenuOpen] = useState(false);
  const [projectMenuOpen, setProjectMenuOpen] = useState(false);
  const [projects, setProjects] = useState<orgApi.Project[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const orgMenuRef = useRef<HTMLDivElement>(null);
  const projectMenuRef = useRef<HTMLDivElement>(null);

  const title = ROUTE_TITLES.find(([re]) => re.test(location.pathname))?.[1] ?? 'CYBERGUARD';

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
      if (orgMenuRef.current && !orgMenuRef.current.contains(e.target as Node)) setOrgMenuOpen(false);
      if (projectMenuRef.current && !projectMenuRef.current.contains(e.target as Node)) setProjectMenuOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleToggleSimulation = () => {
    toggleLiveSimulation();
    const next = !liveSimulation;
    addToast(next ? 'Live alerts enabled' : 'Live alerts disabled', next ? 'low' : 'safe');
  };

  const handleSelectOrg = async (orgId: string, orgName: string) => {
    try {
      setOrgMenuOpen(false);
      setProjects([]);
      await switchOrganization(orgId);
      addToast(`Switched workspace to ${orgName}`, 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to switch workspace', 'high');
    }
  };

  const currentOrg = activeOrganization || (organizations.length > 0 ? organizations[0] : null);
  const activeProject = useAuthStore((s) => s.activeProject);
  const activeProjectId = useAuthStore((s) => s.activeProjectId);
  const switchProject = useAuthStore((s) => s.switchProject);
  // ORG-REDESIGN: the project switcher only exists in a non-personal org.
  const showProjectSwitcher = Boolean(currentOrg && !currentOrg.is_personal);

  useEffect(() => {
    if (!projectMenuOpen || !currentOrg || currentOrg.is_personal) return;
    let cancelled = false;
    setProjectsLoading(true);
    orgApi
      .listProjects(currentOrg.id)
      .then((rows) => {
        if (!cancelled) setProjects(rows.filter((r) => r.status === 'active'));
      })
      .catch(() => {
        if (!cancelled) setProjects([]);
      })
      .finally(() => {
        if (!cancelled) setProjectsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [projectMenuOpen, currentOrg]);

  const handleSelectProject = async (projectId: string | null, name: string) => {
    try {
      setProjectMenuOpen(false);
      await switchProject(projectId);
      addToast(projectId ? `Switched to project ${name}` : 'Project selection cleared', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to switch project', 'high');
    }
  };

  return (
    <header className="relative z-40 flex h-14 items-center justify-between border-b border-zinc-800 bg-zinc-900/90 px-5 backdrop-blur">
      <h1 className="text-base font-semibold text-zinc-100">{title}</h1>

      <div className="flex items-center gap-3">
        {/* Workspace / Organization Switcher */}
        <div className="relative" ref={orgMenuRef}>
          <button
            onClick={() => setOrgMenuOpen((o) => !o)}
            className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200 transition hover:border-red-500/50 hover:bg-zinc-900"
          >
            {currentOrg?.is_personal ? (
              <User className="h-3.5 w-3.5 text-red-400" />
            ) : (
              <Building2 className="h-3.5 w-3.5 text-red-400" />
            )}
            <span className="max-w-[130px] truncate font-medium">
              {currentOrg?.name ?? 'Personal Workspace'}
            </span>
            <span className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-red-400 ring-1 ring-red-500/30">
              {currentOrg?.role ?? user?.role ?? 'admin'}
            </span>
            <ChevronDown className="h-3 w-3 text-zinc-500" />
          </button>

          {orgMenuOpen && (
            <div className="absolute left-0 top-full z-30 mt-1 w-64 rounded-xl border border-zinc-800 bg-zinc-900 p-2 shadow-2xl backdrop-blur">
              <div className="px-2 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400">
                Workspaces & Teams
              </div>

              <div className="space-y-1">
                {organizations.length > 0 ? (
                  organizations.map((org) => {
                    const isSelected = (currentOrg?.id ?? '') === org.id;
                    return (
                      <button
                        key={org.id}
                        onClick={() => handleSelectOrg(org.id, org.name)}
                        className={`flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-xs transition ${
                          isSelected
                            ? 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30'
                            : 'text-zinc-300 hover:bg-zinc-800'
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          {org.is_personal ? (
                            <User className="h-3.5 w-3.5 text-red-400 shrink-0" />
                          ) : (
                            <Building2 className="h-3.5 w-3.5 text-red-400 shrink-0" />
                          )}
                          <div className="truncate">
                            <div className="truncate font-medium">{org.name}</div>
                            <div className="font-mono text-[10px] text-zinc-500">
                              {org.is_personal ? 'Single User' : 'Team SOC'} • {org.role}
                            </div>
                          </div>
                        </div>
                        {isSelected && <Check className="h-3.5 w-3.5 text-red-400 shrink-0 ml-2" />}
                      </button>
                    );
                  })
                ) : (
                  <div className="px-2 py-2 font-mono text-xs text-zinc-500">No organizations found</div>
                )}
              </div>

              {orgEnabled && (
                <>
                  <div className="my-2 border-t border-zinc-800" />
                  <Link
                    to="/organization"
                    onClick={() => setOrgMenuOpen(false)}
                    className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-red-400 transition"
                  >
                    <Users className="h-3.5 w-3.5 text-red-400" />
                    <span>Manage Team & Members</span>
                  </Link>
                </>
              )}
            </div>
          )}
        </div>

        {/* Project Switcher (ORG-REDESIGN) — org workspaces only */}
        {showProjectSwitcher && (
          <div className="relative" ref={projectMenuRef}>
            <button
              onClick={() => setProjectMenuOpen((o) => !o)}
              className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200 transition hover:border-red-500/50 hover:bg-zinc-900"
            >
              <FolderOpen className="h-3.5 w-3.5 text-red-400" />
              <span className="max-w-[130px] truncate font-medium">
                {activeProject ? activeProject.name : 'All Projects'}
              </span>
              <ChevronDown className="h-3 w-3 text-zinc-500" />
            </button>

            {projectMenuOpen && (
              <div className="absolute left-0 top-full z-30 mt-1 w-64 rounded-xl border border-zinc-800 bg-zinc-900 p-2 shadow-2xl backdrop-blur">
                <div className="px-2 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400">
                  Project
                </div>
                <div className="space-y-1">
                  {projectsLoading ? (
                    <div className="px-2 py-2 font-mono text-xs text-zinc-500">Loading…</div>
                  ) : projects.length === 0 ? (
                    <div className="px-2 py-2 text-xs text-zinc-500">
                      No projects — create one in{' '}
                      <a href={`/org/${currentOrg?.id ?? ''}/settings`} className="text-red-400 hover:underline">
                        Settings
                      </a>
                      .
                    </div>
                  ) : (
                    <>
                      <button
                        onClick={() => handleSelectProject(null, '')}
                        className={`flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-xs transition ${
                          !activeProjectId
                            ? 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30'
                            : 'text-zinc-300 hover:bg-zinc-800'
                        }`}
                      >
                        <span>All Projects (org-wide)</span>
                        {!activeProjectId && <Check className="h-3.5 w-3.5 text-red-400 shrink-0 ml-2" />}
                      </button>
                      {projects.map((p) => {
                        const isSelected = activeProjectId === p.id;
                        return (
                          <button
                            key={p.id}
                            onClick={() => handleSelectProject(p.id, p.name)}
                            className={`flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-xs transition ${
                              isSelected
                                ? 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30'
                                : 'text-zinc-300 hover:bg-zinc-800'
                            }`}
                          >
                            <div className="flex min-w-0 items-center gap-2">
                              <FolderOpen className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
                              <div className="truncate">
                                <div className="truncate font-medium">{p.name}</div>
                                <div className="font-mono text-[10px] text-zinc-500">{p.slug}</div>
                              </div>
                            </div>
                            {isSelected && <Check className="h-3.5 w-3.5 text-red-400 shrink-0 ml-2" />}
                          </button>
                        );
                      })}
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Live backend badge */}
        <span className="rounded-md bg-red-500/15 px-2.5 py-1 font-mono text-[11px] font-bold tracking-wider text-red-400 ring-1 ring-red-500/40">
          CLOUD SOC
        </span>

        {/* Live alerts toggle */}
        <button
          onClick={handleToggleSimulation}
          className={`flex items-center gap-2 rounded-md px-2.5 py-1.5 text-xs font-medium ring-1 transition ${
            liveSimulation
              ? 'bg-red-500/15 text-red-400 ring-red-500/50'
              : 'bg-zinc-950 text-zinc-400 ring-zinc-800 hover:text-zinc-200'
          }`}
        >
          {liveSimulation && <Radio className="h-3.5 w-3.5 animate-pulse text-red-400" />}
          <span>Live Alerts</span>
        </button>

        {/* User menu */}
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenuOpen((o) => !o)}
            className="flex items-center gap-2 rounded-md bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-300 ring-1 ring-zinc-800 hover:bg-zinc-900"
          >
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-red-500/20 text-red-400 ring-1 ring-red-500/40">
              <Shield className="h-3.5 w-3.5" />
            </span>
            <span className="hidden md:inline">{user?.name ?? 'Operator'}</span>
            <ChevronDown className="h-3.5 w-3.5 text-zinc-500" />
          </button>
          {menuOpen && (
            <div className="absolute right-0 top-full z-30 mt-1 w-56 rounded-lg border border-zinc-800 bg-zinc-900 p-1.5 shadow-xl">
              <div className="px-2.5 py-2">
                <div className="flex items-center gap-2 text-sm text-zinc-100">
                  <User className="h-3.5 w-3.5 text-zinc-500" />
                  {user?.name}
                </div>
                <div className="mt-0.5 truncate pl-5.5 font-mono text-[11px] text-zinc-500">{user?.email}</div>
                <div className="mt-1 pl-5.5 text-[10px] uppercase tracking-wider text-red-400">
                  Role: {currentOrg?.role ?? user?.role}
                </div>
              </div>
              <div className="my-1 border-t border-zinc-800" />
              {orgEnabled && (
                <Link
                  to="/organization"
                  onClick={() => setMenuOpen(false)}
                  className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-sm text-zinc-300 hover:bg-zinc-800 hover:text-red-400 transition"
                >
                  <Users className="h-3.5 w-3.5 text-red-400" />
                  <span>Organization Settings</span>
                </Link>
              )}
              <div className="my-1 border-t border-zinc-800" />
              <button
                onClick={() => {
                  setMenuOpen(false);
                  logout();
                }}
                className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-sm text-zinc-300 hover:bg-zinc-800 hover:text-red-400 transition"
              >
                <LogOut className="h-3.5 w-3.5" />
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
