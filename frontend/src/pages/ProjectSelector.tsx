import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  Archive,
  ArrowLeft,
  FolderKanban,
  LayoutGrid,
  List,
  Loader2,
  MoreVertical,
  Plus,
  RotateCcw,
  Search,
  X,
} from 'lucide-react';
import Topbar from '../components/layout/Topbar';
import { useAuthStore } from '../store/authStore';
import { orgApi } from '../services/orgApi';
import type { Organization, Project, ProjectStatus } from '../types';

function slugifyName(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'project';
}

export default function ProjectSelector() {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();

  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const setActiveOrganization = useAuthStore((s) => s.setActiveOrganization);
  const activeProject = useAuthStore((s) => s.activeProject);
  const setActiveProject = useAuthStore((s) => s.setActiveProject);
  const fetchOrganizations = useAuthStore((s) => s.fetchOrganizations);

  const [currentOrg, setCurrentOrg] = useState<Organization | null>(activeOrganization);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);

  // Toolbar filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'archived'>('all');
  const [sortBy, setSortBy] = useState<'name' | 'created'>('created');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');

  // New project modal
  const [modalOpen, setModalOpen] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Kebab menu & archive modal
  const [menuOpenId, setMenuOpenId] = useState<string | null>(null);
  const [archiveModalOpen, setArchiveModalOpen] = useState(false);
  const [targetProject, setTargetProject] = useState<Project | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const menuRef = useRef<HTMLDivElement>(null);
  const newSlug = slugifyName(newProjectName);

  // Close kebab dropdown on click outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpenId(null);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // Hydrate organization & project list
  useEffect(() => {
    if (!orgId) return;

    let mounted = true;
    const init = async () => {
      setLoading(true);
      try {
        const orgList = await fetchOrganizations();
        let found = orgList.find((o) => o.id === orgId);
        if (!found) {
          const currentActiveOrg = useAuthStore.getState().activeOrganization;
          if (currentActiveOrg?.id === orgId) {
            found = currentActiveOrg;
          } else {
            try {
              const raw = localStorage.getItem('cyberguard_active_org');
              if (raw) {
                const parsed = JSON.parse(raw);
                if (parsed.id === orgId) found = parsed;
              }
            } catch {
              // ignore
            }
          }
        }

        if (!found && orgList.length > 0) {
          navigate('/org/select', { replace: true });
          return;
        }

        if (mounted && found) {
          setCurrentOrg(found);
          const currentActiveOrg = useAuthStore.getState().activeOrganization;
          if (!currentActiveOrg || currentActiveOrg.id !== found.id) {
            await setActiveOrganization(found);
          }
        }

        const projectList = await orgApi.listProjects(orgId);
        if (mounted) {
          setProjects(projectList);

          // Verify if activeProject belongs to this org and exists in projectList
          const currentActiveProj = useAuthStore.getState().activeProject;
          if (currentActiveProj) {
            const match = projectList.find((p) => p.id === currentActiveProj.id);
            if (!match) {
              await setActiveProject(null);
            }
          }
        }
      } catch (err) {
        console.error('Failed to load projects:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    init();
    return () => {
      mounted = false;
    };
  }, [orgId]);

  // Client-side search, status filter, and sort
  const filteredProjects = useMemo(() => {
    let list = [...projects];

    // Status filter
    if (statusFilter !== 'all') {
      list = list.filter((p) => p.status === statusFilter);
    }

    // Search filter
    const q = search.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (p) => p.name.toLowerCase().includes(q) || (p.slug && p.slug.toLowerCase().includes(q))
      );
    }

    // Sort control
    if (sortBy === 'name') {
      list.sort((a, b) => a.name.localeCompare(b.name));
    } else {
      list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    }

    return list;
  }, [projects, statusFilter, search, sortBy]);

  const handleSelectProject = async (project: Project) => {
    await setActiveProject(project);
    // ORG-SHELL-1: activating a project enters its (empty) workspace shell.
    navigate(`/org/${orgId}/projects/${project.id}/workspace`);
  };

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;
    const cleanName = newProjectName.trim();
    if (cleanName.length < 2) {
      setCreateError('Project name must be at least 2 characters.');
      return;
    }

    setCreating(true);
    setCreateError(null);
    try {
      const created = await orgApi.createProject(orgId, {
        name: cleanName,
        slug: newSlug,
      });
      setProjects((prev) => [created, ...prev]);
      await setActiveProject(created);
      setNewProjectName('');
      setModalOpen(false);
      // ORG-SHELL-1: a freshly created project is activated into the shell too.
      navigate(`/org/${orgId}/projects/${created.id}/workspace`);
    } catch (err: any) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create project');
    } finally {
      setCreating(false);
    }
  };

  const handleToggleProjectStatus = async () => {
    if (!orgId || !targetProject) return;
    const nextStatus: ProjectStatus = targetProject.status === 'active' ? 'archived' : 'active';

    setUpdatingStatus(true);
    try {
      const updated = await orgApi.updateProject(orgId, targetProject.id, {
        status: nextStatus,
      });
      setProjects((prev) =>
        prev.map((p) => (p.id === targetProject.id ? { ...p, status: updated.status } : p))
      );

      // If active project was archived, clear selection
      if (nextStatus === 'archived' && activeProject?.id === targetProject.id) {
        await setActiveProject(null);
      }

      setArchiveModalOpen(false);
      setTargetProject(null);
    } catch (err) {
      console.error('Failed to update project status:', err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      <Topbar />

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
        {/* Navigation back to organization selector */}
        <div className="mb-4">
          <Link
            to="/org/select"
            className="inline-flex items-center gap-1.5 font-mono text-xs text-zinc-400 transition hover:text-red-400"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>All organizations</span>
          </Link>
        </div>

        {/* Heading & Toolbar: Image-3 layout */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-2xl font-bold tracking-tight text-zinc-100">Projects</h2>
            <p className="mt-1 text-xs text-zinc-400">
              Organization: <span className="font-semibold text-zinc-200">{currentOrg?.name || 'Loading...'}</span>
            </p>
          </div>

          <button
            type="button"
            onClick={() => {
              setCreateError(null);
              setNewProjectName('');
              setModalOpen(true);
            }}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-semibold text-white shadow-md shadow-red-600/20 transition hover:bg-red-500"
          >
            <Plus className="h-4 w-4" />
            <span>+ New project</span>
          </button>
        </div>

        {/* Toolbar: Search + Status filter + Sort + View mode */}
        <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search projects..."
              className="w-full rounded-lg border border-zinc-800 bg-zinc-900/90 py-2 pl-9 pr-3 text-xs text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/50 focus:ring-1 focus:ring-red-500/40"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Status filter dropdown */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="rounded-lg border border-zinc-800 bg-zinc-900/90 px-3 py-2 text-xs text-zinc-300 outline-none transition focus:border-zinc-700"
            >
              <option value="all">Status: All</option>
              <option value="active">Status: Active</option>
              <option value="archived">Status: Archived</option>
            </select>

            {/* Sort control dropdown */}
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="rounded-lg border border-zinc-800 bg-zinc-900/90 px-3 py-2 text-xs text-zinc-300 outline-none transition focus:border-zinc-700"
            >
              <option value="created">Sort: Created</option>
              <option value="name">Sort: Name</option>
            </select>

            {/* Grid | List view toggle */}
            <div className="flex items-center rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
              <button
                type="button"
                onClick={() => setViewMode('grid')}
                className={`rounded p-1.5 transition ${
                  viewMode === 'grid' ? 'bg-zinc-800 text-red-400' : 'text-zinc-500 hover:text-zinc-300'
                }`}
                title="Grid view"
              >
                <LayoutGrid className="h-4 w-4" />
              </button>
              <button
                type="button"
                onClick={() => setViewMode('list')}
                className={`rounded p-1.5 transition ${
                  viewMode === 'list' ? 'bg-zinc-800 text-red-400' : 'text-zinc-500 hover:text-zinc-300'
                }`}
                title="List view"
              >
                <List className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Content list */}
        {loading ? (
          <div className="flex h-64 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-red-500" />
          </div>
        ) : filteredProjects.length === 0 ? (
          <div className="mt-12 flex flex-col items-center justify-center rounded-2xl border border-dashed border-zinc-800 bg-zinc-900/40 p-12 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/10 text-red-400 ring-1 ring-red-500/30">
              <FolderKanban className="h-6 w-6" />
            </div>
            <h3 className="mt-4 text-base font-semibold text-zinc-100">No projects found</h3>
            <p className="mt-1.5 max-w-sm text-xs text-zinc-400">
              {search || statusFilter !== 'all'
                ? 'Try adjusting your search terms or filters.'
                : 'Create your first project in this organization to get started.'}
            </p>
          </div>
        ) : viewMode === 'grid' ? (
          /* Grid view: Image-3 structure */
          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {filteredProjects.map((project) => {
              const isSelected = activeProject?.id === project.id;
              return (
                <div
                  key={project.id}
                  onClick={() => handleSelectProject(project)}
                  className={`group relative cursor-pointer rounded-xl border p-5 shadow-lg transition ${
                    isSelected
                      ? 'border-red-500 bg-zinc-900/90 ring-2 ring-red-500/50'
                      : 'border-zinc-800 bg-zinc-900/90 hover:border-zinc-700 hover:ring-1 hover:ring-red-500/30'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2">
                      <div
                        className={`flex h-9 w-9 items-center justify-center rounded-lg ring-1 transition ${
                          isSelected
                            ? 'bg-red-500/20 text-red-400 ring-red-500/40'
                            : 'bg-zinc-800 text-zinc-400 ring-zinc-700/50 group-hover:text-red-400'
                        }`}
                      >
                        <FolderKanban className="h-4 w-4" />
                      </div>
                      <div>
                        <h3 className="text-base font-bold text-zinc-100 group-hover:text-red-400 transition">
                          {project.name}
                        </h3>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                      {/* Active Selection Badge */}
                      {isSelected && (
                        <span className="rounded-full border border-red-500/40 bg-red-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-red-400">
                          Active
                        </span>
                      )}

                      {/* Status badge: active / archived */}
                      <span
                        className={`rounded px-2 py-0.5 font-mono text-[10px] ${
                          project.status === 'active'
                            ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                            : 'border border-zinc-700 bg-zinc-800 text-zinc-400'
                        }`}
                      >
                        {project.status}
                      </span>

                      {/* Kebab Menu */}
                      <div className="relative">
                        <button
                          type="button"
                          onClick={() => setMenuOpenId(menuOpenId === project.id ? null : project.id)}
                          className="rounded p-1 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                        >
                          <MoreVertical className="h-4 w-4" />
                        </button>

                        {menuOpenId === project.id && (
                          <div
                            ref={menuRef}
                            className="absolute right-0 top-full z-20 mt-1 w-36 rounded-lg border border-zinc-800 bg-zinc-900 p-1 shadow-xl"
                          >
                            <button
                              type="button"
                              onClick={() => {
                                setMenuOpenId(null);
                                setTargetProject(project);
                                setArchiveModalOpen(true);
                              }}
                              className="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-xs text-zinc-300 transition hover:bg-zinc-800 hover:text-red-400"
                            >
                              {project.status === 'active' ? (
                                <>
                                  <Archive className="h-3.5 w-3.5" />
                                  <span>Archive</span>
                                </>
                              ) : (
                                <>
                                  <RotateCcw className="h-3.5 w-3.5" />
                                  <span>Unarchive</span>
                                </>
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Second line = slug only */}
                  <p className="mt-3 font-mono text-xs text-zinc-400">{project.slug}</p>
                </div>
              );
            })}
          </div>
        ) : (
          /* List view */
          <div className="mt-6 divide-y divide-zinc-800 rounded-xl border border-zinc-800 bg-zinc-900/90 shadow-lg">
            {filteredProjects.map((project) => {
              const isSelected = activeProject?.id === project.id;
              return (
                <div
                  key={project.id}
                  onClick={() => handleSelectProject(project)}
                  className={`flex cursor-pointer items-center justify-between p-4 transition ${
                    isSelected
                      ? 'bg-red-500/5 ring-1 ring-inset ring-red-500/40'
                      : 'hover:bg-zinc-800/40'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <FolderKanban
                      className={`h-4 w-4 ${isSelected ? 'text-red-400' : 'text-zinc-500'}`}
                    />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-zinc-100">{project.name}</span>
                        {isSelected && (
                          <span className="rounded-full border border-red-500/40 bg-red-500/20 px-1.5 py-0.2 font-mono text-[9px] font-bold text-red-400">
                            Active
                          </span>
                        )}
                      </div>
                      <p className="font-mono text-xs text-zinc-400">{project.slug}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3" onClick={(e) => e.stopPropagation()}>
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[10px] ${
                        project.status === 'active'
                          ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                          : 'border border-zinc-700 bg-zinc-800 text-zinc-400'
                      }`}
                    >
                      {project.status}
                    </span>

                    <button
                      type="button"
                      onClick={() => {
                        setTargetProject(project);
                        setArchiveModalOpen(true);
                      }}
                      className="rounded p-1 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>

      {/* [+ New project] Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="relative w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
              <h3 className="text-base font-semibold text-zinc-100">Create project</h3>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="text-zinc-500 hover:text-zinc-300 transition"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleCreateProject} className="mt-4 space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">
                  Project Name
                </label>
                <div className="relative">
                  <FolderKanban className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    type="text"
                    required
                    autoFocus
                    value={newProjectName}
                    onChange={(e) => setNewProjectName(e.target.value)}
                    placeholder="Core Defense SOC"
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-3 text-sm text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/50 focus:ring-1 focus:ring-red-500/40"
                  />
                </div>
                {newProjectName.trim() && (
                  <p className="mt-2 font-mono text-[11px] text-zinc-400">
                    Slug: <span className="text-zinc-200">{newSlug}</span>
                  </p>
                )}
              </div>

              {createError && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                  {createError}
                </div>
              )}

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  disabled={creating}
                  className="rounded-lg border border-zinc-800 bg-zinc-950 px-3.5 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-60"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating || !newProjectName.trim()}
                  className="flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-bold text-white shadow-md shadow-red-600/20 transition hover:bg-red-500 disabled:opacity-60"
                >
                  {creating && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  <span>{creating ? 'Creating...' : 'Create project'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Archive / Unarchive Confirmation Modal */}
      {archiveModalOpen && targetProject && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="relative w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="text-base font-semibold text-zinc-100">
              {targetProject.status === 'active' ? 'Archive project' : 'Unarchive project'}
            </h3>
            <p className="mt-2 text-xs text-zinc-400">
              Are you sure you want to {targetProject.status === 'active' ? 'archive' : 'unarchive'}{' '}
              <span className="font-semibold text-zinc-200">{targetProject.name}</span>?
            </p>

            <div className="mt-6 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => {
                  setArchiveModalOpen(false);
                  setTargetProject(null);
                }}
                disabled={updatingStatus}
                className="rounded-lg border border-zinc-800 bg-zinc-950 px-3.5 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-60"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleToggleProjectStatus}
                disabled={updatingStatus}
                className="flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-bold text-white shadow-md shadow-red-600/20 transition hover:bg-red-500 disabled:opacity-60"
              >
                {updatingStatus && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                <span>
                  {updatingStatus
                    ? 'Updating...'
                    : targetProject.status === 'active'
                    ? 'Archive'
                    : 'Unarchive'}
                </span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
