import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Building2, Loader2, Plus, Search, X } from 'lucide-react';
import Topbar from '../components/layout/Topbar';
import { useAuthStore } from '../store/authStore';
import { orgApi } from '../services/orgApi';
import type { Organization } from '../types';

function slugifyName(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'organization';
}

export default function OrgSelector() {
  const navigate = useNavigate();
  const setActiveOrganization = useAuthStore((s) => s.setActiveOrganization);
  const fetchOrganizations = useAuthStore((s) => s.fetchOrganizations);

  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [projectCounts, setProjectCounts] = useState<Record<string, number>>({});
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const newOrgSlug = slugifyName(newOrgName);

  // Load organizations
  const loadData = async () => {
    setLoading(true);
    try {
      const list = await fetchOrganizations();
      setOrgs(list);

      // Fetch project count for each organization
      const counts: Record<string, number> = {};
      await Promise.all(
        list.map(async (o) => {
          try {
            const projs = await orgApi.listProjects(o.id);
            counts[o.id] = projs.length;
          } catch {
            counts[o.id] = 0;
          }
        })
      );
      setProjectCounts(counts);
    } catch (err) {
      console.error('Failed to load organizations:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Filter organizations client-side
  const filteredOrgs = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return orgs;
    return orgs.filter(
      (o) => o.name.toLowerCase().includes(q) || (o.slug && o.slug.toLowerCase().includes(q))
    );
  }, [orgs, search]);

  const handleSelectOrg = async (org: Organization) => {
    await setActiveOrganization(org);
    navigate(`/org/${org.id}/projects`);
  };

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = newOrgName.trim();
    if (cleanName.length < 2) {
      setError('Organization name must be at least 2 characters.');
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const created = await orgApi.createOrg(cleanName);
      setOrgs((prev) => [created, ...prev]);
      setProjectCounts((prev) => ({ ...prev, [created.id]: 1 }));
      setNewOrgName('');
      setModalOpen(false);
    } catch (err: any) {
      setError(err instanceof Error ? err.message : 'Failed to create organization');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      <Topbar />

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
        {/* Header & Actions */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-2xl font-bold tracking-tight text-zinc-100">Your organizations</h2>
            <p className="mt-1 text-xs text-zinc-400">
              Select an organization to manage projects and security operations.
            </p>
          </div>

          <button
            type="button"
            onClick={() => {
              setError(null);
              setNewOrgName('');
              setModalOpen(true);
            }}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-semibold text-white shadow-md shadow-red-600/20 transition hover:bg-red-500"
          >
            <Plus className="h-4 w-4" />
            <span>+ New organization</span>
          </button>
        </div>

        {/* Search bar */}
        <div className="relative mt-6 max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search organizations..."
            className="w-full rounded-lg border border-zinc-800 bg-zinc-900/90 py-2 pl-9 pr-3 text-xs text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/50 focus:ring-1 focus:ring-red-500/40"
          />
        </div>

        {/* Content */}
        {loading ? (
          <div className="flex h-64 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-red-500" />
          </div>
        ) : orgs.length === 0 ? (
          /* Empty state: No organizations yet */
          <div className="mt-12 flex flex-col items-center justify-center rounded-2xl border border-dashed border-zinc-800 bg-zinc-900/40 p-12 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/10 text-red-400 ring-1 ring-red-500/30">
              <Building2 className="h-6 w-6" />
            </div>
            <h3 className="mt-4 text-base font-semibold text-zinc-100">No organizations yet</h3>
            <p className="mt-1.5 max-w-sm text-xs text-zinc-400">
              Get started by creating your first organization to organize your security teams and projects.
            </p>
            <button
              type="button"
              onClick={() => {
                setError(null);
                setNewOrgName('');
                setModalOpen(true);
              }}
              className="mt-5 inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white shadow-md shadow-red-600/20 transition hover:bg-red-500"
            >
              <Plus className="h-4 w-4" />
              <span>Create organization</span>
            </button>
          </div>
        ) : filteredOrgs.length === 0 ? (
          <div className="mt-12 text-center text-xs text-zinc-400">
            No organizations match "{search}".
          </div>
        ) : (
          /* Card Grid: Image-2 layout */
          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {filteredOrgs.map((org) => {
              const count = projectCounts[org.id] ?? 0;
              return (
                <div
                  key={org.id}
                  onClick={() => handleSelectOrg(org)}
                  className="group relative cursor-pointer rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 shadow-lg transition hover:border-zinc-700 hover:ring-1 hover:ring-red-500/40"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-800 text-zinc-300 ring-1 ring-zinc-700/50 group-hover:text-red-400">
                      <Building2 className="h-5 w-5" />
                    </div>
                    {org.role && (
                      <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-[10px] uppercase text-zinc-400">
                        {org.role}
                      </span>
                    )}
                  </div>

                  <div className="mt-4">
                    <h3 className="text-base font-bold text-zinc-100 group-hover:text-red-400 transition">
                      {org.name}
                    </h3>
                    <p className="mt-1 font-mono text-xs text-zinc-400">
                      {count} {count === 1 ? 'project' : 'projects'}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>

      {/* [+ New organization] Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="relative w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
              <h3 className="text-base font-semibold text-zinc-100">Create organization</h3>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="text-zinc-500 hover:text-zinc-300 transition"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleCreateOrg} className="mt-4 space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">
                  Organization Name
                </label>
                <div className="relative">
                  <Building2 className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    type="text"
                    required
                    autoFocus
                    value={newOrgName}
                    onChange={(e) => setNewOrgName(e.target.value)}
                    placeholder="Acme Cyber Defense"
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-3 text-sm text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/50 focus:ring-1 focus:ring-red-500/40"
                  />
                </div>
                {newOrgName.trim() && (
                  <p className="mt-2 font-mono text-[11px] text-zinc-400">
                    Slug: <span className="text-zinc-200">{newOrgSlug}</span>
                  </p>
                )}
              </div>

              {error && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                  {error}
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
                  disabled={creating || !newOrgName.trim()}
                  className="flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-bold text-white shadow-md shadow-red-600/20 transition hover:bg-red-500 disabled:opacity-60"
                >
                  {creating && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  <span>{creating ? 'Creating...' : 'Create organization'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
