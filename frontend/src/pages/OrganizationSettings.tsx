import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  AlertTriangle,
  Archive,
  BellRing,
  Check,
  Copy,
  FolderOpen,
  KeyRound,
  Loader2,
  MailPlus,
  Plus,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import * as orgApi from '../services/orgApi';

const ROLE_STYLES: Record<orgApi.OrgMember['role'], string> = {
  admin: 'bg-red-500/15 text-red-400 ring-red-500/40',
  analyst: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
  viewer: 'bg-zinc-700/40 text-zinc-300 ring-zinc-600/50',
};

const ROLES: orgApi.OrgMember['role'][] = ['viewer', 'analyst', 'admin'];

type SettingsTab = 'general' | 'projects' | 'api-keys' | 'email-groups' | 'notifications';

const TABS: [SettingsTab, string][] = [
  ['general', 'General'],
  ['projects', 'Projects'],
  ['api-keys', 'API Keys'],
  ['email-groups', 'Email Groups'],
  ['notifications', 'Notifications'],
];

function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

/** One master/viewer card: shows the live key or the Generate button. */
function ProjectKeyCard({
  orgId,
  project,
  role,
}: {
  orgId: string;
  project: orgApi.Project | null;
  role: 'master' | 'viewer';
}) {
  const addToast = useUiStore((s) => s.addToast);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [activeKey, setActiveKey] = useState<orgApi.ProjectApiKey | null>(null);
  // Plaintext-once panel: shown until the user confirms they saved it.
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const ROLE_META = {
    master: {
      icon: ShieldCheck,
      title: 'Master Key',
      blurb: 'All gateway actions — scans, log ingestion, and every future write action.',
    },
    viewer: {
      icon: FolderOpen,
      title: 'View-Only Key',
      blurb: 'Read-only gateway actions (scan_email, scan_url, ingest_log). Write actions reject with 403.',
    },
  } as const;
  const meta = ROLE_META[role];
  const Icon = meta.icon;

  const load = useCallback(async () => {
    if (!project) return;
    setLoading(true);
    try {
      const keys = await orgApi.listProjectKeys(orgId, project.id);
      setActiveKey(keys.find((k) => k.role === role && k.status === 'active') ?? null);
    } catch {
      setActiveKey(null);
    } finally {
      setLoading(false);
    }
  }, [orgId, project, role]);

  // Reset + reload only when the PROJECT/ROLE identity changes — never when
  // the parent re-renders with a fresh projects array. Otherwise a parent
  // refresh would wipe the plaintext-once panel right after generation.
  const projectId = project?.id ?? null;
  useEffect(() => {
    setCreatedKey(null);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, role, orgId]);

  const handleGenerate = async () => {
    if (!project) return;
    setGenerating(true);
    try {
      const created = await orgApi.createProjectKey(orgId, project.id, role, `${meta.title}`);
      setCreatedKey(created.key);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to generate key', 'high');
    } finally {
      setGenerating(false);
    }
  };

  const handleCopy = async () => {
    if (!createdKey) return;
    try {
      await navigator.clipboard.writeText(createdKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      addToast('Copy failed — select the key text manually', 'medium');
    }
  };

  const handleConfirmSaved = () => {
    setCreatedKey(null);
    addToast(`${meta.title} activated`, 'safe');
    load();
  };

  const handleRevoke = async () => {
    if (!project || !activeKey) return;
    if (!confirm(`Revoke the ${role} key (${activeKey.key_prefix}…)? Integrations using it will stop working.`)) return;
    try {
      await orgApi.revokeProjectKey(orgId, project.id, activeKey.id);
      addToast(`${meta.title} revoked`, 'safe');
      load();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to revoke key', 'high');
    }
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
      <div className="mb-1 flex items-center gap-2">
        <Icon className="h-4 w-4 text-red-400" />
        <h3 className="text-sm font-bold text-zinc-100">{meta.title}</h3>
        {activeKey && (
          <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] uppercase text-emerald-400 ring-1 ring-emerald-500/30">
            active
          </span>
        )}
      </div>
      <p className="mb-4 text-xs text-zinc-400">{meta.blurb}</p>

      {!project ? (
        <p className="text-xs text-zinc-500">Select a project above to manage its keys.</p>
      ) : loading ? (
        <div className="flex items-center gap-2 py-3 text-xs text-zinc-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      ) : createdKey ? (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-4">
          <div className="mb-2 flex items-center gap-2 text-xs font-bold text-amber-300">
            <AlertTriangle className="h-4 w-4" />
            Copy this key now — it will never be shown again
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100">
              {createdKey}
            </code>
            <button
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <p className="mt-2 text-[11px] text-amber-300/70">
            Send it in the <code className="font-mono">org_authorization</code> header to{' '}
            <code className="font-mono">/org/{'{org_id}'}/projects/{project.slug}/gateway</code>.
          </p>
          <button
            onClick={handleConfirmSaved}
            className="mt-3 inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-emerald-500"
          >
            <Check className="h-3.5 w-3.5" /> I have saved this key
          </button>
        </div>
      ) : activeKey ? (
        <div className="space-y-1 rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs">
          <div className="flex justify-between gap-3">
            <span className="text-zinc-500">Prefix</span>
            <span className="font-mono text-zinc-200">{activeKey.key_prefix}…</span>
          </div>
          <div className="flex justify-between gap-3">
            <span className="text-zinc-500">Last used</span>
            <span className="text-zinc-300">{formatDate(activeKey.last_used_at)}</span>
          </div>
          <div className="flex justify-between gap-3">
            <span className="text-zinc-500">Created</span>
            <span className="text-zinc-300">{formatDate(activeKey.created_at)}</span>
          </div>
          <div className="pt-2 text-right">
            <button
              onClick={handleRevoke}
              className="inline-flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] text-red-400 transition hover:bg-red-500/10"
            >
              <Trash2 className="h-3 w-3" /> Revoke
            </button>
          </div>
        </div>
      ) : (
        <div className="rounded-lg border border-dashed border-zinc-700 p-4 text-center">
          <p className="mb-3 text-xs text-zinc-500">
            No active {role} key for this project.
          </p>
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50"
          >
            {generating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <KeyRound className="h-3.5 w-3.5" />}
            Generate {meta.title}
          </button>
        </div>
      )}
    </div>
  );
}

/**
 * ORG-REDESIGN: organization settings with project management and the
 * two-slot project API-key model (master + viewer, plaintext shown once).
 * General keeps the org-level gateway keys and member RBAC.
 */
export default function OrganizationSettings() {
  const { orgId } = useParams<{ orgId: string }>();
  const addToast = useUiStore((s) => s.addToast);

  const [tab, setTab] = useState<SettingsTab>('general');

  // General tab state (org gateway keys + members)
  const [keys, setKeys] = useState<orgApi.OrgApiKey[]>([]);
  const [members, setMembers] = useState<orgApi.OrgMember[]>([]);
  const [loading, setLoading] = useState(true);

  // Create-key modal state
  const [keyModalOpen, setKeyModalOpen] = useState(false);
  const [keyName, setKeyName] = useState('');
  const [keyExpiry, setKeyExpiry] = useState('');
  const [creatingKey, setCreatingKey] = useState(false);
  const [createdKey, setCreatedKey] = useState<orgApi.OrgApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);

  // Invite member form
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<orgApi.OrgMember['role']>('analyst');
  const [inviting, setInviting] = useState(false);
  const [savingUserId, setSavingUserId] = useState<string | null>(null);

  // Projects tab state
  const [projects, setProjects] = useState<orgApi.Project[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [creatingProject, setCreatingProject] = useState(false);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [keyList, memberList] = await Promise.all([
        orgApi.listApiKeys(orgId),
        orgApi.listMembers(orgId),
      ]);
      setKeys(keyList);
      setMembers(memberList);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load organization settings', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, addToast]);

  const loadProjects = useCallback(async () => {
    if (!orgId) return;
    setProjectsLoading(true);
    try {
      const rows = await orgApi.listProjects(orgId);
      setProjects(rows.filter((r) => r.status === 'active'));
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load projects', 'high');
    } finally {
      setProjectsLoading(false);
    }
  }, [orgId, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (tab === 'projects' || tab === 'api-keys') loadProjects();
  }, [tab, loadProjects]);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !keyName.trim()) return;
    setCreatingKey(true);
    try {
      const created = await orgApi.createApiKey(
        orgId,
        keyName.trim(),
        keyExpiry ? new Date(keyExpiry).toISOString() : null,
      );
      setCreatedKey(created);
      setKeyName('');
      setKeyExpiry('');
      const list = await orgApi.listApiKeys(orgId);
      setKeys(list);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to create API key', 'high');
    } finally {
      setCreatingKey(false);
    }
  };

  const handleCopyKey = async () => {
    if (!createdKey) return;
    try {
      await navigator.clipboard.writeText(createdKey.key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      addToast('Copy failed — select the key text manually', 'medium');
    }
  };

  const handleRevoke = async (key: orgApi.OrgApiKey) => {
    if (!orgId) return;
    if (!confirm(`Revoke API key "${key.name}" (${key.keyPrefix}…)? Integrations using it will stop working.`)) return;
    try {
      await orgApi.revokeApiKey(orgId, key.id);
      setKeys((prev) => prev.map((k) => (k.id === key.id ? { ...k, status: 'revoked' } : k)));
      addToast('API key revoked', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to revoke key', 'high');
    }
  };

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !inviteEmail.trim()) return;
    setInviting(true);
    try {
      const member = await orgApi.addMember(orgId, inviteEmail.trim(), inviteRole);
      setMembers((prev) => [...prev, member]);
      setInviteEmail('');
      addToast(`Added ${member.email ?? 'member'} as ${member.role}`, 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to add member', 'high');
    } finally {
      setInviting(false);
    }
  };

  const handleChangeRole = async (member: orgApi.OrgMember, role: orgApi.OrgMember['role']) => {
    if (!orgId) return;
    setSavingUserId(member.userId);
    try {
      await orgApi.updateMemberRole(orgId, member.userId, role);
      setMembers((prev) => prev.map((m) => (m.userId === member.userId ? { ...m, role } : m)));
      addToast('Member role updated', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to update role', 'high');
    } finally {
      setSavingUserId(null);
    }
  };

  const handleRemove = async (member: orgApi.OrgMember) => {
    if (!orgId) return;
    if (!confirm(`Remove ${member.email ?? member.userId} from the organization?`)) return;
    setSavingUserId(member.userId);
    try {
      await orgApi.removeMember(orgId, member.userId);
      setMembers((prev) => prev.filter((m) => m.userId !== member.userId));
      addToast('Member removed', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to remove member', 'high');
    } finally {
      setSavingUserId(null);
    }
  };

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !newProjectName.trim()) return;
    setCreatingProject(true);
    try {
      const project = await orgApi.createProject(orgId, newProjectName.trim());
      setNewProjectName('');
      await loadProjects();
      setSelectedProjectId(project.id);
      addToast(`Project "${project.name}" created (${project.slug})`, 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to create project', 'high');
    } finally {
      setCreatingProject(false);
    }
  };

  const handleArchiveProject = async (project: orgApi.Project) => {
    if (!orgId) return;
    if (!confirm(`Archive project "${project.name}"? Its gateway endpoint will 404; history keeps its stamps.`)) return;
    try {
      await orgApi.archiveProject(orgId, project.id);
      if (selectedProjectId === project.id) setSelectedProjectId(null);
      await loadProjects();
      addToast('Project archived', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to archive project', 'high');
    }
  };

  if (!orgId) {
    return <div className="p-6 text-sm text-zinc-400">No organization selected.</div>;
  }

  const selectedProject = projects.find((p) => p.id === selectedProjectId) ?? null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Organization Settings"
        description="Projects, project-scoped API keys, org gateway keys, and team members with role-based access."
      />

      {/* Tabs */}
      <div className="flex flex-wrap gap-1 rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-1 backdrop-blur">
        {TABS.map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex-1 rounded-lg px-3 py-2 text-xs font-semibold sm:text-sm ${
              tab === key ? 'bg-red-500/15 text-red-300 ring-1 ring-red-500/40' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ------------------------------------------------ General */}
      {tab === 'general' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
                <KeyRound className="h-4 w-4 text-red-400" />
                <span>Org Gateway Keys (org-level)</span>
              </div>
              <button
                onClick={() => {
                  setCreatedKey(null);
                  setKeyModalOpen(true);
                }}
                className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Create New Key</span>
              </button>
            </div>

            {createdKey && (
              <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/5 p-4">
                <div className="mb-2 flex items-center gap-2 text-xs font-bold text-amber-300">
                  <AlertTriangle className="h-4 w-4" />
                  Copy this key now — it will never be shown again
                </div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 overflow-x-auto rounded bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100">
                    {createdKey.key}
                  </code>
                  <button
                    onClick={handleCopyKey}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <p className="mt-2 text-[11px] text-amber-300/70">
                  Legacy org-flat gateway (<code className="font-mono">/org/&#123;org_id&#125;/gateway</code>) — deprecated.
                  Prefer project keys under the API Keys tab.
                </p>
              </div>
            )}

            {loading ? (
              <div className="flex items-center gap-2 py-6 text-xs text-zinc-500">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading…
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
                    <tr>
                      <th className="py-2 pr-4">Name</th>
                      <th className="py-2 pr-4">Prefix</th>
                      <th className="py-2 pr-4">Last Used</th>
                      <th className="py-2 pr-4">Expires</th>
                      <th className="py-2 pr-4">Status</th>
                      <th className="py-2"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/70">
                    {keys.length === 0 && (
                      <tr>
                        <td colSpan={6} className="py-4 text-zinc-500">
                          No org gateway keys yet — project keys under the API Keys tab are preferred.
                        </td>
                      </tr>
                    )}
                    {keys.map((k) => (
                      <tr key={k.id} className="text-zinc-300">
                        <td className="py-2.5 pr-4 font-medium text-zinc-100">{k.name}</td>
                        <td className="py-2.5 pr-4 font-mono text-zinc-400">{k.keyPrefix}…</td>
                        <td className="py-2.5 pr-4 text-zinc-400">{formatDate(k.lastUsedAt)}</td>
                        <td className="py-2.5 pr-4 text-zinc-400">{k.expiresAt ? formatDate(k.expiresAt) : 'Never'}</td>
                        <td className="py-2.5 pr-4">
                          <span
                            className={`rounded-full px-2 py-0.5 font-mono text-[10px] uppercase ring-1 ${
                              k.status === 'active'
                                ? 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30'
                                : 'bg-zinc-700/30 text-zinc-400 ring-zinc-600/40'
                            }`}
                          >
                            {k.status}
                          </span>
                        </td>
                        <td className="py-2.5 text-right">
                          {k.status === 'active' && (
                            <button
                              onClick={() => handleRevoke(k)}
                              className="inline-flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] text-red-400 transition hover:bg-red-500/10"
                            >
                              <Trash2 className="h-3 w-3" /> Revoke
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
            <div className="mb-4 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
              <Users className="h-4 w-4 text-red-400" />
              <span>Members & Roles</span>
            </div>

            <form onSubmit={handleInvite} className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center">
              <input
                type="email"
                required
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="analyst@organization.com"
                className="flex-1 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
              />
              <select
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value as orgApi.OrgMember['role'])}
                className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
              >
                {ROLES.map((role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                disabled={inviting}
                className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50"
              >
                {inviting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <UserPlus className="h-3.5 w-3.5" />}
                <span>Invite Member</span>
              </button>
            </form>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
                  <tr>
                    <th className="py-2 pr-4">Member</th>
                    <th className="py-2 pr-4">Email</th>
                    <th className="py-2 pr-4">Role</th>
                    <th className="py-2"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/70">
                  {members.map((m) => (
                    <tr key={m.id} className="text-zinc-300">
                      <td className="py-2.5 pr-4 font-medium text-zinc-100">{m.fullName ?? '—'}</td>
                      <td className="py-2.5 pr-4 text-zinc-400">{m.email ?? '—'}</td>
                      <td className="py-2.5 pr-4">
                        <div className="flex items-center gap-2">
                          <select
                            value={m.role}
                            onChange={(e) => handleChangeRole(m, e.target.value as orgApi.OrgMember['role'])}
                            className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-200 outline-none focus:border-red-500/60"
                          >
                            {ROLES.map((role) => (
                              <option key={role} value={role}>
                                {role}
                              </option>
                            ))}
                          </select>
                          <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${ROLE_STYLES[m.role]}`}>
                            {m.role}
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={() => handleRemove(m)}
                          disabled={savingUserId === m.userId}
                          className="inline-flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] text-red-400 transition hover:bg-red-500/10 disabled:opacity-50"
                        >
                          <Trash2 className="h-3 w-3" /> Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-3 text-[11px] text-zinc-500">
              Admins manage keys, members and settings. Analysts run analyses. Viewers are read-only
              and cannot access sensitive settings (API keys, billing).
            </p>
          </div>
        </div>
      )}

      {/* ------------------------------------------------ Projects */}
      {tab === 'projects' && (
        <div className="space-y-4">
          <form
            onSubmit={handleCreateProject}
            className="flex flex-col gap-3 rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur sm:flex-row sm:items-center"
          >
            <div className="flex-1">
              <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Create Project</label>
              <input
                type="text"
                required
                maxLength={120}
                value={newProjectName}
                onChange={(e) => setNewProjectName(e.target.value)}
                placeholder='e.g. "Demo" — slug demo is generated automatically'
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
              />
            </div>
            <button
              type="submit"
              disabled={creatingProject || !newProjectName.trim()}
              className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50 sm:mt-5"
            >
              {creatingProject ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
              <span>Create Project</span>
            </button>
          </form>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
            <div className="mb-4 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
              <FolderOpen className="h-4 w-4 text-red-400" />
              <span>Projects</span>
            </div>
            {projectsLoading ? (
              <div className="flex items-center gap-2 py-6 text-xs text-zinc-500">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading…
              </div>
            ) : projects.length === 0 ? (
              <p className="py-4 text-xs text-zinc-500">
                No projects yet — create one above to scope gateway integrations and dashboards.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
                    <tr>
                      <th className="py-2 pr-4">Name</th>
                      <th className="py-2 pr-4">Slug (gateway URL)</th>
                      <th className="py-2 pr-4">Created</th>
                      <th className="py-2 pr-4">Status</th>
                      <th className="py-2"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/70">
                    {projects.map((p) => (
                      <tr key={p.id} className="text-zinc-300">
                        <td className="py-2.5 pr-4 font-medium text-zinc-100">{p.name}</td>
                        <td className="py-2.5 pr-4 font-mono text-zinc-400">{p.slug}</td>
                        <td className="py-2.5 pr-4 text-zinc-400">{formatDate(p.created_at)}</td>
                        <td className="py-2.5 pr-4">
                          <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] uppercase text-emerald-400 ring-1 ring-emerald-500/30">
                            {p.status}
                          </span>
                        </td>
                        <td className="py-2.5 text-right">
                          <button
                            onClick={() => handleArchiveProject(p)}
                            className="inline-flex items-center gap-1 rounded border border-amber-500/40 px-2 py-1 text-[11px] text-amber-400 transition hover:bg-amber-500/10"
                          >
                            <Archive className="h-3 w-3" /> Archive
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------ API Keys (project) */}
      {tab === 'api-keys' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
            <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Project</label>
            <select
              value={selectedProjectId ?? ''}
              onChange={(e) => setSelectedProjectId(e.target.value || null)}
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60 sm:max-w-md"
            >
              <option value="">Select a project…</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.slug})
                </option>
              ))}
            </select>
            {projects.length === 0 && !projectsLoading && (
              <p className="mt-2 text-xs text-zinc-500">
                No projects yet — create one in the Projects tab first.
              </p>
            )}
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <ProjectKeyCard orgId={orgId} project={selectedProject} role="master" />
            <ProjectKeyCard orgId={orgId} project={selectedProject} role="viewer" />
          </div>
          <p className="text-[11px] text-zinc-500">
            Exactly one active key per role, always — revoking frees the slot for regeneration.
            Keys authenticate <code className="font-mono">POST /org/&#123;org_id&#125;/projects/&#123;slug&#125;/gateway</code> via
            the <code className="font-mono">org_authorization</code> header.
          </p>
        </div>
      )}

      {/* ------------------------------------------------ Email Groups */}
      {tab === 'email-groups' && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-8 text-center backdrop-blur">
          <MailPlus className="mx-auto h-6 w-6 text-red-400" />
          <h3 className="mt-3 text-sm font-bold text-zinc-100">Email Groups</h3>
          <p className="mx-auto mt-1 max-w-md text-xs text-zinc-400">
            Role-grouped notification lists and per-event-type email routing are managed on the
            dedicated Email Groups page.
          </p>
          <Link
            to={`/org/${orgId}/notifications`}
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-red-500"
          >
            Open Email Groups
          </Link>
        </div>
      )}

      {/* ------------------------------------------------ Notifications */}
      {tab === 'notifications' && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-8 text-center backdrop-blur">
          <BellRing className="mx-auto h-6 w-6 text-red-400" />
          <h3 className="mt-3 text-sm font-bold text-zinc-100">Notification Logs</h3>
          <p className="mx-auto mt-1 max-w-md text-xs text-zinc-400">
            Every org notification delivery — event type, recipients, and status — is recorded in
            the notification log.
          </p>
          <Link
            to={`/org/${orgId}/notifications/logs`}
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-red-500"
          >
            Open Notification Logs
          </Link>
        </div>
      )}

      {/* ------------------------------------------------ Create-key modal (org-level) */}
      {keyModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="mb-1 text-sm font-bold text-zinc-100">Create Org Gateway Key</h3>
            <p className="mb-4 text-xs text-zinc-400">
              Legacy org-level key for <code className="font-mono text-zinc-300">/org/&#123;org_id&#125;/gateway</code> —
              prefer project-scoped keys under the API Keys tab.
            </p>
            <form onSubmit={handleCreateKey}>
              <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Key name</label>
              <input
                type="text"
                required
                maxLength={120}
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                placeholder="Production Key"
                className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
              />
              <label className="mb-1.5 block text-xs font-semibold text-zinc-300">
                Expiry (optional — blank = never)
              </label>
              <input
                type="date"
                value={keyExpiry}
                onChange={(e) => setKeyExpiry(e.target.value)}
                className="mb-5 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setKeyModalOpen(false)}
                  className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-300 transition hover:border-zinc-500"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingKey || !keyName.trim()}
                  className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50"
                >
                  {creatingKey && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  <span>Create Key</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
