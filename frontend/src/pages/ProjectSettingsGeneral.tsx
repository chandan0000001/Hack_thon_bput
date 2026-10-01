import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  Building2,
  Check,
  Copy,
  Loader2,
  LogOut,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import { orgApi, type OrgMemberRow, type OrgInfo, type CreatedInvitation } from '../services/orgApi';
import { ApiError } from '../services/http';
import { useAuthStore } from '../store/authStore';
import InviteMemberModal from '../components/InviteMemberModal';
import PendingInvitations from '../components/PendingInvitations';
import type { Project } from '../types';

type Flash = { ok: boolean; text: string } | null;

const ROLE_OPTIONS = ['admin', 'analyst', 'viewer'] as const;

function useCopyFlash() {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard unavailable — still flash so the click is acknowledged
    }
    setCopiedKey(key);
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setCopiedKey(null), 1500);
  };
  useEffect(() => () => {
    if (timer.current) window.clearTimeout(timer.current);
  }, []);
  return { copiedKey, copy };
}

function CopyButton({ copied, onClick }: { copied: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-[10px] transition ${
        copied
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
          : 'border-zinc-700 bg-zinc-950 text-zinc-400 hover:text-zinc-200'
      }`}
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      <span>{copied ? 'Copied' : 'Copy'}</span>
    </button>
  );
}

/**
 * ORG-SETTINGS-P3: General section — Details, Access, and Delete cards.
 */
export default function ProjectSettingsGeneral({
  orgId,
  project,
  onProjectRefresh,
}: {
  orgId: string;
  project: Project;
  onProjectRefresh: () => void | Promise<void>;
}) {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);

  const [org, setOrg] = useState<OrgInfo | null>(null);
  const [members, setMembers] = useState<OrgMemberRow[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  // G1: details card state
  const [nameDraft, setNameDraft] = useState(project.name);
  const [nameMsg, setNameMsg] = useState<Flash>(null);
  const [savingName, setSavingName] = useState(false);
  const { copiedKey, copy } = useCopyFlash();

  // G2: access card state
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteMsg, setInviteMsg] = useState<Flash>(null);
  const [inviteRefresh, setInviteRefresh] = useState(0);
  const [removeTarget, setRemoveTarget] = useState<OrgMemberRow | null>(null);
  const [removing, setRemoving] = useState(false);
  const [removeMsg, setRemoveMsg] = useState<Flash>(null);
  const [roleBusyId, setRoleBusyId] = useState<string | null>(null);

  // G3: delete card state
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState('');
  const [deleteMsg, setDeleteMsg] = useState<Flash>(null);
  const [deleting, setDeleting] = useState(false);

  // MEMBER-INVITE-P4: leave organization state
  const [leaveOpen, setLeaveOpen] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const [leaveMsg, setLeaveMsg] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const [orgInfo, memberRows] = await Promise.all([
          orgApi.getOrg(orgId),
          orgApi.listMembers(orgId),
        ]);
        if (!mounted) return;
        setOrg(orgInfo);
        setMembers(memberRows);
      } catch (err) {
        if (mounted) {
          setLoadError(err instanceof Error ? err.message : 'Failed to load members');
        }
      }
    };
    load();
    return () => {
      mounted = false;
    };
  }, [orgId]);

  useEffect(() => {
    setNameDraft(project.name);
  }, [project.name]);

  const isAdmin = org?.role === 'admin';
  const nameDirty = nameDraft.trim() !== project.name && nameDraft.trim().length >= 2;

  const saveName = async () => {
    setSavingName(true);
    setNameMsg(null);
    try {
      await orgApi.updateProject(orgId, project.id, { name: nameDraft.trim() });
      setNameMsg({ ok: true, text: 'Project name updated' });
      await onProjectRefresh();
    } catch (err) {
      setNameMsg({
        ok: false,
        text: err instanceof ApiError ? err.message : 'Failed to update project name',
      });
    } finally {
      setSavingName(false);
    }
  };

  const changeRole = async (member: OrgMemberRow, role: string) => {
    setRoleBusyId(member.id);
    setRemoveMsg(null);
    try {
      await orgApi.updateMemberRole(orgId, member.id, role);
      setMembers((rows) => rows.map((r) => (r.id === member.id ? { ...r, role: role as OrgMemberRow['role'] } : r)));
    } catch (err) {
      setRemoveMsg({
        ok: false,
        text: err instanceof ApiError ? err.message : 'Failed to update role',
      });
    } finally {
      setRoleBusyId(null);
    }
  };

  const submitInvite = async (invitation: CreatedInvitation) => {
    setInviteMsg({ ok: true, text: `Invitation sent to ${invitation.email}` });
    setInviteRefresh((n) => n + 1);
  };

  const confirmRemove = async () => {
    if (!removeTarget) return;
    setRemoving(true);
    setRemoveMsg(null);
    try {
      await orgApi.removeMember(orgId, removeTarget.id);
      setMembers((rows) => rows.filter((r) => r.id !== removeTarget.id));
      setRemoveTarget(null);
    } catch (err) {
      setRemoveMsg({
        ok: false,
        text: err instanceof ApiError ? err.message : 'Failed to remove member',
      });
      setRemoveTarget(null);
    } finally {
      setRemoving(false);
    }
  };

  const confirmDelete = async () => {
    setDeleting(true);
    setDeleteMsg(null);
    try {
      await orgApi.deleteProject(orgId, project.id, deleteConfirm);
      navigate(`/org/${orgId}/projects`);
    } catch (err) {
      setDeleteMsg({
        ok: false,
        text: err instanceof ApiError ? err.message : 'Failed to delete project',
      });
    } finally {
      setDeleting(false);
    }
  };

  // MEMBER-INVITE-P4: the current user's membership row (owner never sees the
  // leave control; the backend also blocks removing the organization owner).
  const myMember = members.find((m) => m.user_id === user?.id);
  const canLeave = Boolean(org && myMember && myMember.user_id !== org.owner_id);

  const confirmLeave = async () => {
    if (!myMember) return;
    setLeaving(true);
    setLeaveMsg(null);
    try {
      await orgApi.removeMember(orgId, myMember.id);
      navigate('/org/select');
    } catch (err) {
      setLeaveMsg(err instanceof ApiError ? err.message : 'Failed to leave organization');
      setLeaveOpen(false);
    } finally {
      setLeaving(false);
    }
  };

  if (loadError) {
    return (
      <section className="mt-6">
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-400">
          {loadError}
        </div>
      </section>
    );
  }

  return (
    <div className="mt-6 space-y-5">
      {/* ── G1: Project details ─────────────────────────────────────────── */}
      <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5" data-testid="general-details-card">
        <div className="mb-4 flex items-center gap-2">
          <Building2 className="h-4 w-4 text-red-400" />
          <h3 className="text-sm font-semibold text-zinc-100">Project details</h3>
        </div>

        {/* Name row */}
        <div className="mb-4">
          <label className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
            Project name
          </label>
          {isAdmin ? (
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={nameDraft}
                onChange={(e) => setNameDraft(e.target.value)}
                data-testid="project-name-input"
                className="min-w-56 flex-1 rounded-lg border border-zinc-700/60 bg-zinc-900/80 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-red-500/60"
              />
              <button
                type="button"
                onClick={saveName}
                disabled={!nameDirty || savingName}
                data-testid="save-name-btn"
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {savingName && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                <span>Save changes</span>
              </button>
            </div>
          ) : (
            <p className="text-sm text-zinc-100" data-testid="project-name-plain">
              {project.name}
            </p>
          )}
          {nameMsg && (
            <p
              data-testid="name-flash"
              className={`mt-2 text-xs ${nameMsg.ok ? 'text-emerald-400' : 'text-red-400'}`}
            >
              {nameMsg.text}
            </p>
          )}
        </div>

        {/* Read-only identity rows */}
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Project ID</p>
              <p className="truncate font-mono text-xs text-zinc-300">{project.id}</p>
            </div>
            <CopyButton
              copied={copiedKey === 'id'}
              onClick={() => copy('id', project.id)}
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Slug</p>
              <p className="truncate font-mono text-xs text-zinc-300">{project.slug}</p>
            </div>
            <CopyButton
              copied={copiedKey === 'slug'}
              onClick={() => copy('slug', project.slug)}
            />
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <div>
              <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Status</p>
              <span
                data-testid="project-status-badge"
                className={`mt-0.5 inline-block rounded px-2 py-0.5 font-mono text-[10px] ${
                  project.status === 'active'
                    ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                    : 'border border-zinc-700 bg-zinc-800 text-zinc-400'
                }`}
              >
                {project.status}
              </span>
            </div>
            <div>
              <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Created</p>
              <p className="mt-0.5 text-xs text-zinc-300">
                {new Date(project.created_at).toLocaleDateString()}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── G2: Project access ──────────────────────────────────────────── */}
      <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5" data-testid="general-access-card">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-2">
            <Users className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">Organization-wide access</h3>
              <p className="mt-1 text-xs text-zinc-400" data-testid="access-subtitle">
                All {org?.members_count ?? '…'} organization members can access this project.
              </p>
            </div>
          </div>
          {isAdmin && (
            <button
              type="button"
              onClick={() => {
                setInviteMsg(null);
                setInviteOpen(true);
              }}
              data-testid="manage-members-btn"
              className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-300 transition hover:text-red-400"
            >
              <UserPlus className="h-3.5 w-3.5" />
              <span>Manage members</span>
            </button>
          )}
        </div>

        {removeMsg && (
          <p data-testid="members-flash" className={`mb-3 text-xs ${removeMsg.ok ? 'text-emerald-400' : 'text-red-400'}`}>
            {removeMsg.text}
          </p>
        )}

        {inviteMsg && (
          <p data-testid="invite-flash" className={`mb-3 text-xs ${inviteMsg.ok ? 'text-emerald-400' : 'text-red-400'}`}>
            {inviteMsg.text}
          </p>
        )}

        <div className="overflow-hidden rounded-lg border border-zinc-800">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/60">
              <tr>
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">Member</th>
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">Role</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {members.map((m) => {
                const isYou = m.user_id === user?.id;
                const ownerLocked = org ? m.user_id === org.owner_id : false;
                return (
                  <tr key={m.id} data-testid={`member-row-${m.user_id}`}>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-zinc-200">{m.email || m.full_name || m.user_id}</span>
                        {isYou && (
                          <span
                            data-testid="you-badge"
                            className="rounded-full border border-red-500/40 bg-red-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-red-400"
                          >
                            YOU
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      {isAdmin && !ownerLocked ? (
                        <div className="flex items-center gap-2">
                          <select
                            value={m.role}
                            disabled={roleBusyId === m.id}
                            onChange={(e) => changeRole(m, e.target.value)}
                            data-testid={`role-select-${m.user_id}`}
                            className="rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-300 outline-none"
                          >
                            {ROLE_OPTIONS.map((r) => (
                              <option key={r} value={r}>
                                {r}
                              </option>
                            ))}
                          </select>
                          {roleBusyId === m.id && <Loader2 className="h-3 w-3 animate-spin text-zinc-500" />}
                          <button
                            type="button"
                            onClick={() => setRemoveTarget(m)}
                            data-testid={`remove-member-${m.user_id}`}
                            className="rounded-md px-1.5 py-1 text-zinc-500 transition hover:bg-red-500/10 hover:text-red-400"
                            title="Remove member"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      ) : (
                        <span className="font-mono text-xs text-zinc-400" data-testid={`role-plain-${m.user_id}`}>
                          {m.role}
                          {ownerLocked && ' · owner'}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {members.length === 0 && (
                <tr>
                  <td colSpan={2} className="px-3 py-4 text-center text-zinc-500">Loading members…</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* MEMBER-INVITE-P4: leave organization (hidden for the owner) */}
        {canLeave && (
          <div className="mt-4 flex flex-wrap items-center justify-between gap-2" data-testid="leave-org-section">
            <p className="text-[11px] text-zinc-500">
              No longer part of this organization? You can remove yourself.
            </p>
            <button
              type="button"
              onClick={() => {
                setLeaveMsg(null);
                setLeaveOpen(true);
              }}
              data-testid="leave-org-btn"
              className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-300 transition hover:border-red-500/40 hover:bg-red-500/10 hover:text-red-400"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>Leave organization</span>
            </button>
          </div>
        )}
        {leaveMsg && (
          <p data-testid="leave-error" className="mt-3 text-xs text-red-400">
            {leaveMsg}
          </p>
        )}
      </section>

      {/* ── G3: Danger zone (admin only) ────────────────────────────────── */}
      {isAdmin && (
        <section className="rounded-xl border border-red-500/30 bg-zinc-900/60 p-5" data-testid="general-delete-card">
          <div className="mb-3 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <h3 className="text-sm font-semibold text-zinc-100">Danger zone</h3>
          </div>
          <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2.5">
            <p className="text-xs leading-relaxed text-red-300">
              Deleting this project permanently removes its events, API keys, and project
              settings. The organization and its members are not affected.
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              setDeleteMsg(null);
              setDeleteConfirm('');
              setDeleteOpen(true);
            }}
            data-testid="delete-project-btn"
            className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-bold text-white shadow-md shadow-red-600/20 transition hover:bg-red-500"
          >
            <Trash2 className="h-3.5 w-3.5" />
            <span>Delete project</span>
          </button>
        </section>
      )}

      {/* ── Pending invitations (admin only) ──────────────────────────────── */}
      {isAdmin && <PendingInvitations orgId={orgId} refreshSignal={inviteRefresh} />}

      {/* ── Invite modal ──────────────────────────────────────────────────── */}
      {inviteOpen && (
        <InviteMemberModal
          orgId={orgId}
          onClose={() => setInviteOpen(false)}
          onInvited={submitInvite}
        />
      )}

      {/* ── Remove member confirm modal ───────────────────────────────────── */}
      {removeTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="text-sm font-semibold text-zinc-100">Remove member</h3>
            <p className="mt-2 text-xs text-zinc-400">
              Remove <span className="font-semibold text-zinc-200">{removeTarget.email || removeTarget.user_id}</span>{' '}
              from this organization? They will lose access to all of its projects.
            </p>
            <div className="mt-5 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setRemoveTarget(null)}
                className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmRemove}
                disabled={removing}
                data-testid="confirm-remove-btn"
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:opacity-60"
              >
                {removing && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                <span>Remove</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Leave organization confirm modal (MEMBER-INVITE-P4) ───────────── */}
      {leaveOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-red-500/30 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="text-sm font-semibold text-zinc-100">Leave organization</h3>
            <p className="mt-2 text-xs text-zinc-400">
              Are you sure you want to leave {org?.name || 'this organization'}? You will lose
              access to all projects.
            </p>
            <div className="mt-5 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setLeaveOpen(false)}
                className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmLeave}
                disabled={leaving}
                data-testid="confirm-leave-btn"
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:opacity-60"
              >
                {leaving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                <span>Leave</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Delete project confirm modal ──────────────────────────────────── */}
      {deleteOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-red-500/30 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="text-sm font-semibold text-zinc-100">Delete project</h3>
            <p className="mt-2 text-xs text-zinc-400">
              Type <span className="font-mono font-semibold text-zinc-200">{project.name}</span> to confirm.
              This cannot be undone.
            </p>
            <input
              type="text"
              autoFocus
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.target.value)}
              data-testid="delete-confirm-input"
              className="mt-3 w-full rounded-lg border border-zinc-700/60 bg-zinc-900/80 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-red-500/60"
            />
            {deleteMsg && !deleteMsg.ok && (
              <p data-testid="delete-error" className="mt-2 text-xs text-red-400">
                {deleteMsg.text}
              </p>
            )}
            <div className="mt-5 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setDeleteOpen(false)}
                className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmDelete}
                disabled={deleting || deleteConfirm !== project.name}
                data-testid="confirm-delete-btn"
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {deleting && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                <span>Delete project</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
