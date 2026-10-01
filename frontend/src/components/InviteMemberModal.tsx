import { useState } from 'react';
import { Loader2, Shield, UserPlus } from 'lucide-react';
import { orgApi, type CreatedInvitation } from '../services/orgApi';
import { ApiError } from '../services/http';

const ROLE_OPTIONS = ['admin', 'analyst', 'viewer'] as const;

/**
 * MEMBER-INVITE-P2: "Invite member" modal (admin only). POSTs an invitation
 * (single-use token, email-based acceptance) instead of directly inserting a
 * membership. On success the parent shows the "Invitation sent" flash and
 * this modal closes.
 */
export default function InviteMemberModal({
  orgId,
  onClose,
  onInvited,
}: {
  orgId: string;
  onClose: () => void;
  onInvited: (invitation: CreatedInvitation) => void;
}) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<string>('viewer');
  const [error, setError] = useState<string | null>(null);
  const [inviting, setInviting] = useState(false);

  const submitInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInviting(true);
    setError(null);
    try {
      const invitation = await orgApi.inviteMember(orgId, email.trim(), role);
      onInvited(invitation);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to send invitation');
    } finally {
      setInviting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center gap-2">
          <Shield className="h-4 w-4 text-red-400" />
          <h3 className="text-sm font-semibold text-zinc-100">Invite member</h3>
        </div>
        <p className="mb-4 text-xs text-zinc-400">
          They&apos;ll receive a single-use invitation link — membership starts once they accept it.
        </p>
        <form onSubmit={submitInvite} className="space-y-4">
          <div>
            <label className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
              Email
            </label>
            <input
              type="email"
              required
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@company.com"
              data-testid="invite-email-input"
              className="w-full rounded-lg border border-zinc-700/60 bg-zinc-900/80 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-red-500/60"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
              Role
            </label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              data-testid="invite-role-select"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-300 outline-none"
            >
              {ROLE_OPTIONS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          {error && (
            <p data-testid="invite-error" className="text-xs text-red-400">
              {error}
            </p>
          )}
          <div className="flex items-center justify-end gap-3 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={inviting || !email.trim()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:opacity-60"
            >
              {inviting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <UserPlus className="h-3.5 w-3.5" />}
              <span>Send invitation</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
