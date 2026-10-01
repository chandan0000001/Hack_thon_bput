import { useEffect, useState } from 'react';
import { Loader2, MailX } from 'lucide-react';
import { orgApi, type Invitation } from '../services/orgApi';
import { ApiError } from '../services/http';

/**
 * MEMBER-INVITE-P2: pending invitations table for the org settings members
 * section (admin only). Fetches on mount (and whenever `refreshSignal`
 * changes, e.g. after a new invitation is sent) and supports revoking
 * pending invitations.
 */
export default function PendingInvitations({
  orgId,
  refreshSignal = 0,
}: {
  orgId: string;
  refreshSignal?: number;
}) {
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<Invitation | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    orgApi
      .listInvitations(orgId)
      .then((rows) => {
        if (mounted) {
          setInvitations(rows);
          setLoadError(null);
        }
      })
      .catch((err) => {
        if (mounted) setLoadError(err instanceof ApiError ? err.message : 'Failed to load invitations');
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [orgId, refreshSignal]);

  const confirmRevoke = async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    setRevokeError(null);
    try {
      await orgApi.revokeInvitation(orgId, revokeTarget.id);
      setInvitations((rows) => rows.filter((r) => r.id !== revokeTarget.id));
      setRevokeTarget(null);
    } catch (err) {
      setRevokeError(err instanceof ApiError ? err.message : 'Failed to revoke invitation');
      setRevokeTarget(null);
    } finally {
      setRevoking(false);
    }
  };

  return (
    <div className="mt-4" data-testid="pending-invitations">
      <h4 className="mb-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
        Invitations
      </h4>

      {loadError && (
        <p data-testid="invitations-error" className="mb-2 text-xs text-red-400">
          {loadError}
        </p>
      )}
      {revokeError && (
        <p data-testid="revoke-error" className="mb-2 text-xs text-red-400">
          {revokeError}
        </p>
      )}

      {loading ? (
        <div className="flex items-center gap-2 px-1 py-4 text-xs text-zinc-500" data-testid="invitations-loading">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          <span>Loading invitations…</span>
        </div>
      ) : invitations.length === 0 ? (
        <p className="px-1 py-3 text-xs text-zinc-500" data-testid="invitations-empty">
          No pending invitations
        </p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-zinc-800">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/60">
              <tr>
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">Email</th>
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">Role</th>
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">Expires</th>
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">Status</th>
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {invitations.map((inv) => (
                <tr key={inv.id} data-testid={`invitation-row-${inv.email}`}>
                  <td className="px-3 py-2.5 text-zinc-200">{inv.email}</td>
                  <td className="px-3 py-2.5 font-mono text-zinc-400">{inv.role}</td>
                  <td className="px-3 py-2.5 text-zinc-400">
                    {inv.expires_at ? new Date(inv.expires_at).toLocaleDateString() : '—'}
                  </td>
                  <td className="px-3 py-2.5">
                    <span
                      data-testid={`invitation-status-${inv.id}`}
                      className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                        inv.status === 'pending'
                          ? 'border border-amber-500/30 bg-amber-500/10 text-amber-400'
                          : inv.status === 'accepted'
                            ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                            : 'border border-zinc-700 bg-zinc-800 text-zinc-400'
                      }`}
                    >
                      {inv.status}
                    </span>
                  </td>
                  <td className="px-3 py-2.5">
                    {inv.status === 'pending' && (
                      <button
                        type="button"
                        onClick={() => setRevokeTarget(inv)}
                        data-testid={`revoke-invitation-${inv.email}`}
                        className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-zinc-500 transition hover:bg-red-500/10 hover:text-red-400"
                        title="Revoke invitation"
                      >
                        <MailX className="h-3.5 w-3.5" />
                        <span className="text-[11px]">Revoke</span>
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {revokeTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="text-sm font-semibold text-zinc-100">Revoke invitation</h3>
            <p className="mt-2 text-xs text-zinc-400">
              Revoke the invitation for{' '}
              <span className="font-semibold text-zinc-200">{revokeTarget.email}</span>? The link
              they received will stop working.
            </p>
            <div className="mt-5 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setRevokeTarget(null)}
                className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmRevoke}
                disabled={revoking}
                data-testid="confirm-revoke-btn"
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:opacity-60"
              >
                {revoking && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                <span>Revoke</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
