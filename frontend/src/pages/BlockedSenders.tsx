import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Ban, Clock, Loader2, RefreshCw, ShieldCheck, ShieldOff, Trash2 } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import * as api from '../services/api';
import type { BlockedSender, TrustedSender } from '../types';
import { formatLocal } from '../utils/datetime';

const STATUS_STYLES: Record<string, string> = {
  blocked: 'bg-red-500/10 text-red-400 ring-1 ring-red-500/30',
  released: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  expired: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700',
};

function formatWhen(iso: string | null): string {
  return formatLocal(iso);
}

export default function BlockedSenders() {
  const [blocks, setBlocks] = useState<BlockedSender[]>([]);
  const [trustedSenders, setTrustedSenders] = useState<TrustedSender[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionId, setActionId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [blocksData, trustedData] = await Promise.all([
        api.listBlockedSenders(),
        api.listTrustedSenders(),
      ]);
      setBlocks(blocksData);
      setTrustedSenders(trustedData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleUnblock = async (block: BlockedSender) => {
    setActionId(block.id);
    setError(null);
    try {
      await api.unblockSender(block.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unblock failed');
    } finally {
      setActionId(null);
    }
  };

  // Two-action honesty (D1): "Trust sender" never removes an active filter.
  // Unblocking remains a separate explicit button on this page.
  const handleTrust = async (block: BlockedSender) => {
    setActionId(block.id);
    setError(null);
    setNotice(null);
    try {
      await api.trustSender(block.sender_email, 'trusted from Blocked Senders page');
      setNotice(
        `${block.sender_email} added to your trust list — future auto-enforcement for this sender is recommend-only. The Gmail filter stays active until you unblock it explicitly.`,
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Trust failed');
    } finally {
      setActionId(null);
    }
  };

  const handleUntrust = async (senderId: string, email: string) => {
    setActionId(senderId);
    setError(null);
    try {
      await api.removeTrustedSender(senderId);
      setNotice(`${email} removed from your trust list — auto-quarantine will apply to future incoming emails.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove trusted sender');
    } finally {
      setActionId(null);
    }
  };

  const activeBlocks = blocks.filter((b) => b.status === 'blocked');
  const pastBlocks = blocks.filter((b) => b.status !== 'blocked');

  return (
    <div className="space-y-6">
      <PageHeader
        title="Blocked Senders"
        description="Senders auto-blocked via Gmail filters after high or critical verdicts. Temporary blocks expire automatically and their filters are removed by the scheduler. Trusting a sender makes future enforcement recommend-only — it never removes the active filter; use Unblock for that."
      />

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          {error}
        </div>
      )}
      {notice && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2.5 text-sm text-emerald-300">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          {notice}
        </div>
      )}

      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-zinc-100">
            Blocked senders{' '}
            <span className="font-mono text-xs text-zinc-500">({activeBlocks.length} active)</span>
          </h2>
          <button
            type="button"
            onClick={load}
            className="flex items-center gap-1.5 text-xs text-zinc-400 transition hover:text-red-400"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-10 text-sm text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading blocked senders…
          </div>
        ) : blocks.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">
            No senders blocked yet. High and critical scan verdicts auto-block their sender via a
            Gmail filter when auto-enforcement is on.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {[...activeBlocks, ...pastBlocks].map((block) => (
              <div key={block.id} className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Ban className="h-3.5 w-3.5 text-red-400" />
                    <span className="truncate text-sm font-semibold text-zinc-100">{block.sender_email}</span>
                    <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${STATUS_STYLES[block.status] ?? STATUS_STYLES.expired}`}>
                      {block.status}
                    </span>
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-zinc-500">
                    {block.reason} · blocked {formatWhen(block.blocked_at)} · expires{' '}
                    {block.expires_at ? (
                      <span className="inline-flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {formatWhen(block.expires_at)}
                      </span>
                    ) : (
                      'manual'
                    )}
                    {block.provider_rule_id ? ` · filter ${block.provider_rule_id}` : ' · no filter created'}
                  </p>
                  {block.last_error && <p className="mt-1 text-xs text-red-400">Last error: {block.last_error}</p>}
                </div>
                <div className="flex flex-shrink-0 items-center gap-2">
                  {block.status === 'blocked' && (
                    <>
                      <button
                        type="button"
                        onClick={() => handleTrust(block)}
                        disabled={actionId === block.id}
                        className="flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-400 transition hover:bg-sky-500/20 disabled:opacity-50"
                      >
                        {actionId === block.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                        Trust Sender
                      </button>
                      <button
                        type="button"
                        onClick={() => handleUnblock(block)}
                        disabled={actionId === block.id}
                        className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                      >
                        {actionId === block.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldOff className="h-3.5 w-3.5" />}
                        Unblock Sender
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Trusted Senders List */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              Trusted Senders{' '}
              <span className="font-mono text-xs text-zinc-500">({trustedSenders.length})</span>
            </h2>
            <p className="mt-0.5 text-xs text-zinc-400">
              Senders in this list are exempt from auto-quarantine. Incoming emails will still be scanned and scored, but will not be quarantined.
            </p>
          </div>
        </div>

        {trustedSenders.length === 0 ? (
          <div className="px-5 py-6 text-center text-xs text-zinc-500">
            No trusted senders. Senders you choose to "Trust" from alerts or blocked senders will appear here.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {trustedSenders.map((sender) => (
              <div key={sender.id} className="flex flex-col gap-2 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-sm font-semibold text-zinc-100">{sender.sender_email}</span>
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-zinc-500">
                    {sender.reason || 'trusted'} · added {formatWhen(sender.created_at)}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleUntrust(sender.id, sender.sender_email)}
                  disabled={actionId === sender.id}
                  className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1 text-xs font-semibold text-red-400 transition hover:bg-red-500/20 disabled:opacity-50"
                >
                  {actionId === sender.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                  Remove from Trust List
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
