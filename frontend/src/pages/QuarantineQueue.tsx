import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  History,
  Inbox,
  Loader2,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Trash2,
  X,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import VerboseResultPanel, { SEVERITY_STYLES } from '../components/common/VerboseResultPanel';
import * as api from '../services/api';
import { useAuthStore } from '../store/authStore';
import type { QuarantineReview, QuarantinedItem } from '../types';
import { formatLocal } from '../utils/datetime';
import {
  useRealtimeEmails,
  shouldAutoScrollToTop,
  type EmailAnalyzedPayload,
} from '../hooks/useRealtimeEmails';

const STATUS_STYLES: Record<string, string> = {
  quarantined: 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/30',
  released: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  deleted: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700',
  expired: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700',
};

function formatWhen(iso: string | null): string {
  return formatLocal(iso);
}

export default function QuarantineQueue() {
  const [items, setItems] = useState<QuarantinedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionId, setActionId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<QuarantinedItem | null>(null);
  const [review, setReview] = useState<QuarantineReview | null>(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [highlightedId, setHighlightedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await api.listQuarantined());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load quarantine queue');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleRealtimeEmail = useCallback(
    (event: EmailAnalyzedPayload) => {
      // Build real-time row matching the QuarantinedItem shape
      const newItem: QuarantinedItem = {
        id: event.processed_email_id,
        connector_id: 'gmail',
        provider_message_id: event.processed_email_id,
        sender_email: event.sender || 'Analyzing sender...',
        reason: event.classification || 'email_analyzed',
        severity: (event.severity || (event.risk_score >= 0.8 ? 'critical' : event.risk_score >= 0.5 ? 'high' : 'medium')) as string,
        scan_result: event.scan_result_id
          ? ({
              id: event.scan_result_id,
              subject: event.subject || 'Threat Analysis Completed',
              verdict: event.severity || event.classification || 'phishing',
              score: Math.round((event.risk_score || 0) * 100),
              indicators: [],
              mitre_attack_tags: [],
            } as any)
          : null,
        quarantined_at: event.analyzed_at || new Date().toISOString(),
        expires_at: null,
        status: 'quarantined',
        last_error: null,
      };

      // Insert at top with highlight animation
      setItems((prev) => [newItem, ...prev.filter((i) => i.id !== newItem.id)]);
      setHighlightedId(event.processed_email_id);
      setTimeout(() => {
        setHighlightedId((curr) => (curr === event.processed_email_id ? null : curr));
      }, 3500);

      // Auto-scroll-to-top on new critical arrival (respect user scroll — only if near top)
      if (typeof window !== 'undefined' && shouldAutoScrollToTop(event, window.scrollY)) {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    },
    [],
  );

  const { isConnected, isPolling, resetLiveCount } = useRealtimeEmails({
    onEvent: handleRealtimeEmail,
    onRefresh: async () => {
      await load();
      resetLiveCount();
    },
    enabled: true,
  });

  useEffect(() => {
    load().then(() => {
      resetLiveCount();
    });
  }, [load, resetLiveCount]);

  const openReview = useCallback(async (item: QuarantinedItem) => {
    setSelected(item);
    setReview(null);
    setReviewLoading(true);
    setError(null);
    try {
      setReview(await api.getQuarantineReview(item.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load review');
    } finally {
      setReviewLoading(false);
    }
  }, []);

  useEffect(() => {
    // no-op: kept for symmetric hooks usage
  }, []);

  const handleKeep = async (item: QuarantinedItem) => {
    setActionId(item.id);
    setError(null);
    setNotice(null);
    try {
      await api.keepQuarantined(item.id);
      setNotice('Item kept in quarantine.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Keep failed');
    } finally {
      setActionId(null);
    }
  };

  const handleRelease = async (item: QuarantinedItem) => {
    setActionId(item.id);
    setError(null);
    setNotice(null);
    try {
      await api.releaseQuarantined(item.id);
      const notificationEmail = useAuthStore.getState().notificationEmail;
      setNotice(
        notificationEmail
          ? `Released "${item.scan_result?.subject || item.provider_message_id}". Action successful. Notification sent to ${notificationEmail}.`
          : `Released "${item.scan_result?.subject || item.provider_message_id}" back to the inbox.`,
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Release failed');
    } finally {
      setActionId(null);
    }
  };

  // Two-action honesty (D1): "Release & trust" never silently removes an
  // active Gmail filter. When the response reports an existing block, the UI
  // offers "Also unblock sender" as an explicit second step.
  const [pendingUnblock, setPendingUnblock] = useState<{ blockId: string; senderEmail: string } | null>(null);

  const handleReleaseAndTrust = async (item: QuarantinedItem) => {
    setActionId(item.id);
    setError(null);
    setNotice(null);
    setPendingUnblock(null);
    try {
      const res = await api.releaseAndTrustQuarantined(item.id);
      setNotice(
        res.message ??
          `Released "${item.scan_result?.subject || item.provider_message_id}" and added ${item.sender_email} to your trust list.`,
      );
      if (res.existing_block) {
        setPendingUnblock({ blockId: res.existing_block.id, senderEmail: res.existing_block.sender_email });
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Release & trust failed');
    } finally {
      setActionId(null);
    }
  };

  const handleDelete = async (item: QuarantinedItem) => {
    setActionId(item.id);
    setError(null);
    setNotice(null);
    try {
      const res = await api.deleteQuarantined(item.id);
      setNotice(res.message ?? 'Message deleted.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setActionId(null);
    }
  };

  const activeItems = items.filter((i) => i.status === 'quarantined');
  const pastItems = items.filter((i) => i.status !== 'quarantined');

  return (
    <div className="space-y-6">
      <PageHeader
        title="Quarantine Queue"
        description="Messages quarantined at Gmail by auto-enforcement. Release returns them to the inbox; delete trashes or permanently removes them per your connector settings."
        actions={
          <div className="flex items-center gap-2">
            {isConnected ? (
              <span
                title="Supabase Realtime subscription active"
                className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-400"
              >
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                LIVE
              </span>
            ) : isPolling ? (
              <span
                title="Realtime disconnected; polling fallback active (refreshes every 60s)"
                className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs font-semibold text-amber-300"
              >
                <span className="h-2 w-2 rounded-full bg-amber-400" />
                POLLING
              </span>
            ) : (
              <span
                title="Connecting to realtime pipeline..."
                className="inline-flex items-center gap-1.5 rounded-full border border-zinc-700 bg-zinc-800/60 px-2.5 py-1 text-xs font-semibold text-zinc-400"
              >
                <span className="h-2 w-2 rounded-full bg-zinc-500 animate-ping" />
                CONNECTING
              </span>
            )}
          </div>
        }
      />

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          {error}
        </div>
      )}
      {notice && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2.5 text-sm text-emerald-300">
          <Inbox className="h-4 w-4 text-emerald-400" />
          {notice}
        </div>
      )}
      {pendingUnblock && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-2.5 text-sm text-amber-300">
          <ShieldOff className="h-4 w-4 text-amber-400" />
          <span className="flex-1">
            {pendingUnblock.senderEmail} is still blocked by an active Gmail filter — trusting does not unblock automatically.
          </span>
          <button
            type="button"
            onClick={async () => {
              setActionId(pendingUnblock.blockId);
              try {
                await api.unblockSender(pendingUnblock.blockId);
                setNotice(`Sender ${pendingUnblock.senderEmail} unblocked — Gmail filter removed.`);
                await load();
              } catch (err) {
                setError(err instanceof Error ? err.message : 'Unblock failed');
              } finally {
                setPendingUnblock(null);
                setActionId(null);
              }
            }}
            disabled={actionId === pendingUnblock.blockId}
            className="flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300 transition hover:bg-amber-500/20 disabled:opacity-50"
          >
            {actionId === pendingUnblock.blockId ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldOff className="h-3.5 w-3.5" />}
            Also unblock sender
          </button>
          <button
            type="button"
            onClick={() => setPendingUnblock(null)}
            className="text-xs text-zinc-400 transition hover:text-zinc-200"
          >
            Keep blocked
          </button>
        </div>
      )}

      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-zinc-100">
            Quarantined messages{' '}
            <span className="font-mono text-xs text-zinc-500">({activeItems.length} active)</span>
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
            <Loader2 className="h-4 w-4 animate-spin" /> Loading quarantine queue…
          </div>
        ) : items.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">
            Nothing quarantined yet. Run a mailbox scan from Email Connectors — high and critical
            verdicts are quarantined automatically when auto-enforcement is on.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {[...activeItems, ...pastItems].map((item) => {
              const isHighlighted = item.id === highlightedId;
              return (
                <div
                  key={item.id}
                  className={`flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:justify-between transition-colors duration-1000 ${
                    isHighlighted ? 'bg-red-500/15 ring-1 ring-inset ring-red-500/40' : ''
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      {!item.scan_result ? (
                        <span className="flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-amber-400 ring-1 ring-amber-500/30 animate-pulse">
                          <Loader2 className="h-3 w-3 animate-spin" />
                          Analyzing...
                        </span>
                      ) : (
                        <span
                          className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${
                            SEVERITY_STYLES[item.severity] ?? SEVERITY_STYLES.safe
                          }`}
                        >
                          {item.severity}
                        </span>
                      )}
                      <span className="truncate text-sm font-semibold text-zinc-100">
                        {item.scan_result?.subject || '(no subject)'}
                      </span>
                      <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${STATUS_STYLES[item.status] ?? STATUS_STYLES.deleted}`}>
                        {item.status}
                      </span>
                    </div>
                  <p className="mt-1 font-mono text-[11px] text-zinc-500">
                    From {item.sender_email} · quarantined {formatWhen(item.quarantined_at)} · expires{' '}
                    {item.expires_at ? formatWhen(item.expires_at) : 'manual'}
                  </p>
                  {item.last_error && <p className="mt-1 text-xs text-red-400">Last error: {item.last_error}</p>}
                </div>
                <div className="flex flex-shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => openReview(item)}
                    className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-200 transition hover:border-zinc-700 hover:bg-zinc-800/60"
                  >
                    <History className="h-3.5 w-3.5" />
                    Review
                  </button>
                  {item.status === 'quarantined' && (
                    <>
                      <button
                        type="button"
                        onClick={() => handleRelease(item)}
                        disabled={actionId === item.id}
                        className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                      >
                        {actionId === item.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Inbox className="h-3.5 w-3.5" />}
                        Release to Inbox
                      </button>
                      <button
                        type="button"
                        onClick={() => handleReleaseAndTrust(item)}
                        disabled={actionId === item.id}
                        className="flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-400 transition hover:bg-sky-500/20 disabled:opacity-50"
                      >
                        {actionId === item.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                        Release &amp; trust sender
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDelete(item)}
                        disabled={actionId === item.id}
                        className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-400 transition hover:bg-red-500/20 disabled:opacity-50"
                      >
                        {actionId === item.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                        Delete Permanently
                      </button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
          </div>
        )}
      </div>

      {/* Why-drawer with the full verbose analysis */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/70 backdrop-blur-sm" onClick={() => setSelected(null)}>
          <div
            className="h-full w-full max-w-3xl overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-zinc-100">{selected.scan_result?.subject || '(no subject)'}</h3>
                <p className="mt-0.5 font-mono text-xs text-zinc-500">From {selected.sender_email}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 p-1.5 text-zinc-400 transition hover:text-red-400"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            {reviewLoading && (
              <div className="flex items-center gap-2 text-sm text-zinc-500">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading review…
              </div>
            )}

            {!reviewLoading && review && (
              <>
                <div className="mb-4 flex flex-wrap items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900/60 p-3">
                  <span className="font-mono text-xs text-zinc-400">
                    {review.message.sender_email} · status{' '}
                    <span className="text-zinc-200">{review.item.status}</span>
                    {review.item.expires_at ? ` · expires ${formatLocal(review.item.expires_at)}` : ' · manual expiry'}
                  </span>
                  {review.available_actions.connector_ready ? (
                    <span className="flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-400 ring-1 ring-emerald-500/30">
                      <CheckCircle2 className="h-3 w-3" /> connector ready
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-400 ring-1 ring-amber-500/30">
                      <ShieldOff className="h-3 w-3" /> connector unavailable
                    </span>
                  )}
                </div>

                {review.scan_result && Object.keys(review.scan_result).length > 0 ? (
                  <VerboseResultPanel scan={review.scan_result} />
                ) : (
                  <p className="text-sm text-zinc-500">No stored analysis for this item.</p>
                )}

                {/* Event chain timeline */}
                <div className="mt-5">
                  <h4 className="mb-2 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">
                    Event chain ({review.event_chain.length})
                  </h4>
                  <div className="space-y-0">
                    {review.event_chain.map((event, idx) => (
                      <div key={event.id} className="flex gap-3">
                        <div className="flex flex-col items-center">
                          <div className={`mt-1.5 h-2.5 w-2.5 rounded-full ${idx === review.event_chain.length - 1 ? 'bg-red-500' : 'bg-zinc-600'}`} />
                          {idx < review.event_chain.length - 1 && <div className="h-full w-px flex-1 bg-zinc-800" />}
                        </div>
                        <div className="pb-4">
                          <p className="font-mono text-xs font-semibold text-zinc-200">
                            {event.event_type.replace(/_/g, ' ')}
                            <span className={`ml-2 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                              event.actor_type === 'system'
                                ? 'bg-red-500/15 text-red-400'
                                : event.actor_type === 'scheduler'
                                  ? 'bg-blue-500/10 text-blue-400'
                                  : 'bg-zinc-800 text-zinc-300'
                            }`}>
                              {event.actor_type}
                            </span>
                            {event.operation_status && (
                              <span className={`ml-1.5 rounded px-1.5 py-0.5 text-[9px] uppercase ${
                                event.operation_status === 'success' ? 'text-emerald-400' : 'text-amber-400'
                              }`}>
                                {event.operation_status.replace(/_/g, ' ')}
                              </span>
                            )}
                          </p>
                          {event.operation_detail && (
                            <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">{event.operation_detail}</p>
                          )}
                          <p className="mt-0.5 font-mono text-[10px] text-zinc-600">
                            {event.created_at ? formatLocal(event.created_at) : '—'}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Manual actions gated by available_actions */}
                {review.item.status === 'quarantined' && review.available_actions.connector_ready && (
                  <div className="mt-4 flex flex-wrap gap-2">
                    {review.available_actions.release && (
                      <button
                        type="button"
                        onClick={() => handleRelease(selected)}
                        disabled={actionId === selected.id}
                        className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                      >
                        {actionId === selected.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Inbox className="h-3.5 w-3.5" />}
                        Release to Inbox
                      </button>
                    )}
                    {review.available_actions.release && (
                      <button
                        type="button"
                        onClick={() => handleReleaseAndTrust(selected)}
                        disabled={actionId === selected.id}
                        className="flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-400 transition hover:bg-sky-500/20 disabled:opacity-50"
                      >
                        {actionId === selected.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                        Release &amp; trust sender
                      </button>
                    )}
                    {review.available_actions.keep && (
                      <button
                        type="button"
                        onClick={() => handleKeep(selected)}
                        disabled={actionId === selected.id}
                        className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-200 transition hover:bg-zinc-800/60 disabled:opacity-50"
                      >
                        {actionId === selected.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Archive className="h-3.5 w-3.5" />}
                        Keep Quarantined
                      </button>
                    )}
                    {review.available_actions.delete && (
                      <button
                        type="button"
                        onClick={() => handleDelete(selected)}
                        disabled={actionId === selected.id}
                        className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-400 transition hover:bg-red-500/20 disabled:opacity-50"
                      >
                        {actionId === selected.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                        {review.available_actions.delete_mode === 'permanent' ? 'Delete Permanently' : 'Move to Trash'}
                      </button>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
