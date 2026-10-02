import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  ChevronDown,
  Clock,
  Loader2,
  RefreshCw,
  X,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { SEVERITY_STYLES } from '../components/common/VerboseResultPanel';
import { normalizeScorePct } from '../utils/score';
import * as api from '../services/api';
import type { SecurityEventRecord } from '../types';

const ACTOR_STYLES: Record<string, string> = {
  system: 'bg-red-500/15 text-red-400 ring-1 ring-red-500/40',
  user: 'bg-zinc-800 text-zinc-300 ring-1 ring-zinc-700',
  scheduler: 'bg-blue-500/10 text-blue-400 ring-1 ring-blue-500/40',
};

const OP_STATUS_STYLES: Record<string, string> = {
  success: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  failed: 'bg-red-500/10 text-red-400 ring-1 ring-red-500/30',
  reauth_required: 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/30',
  insufficient_scope: 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/30',
};

const EVENT_TYPES = [
  'scan_verdict', 'quarantine', 'release', 'keep', 'delete',
  'sender_block', 'sender_release', 'sender_expiry',
  'connector_connect', 'connector_disconnect', 'connector_test',
];

const PAGE_SIZE = 25;

function formatWhen(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

export default function SecurityHistory() {
  const [items, setItems] = useState<SecurityEventRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<SecurityEventRecord | null>(null);

  const [fEventType, setFEventType] = useState('');
  const [fActor, setFActor] = useState('');
  const [fSeverity, setFSeverity] = useState('');
  const [fSender, setFSender] = useState('');
  const [fFrom, setFFrom] = useState('');
  const [fTo, setFTo] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listSecurityHistory({
        event_type: fEventType || undefined,
        actor_type: fActor || undefined,
        severity: fSeverity || undefined,
        sender_email: fSender || undefined,
        from: fFrom || undefined,
        to: fTo || undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      });
      setItems(res.items);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load security history');
    } finally {
      setLoading(false);
    }
  }, [fEventType, fActor, fSeverity, fSender, fFrom, fTo, page]);

  useEffect(() => {
    load();
  }, [load]);

  const applyFilters = () => setPage(0); // triggers load via state change

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security History"
        description="Permanent record of real security events and provider operations — scan verdicts, quarantines, sender-rule lifecycle, and manual reviews."
      />

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          {error}
        </div>
      )}

      {/* Filter bar */}
      <div className="flex flex-wrap items-end gap-3 rounded-2xl border border-zinc-800 bg-zinc-900/90 p-4">
        <div>
          <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-zinc-500">Event</label>
          <select value={fEventType} onChange={(e) => { setFEventType(e.target.value); applyFilters(); }}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60">
            <option value="">All events</option>
            {EVENT_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
        </div>
        <div>
          <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-zinc-500">Actor</label>
          <select value={fActor} onChange={(e) => { setFActor(e.target.value); applyFilters(); }}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60">
            <option value="">All actors</option>
            <option value="system">System</option>
            <option value="user">User</option>
            <option value="scheduler">Scheduler</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-zinc-500">Severity</label>
          <select value={fSeverity} onChange={(e) => { setFSeverity(e.target.value); applyFilters(); }}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60">
            <option value="">All</option>
            {['critical', 'high', 'medium', 'low', 'safe'].map((sv) => <option key={sv} value={sv}>{sv}</option>)}
          </select>
        </div>
        <div className="min-w-40">
          <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-zinc-500">Sender</label>
          <input value={fSender} onChange={(e) => setFSender(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
            placeholder="search sender…"
            className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60" />
        </div>
        <div>
          <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-zinc-500">From</label>
          <input type="date" value={fFrom} onChange={(e) => { setFFrom(e.target.value); applyFilters(); }}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60" />
        </div>
        <div>
          <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-zinc-500">To</label>
          <input type="date" value={fTo} onChange={(e) => { setFTo(e.target.value); applyFilters(); }}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60" />
        </div>
        <button type="button" onClick={load}
          className="ml-auto flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-200 transition hover:border-red-500/40">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Table */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-zinc-100">
            Events <span className="font-mono text-xs text-zinc-500">({total} total)</span>
          </h2>
          <div className="flex items-center gap-2">
            <button type="button" disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="rounded border border-zinc-800 px-2 py-1 text-xs text-zinc-400 disabled:opacity-40 hover:text-red-400">
              Prev
            </button>
            <span className="font-mono text-[11px] text-zinc-500">page {page + 1}</span>
            <button type="button" disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)}
              className="rounded border border-zinc-800 px-2 py-1 text-xs text-zinc-400 disabled:opacity-40 hover:text-red-400">
              Next
            </button>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-10 text-sm text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading history…
          </div>
        ) : items.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">
            No security events recorded yet{fEventType || fActor || fSeverity || fSender ? ' for these filters' : ''}.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {items.map((event) => (
              <button
                key={event.id}
                type="button"
                onClick={() => setSelected(event)}
                className="flex w-full flex-wrap items-center gap-2.5 px-5 py-3 text-left transition hover:bg-zinc-900"
              >
                <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${ACTOR_STYLES[event.actor_type] ?? ACTOR_STYLES.user}`}>
                  {event.actor_type}
                </span>
                <span className="font-mono text-xs font-semibold text-zinc-100">{event.event_type.replace(/_/g, ' ')}</span>
                {event.severity && (
                  <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${SEVERITY_STYLES[event.severity] ?? SEVERITY_STYLES.safe}`}>
                    {event.severity}
                  </span>
                )}
                <span className="min-w-0 flex-1 truncate text-xs text-zinc-400">
                  {event.sender_email || event.subject || event.operation_detail || '—'}
                </span>
                {event.operation_status && (
                  <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase ${OP_STATUS_STYLES[event.operation_status] ?? OP_STATUS_STYLES.failed}`}>
                    {event.operation_status.replace(/_/g, ' ')}
                  </span>
                )}
                <span className="font-mono text-[11px] text-zinc-600">{formatWhen(event.created_at)}</span>
                <ChevronDown className="h-3.5 w-3.5 text-zinc-600" />
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Detail drawer */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/70 backdrop-blur-sm" onClick={() => setSelected(null)}>
          <div
            className="h-full w-full max-w-2xl overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <h3 className="font-mono text-base font-bold text-zinc-100">{selected.event_type.replace(/_/g, ' ')}</h3>
                <p className="mt-0.5 flex items-center gap-1.5 font-mono text-xs text-zinc-500">
                  <Clock className="h-3 w-3" /> {formatWhen(selected.created_at)}
                </p>
              </div>
              <button type="button" onClick={() => setSelected(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 p-1.5 text-zinc-400 transition hover:text-red-400">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mb-4 flex flex-wrap items-center gap-2">
              <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${ACTOR_STYLES[selected.actor_type] ?? ACTOR_STYLES.user}`}>
                {selected.actor_type}
              </span>
              {selected.severity && (
                <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${SEVERITY_STYLES[selected.severity] ?? SEVERITY_STYLES.safe}`}>
                  {selected.severity}
                </span>
              )}
              {selected.operation_status && (
                <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase ${OP_STATUS_STYLES[selected.operation_status] ?? OP_STATUS_STYLES.failed}`}>
                  {selected.operation_status.replace(/_/g, ' ')}
                </span>
              )}
              {selected.score !== null && (
                <span className="font-mono text-xs text-zinc-400">score {normalizeScorePct(selected.score)}/100</span>
              )}
            </div>

            {selected.sender_email && (
              <p className="mb-1 font-mono text-xs text-zinc-400">From: {selected.sender_email}</p>
            )}
            {selected.subject && (
              <p className="mb-3 text-sm text-zinc-200">{selected.subject}</p>
            )}
            {selected.explanation && (
              <div className="mb-4 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
                <h4 className="mb-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-red-400">Why</h4>
                <p className="whitespace-pre-line text-xs leading-relaxed text-zinc-300">{selected.explanation}</p>
              </div>
            )}

            <div className="mb-4 grid grid-cols-2 gap-3 text-xs">
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-3">
                <p className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">Action requested</p>
                <p className="mt-1 font-mono text-zinc-200">{selected.action_requested ?? '—'}</p>
              </div>
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-3">
                <p className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">Action performed</p>
                <p className="mt-1 font-mono text-zinc-200">{selected.action_performed ?? '—'}</p>
              </div>
            </div>

            {selected.operation_detail && (
              <div className="mb-4 rounded-xl border border-zinc-800 bg-zinc-900/60 p-3">
                <p className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">Provider operation</p>
                <p className="mt-1 text-xs leading-relaxed text-zinc-300">{selected.operation_detail}</p>
              </div>
            )}

            {selected.indicators.length > 0 && (
              <div className="overflow-hidden rounded-lg border border-zinc-800">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="bg-zinc-900 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                      <th className="px-3 py-2">Indicator</th>
                      <th className="px-3 py-2">Evidence</th>
                      <th className="px-3 py-2 text-right">Weight</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/70">
                    {selected.indicators.map((ind, idx) => (
                      <tr key={idx} className="text-zinc-300">
                        <td className="px-3 py-2 font-mono text-[11px] text-zinc-400">{ind.name}</td>
                        <td className="max-w-sm break-words px-3 py-2">{ind.value}</td>
                        <td className="px-3 py-2 text-right font-mono text-zinc-500">{ind.weight}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
