import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Loader2, RefreshCw, Search, X } from 'lucide-react';
import PageHeader from '../common/PageHeader';
import OrgIngestionStrip from './OrgIngestionStrip';
import { useOrgMode } from '../../hooks/useOrgMode';
import { useOrgRealtime } from '../../hooks/useOrgRealtime';
import { useUiStore } from '../../store/uiStore';
import * as orgApi from '../../services/orgApi';
import type { StreamFeature, StreamRow } from '../../services/orgApi';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 ring-red-500/40',
  high: 'bg-orange-500/10 text-orange-400 ring-orange-500/40',
  medium: 'bg-amber-500/10 text-amber-400 ring-amber-500/40',
  low: 'bg-zinc-700/30 text-zinc-300 ring-zinc-600/40',
  safe: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
  info: 'bg-zinc-700/30 text-zinc-400 ring-zinc-600/40',
};

const SOURCE_STYLES: Record<string, string> = {
  gateway: 'bg-red-500/10 text-red-300 ring-red-500/30',
  connector: 'bg-blue-500/10 text-blue-300 ring-blue-500/30',
  pipeline: 'bg-purple-500/10 text-purple-300 ring-purple-500/30',
  'manual-org': 'bg-zinc-700/30 text-zinc-300 ring-zinc-600/40',
};

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'safe', 'info'];
const SOURCE_OPTIONS = ['gateway', 'connector', 'pipeline', 'manual-org'];
const RANGE_OPTIONS: [string, string][] = [
  ['1h', 'Last hour'],
  ['24h', 'Last 24 hours'],
  ['7d', 'Last 7 days'],
  ['all', 'All time'],
];

function formatTs(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

/**
 * ORG-LIVE-VIEWS: read-only Splunk-style monitored event stream for one
 * feature, scoped to the active project (or org-wide). Rows come from the
 * streams endpoint (10 s poll, toggleable) and refresh instantly on
 * Supabase realtime pushes (alerts / org_log_events). No entry forms, no
 * create/analyze buttons — this page only watches.
 */
export default function OrgLiveStream({
  feature,
  title,
  description,
}: {
  feature: StreamFeature;
  title: string;
  description: string;
}) {
  const { orgId, projectSlug, projectId } = useOrgMode();
  const addToast = useUiStore((s) => s.addToast);

  const [rows, setRows] = useState<orgApi.StreamRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [realtimeLive, setRealtimeLive] = useState(false);
  const [severity, setSeverity] = useState('');
  const [source, setSource] = useState('');
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [range, setRange] = useState('24h');
  const [drawerId, setDrawerId] = useState<string | null>(null);
  const [detail, setDetail] = useState<orgApi.StreamDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Debounce the search box so typing doesn't hammer the API.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim()), 350);
    return () => clearTimeout(t);
  }, [search]);

  const fetchStream = useCallback(async () => {
    if (!orgId) return;
    try {
      const res = await orgApi.getOrgStream(orgId, projectSlug, feature, {
        severity: severity || undefined,
        source: source || undefined,
        q: debouncedSearch || undefined,
        range,
        limit: 100,
      });
      // Newest-first merge, deduped by id (refetch is authoritative).
      const merged = new Map<string, orgApi.StreamRow>();
      for (const r of res.rows) merged.set(r.id, r);
      setRows([...merged.values()]);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load event stream', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, projectSlug, feature, severity, source, debouncedSearch, range, addToast]);

  useEffect(() => {
    setLoading(true);
    fetchStream();
  }, [fetchStream]);

  // 10 s poll fallback (toggleable) — realtime covers the gaps.
  useEffect(() => {
    if (!autoRefresh || !orgId) return;
    const t = setInterval(fetchStream, 10000);
    return () => clearInterval(t);
  }, [autoRefresh, fetchStream, orgId]);

  // Realtime: any push for the org's alerts/log events triggers a refetch.
  const bumpRef = useRef(fetchStream);
  bumpRef.current = fetchStream;
  useOrgRealtime('alerts', orgId ?? undefined, () => bumpRef.current(), setRealtimeLive);
  useOrgRealtime('org_log_events', orgId ?? undefined, () => bumpRef.current(), setRealtimeLive);

  const openDetail = useCallback(
    async (row: StreamRow) => {
      if (!orgId) return;
      setDrawerId(row.id);
      setDetail(null);
      setDetailLoading(true);
      try {
        setDetail(await orgApi.getOrgStreamDetail(orgId, projectSlug, feature, row.id));
      } catch (err) {
        addToast(err instanceof Error ? err.message : 'Failed to load event detail', 'high');
        setDrawerId(null);
      } finally {
        setDetailLoading(false);
      }
    },
    [orgId, projectSlug, feature, addToast],
  );

  const severityEntries = useMemo(() => {
    if (!detail) return [];
    const raw = detail.analysis.indicators ?? [];
    return raw
      .map((i) => ({
        type: String((i as Record<string, unknown>).type ?? (i as Record<string, unknown>).name ?? 'indicator'),
        value: String((i as Record<string, unknown>).value ?? ''),
        severity: String((i as Record<string, unknown>).severity ?? 'low'),
        description: String((i as Record<string, unknown>).description ?? ''),
        weight: (i as Record<string, unknown>).weight,
      }))
      .filter((i) => i.type || i.description);
  }, [detail]);

  if (!orgId) {
    // Non-org renderers never mount this component (route gate), but guard anyway.
    return <div className="p-6 text-sm text-zinc-400">No organization workspace selected.</div>;
  }

  return (
    <div className="space-y-4">
      <PageHeader title={title} description={description} />

      {/* Ingestion strip + status controls */}
      <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <OrgIngestionStrip orgId={orgId} projectId={projectId} />
        <div className="flex items-center gap-2">
          {realtimeLive ? (
            <span
              title="Subscribed to live org events (Supabase realtime)"
              className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-400"
            >
              <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
              LIVE
            </span>
          ) : (
            <span
              title="Realtime unavailable — 10s polling fallback active"
              className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs font-semibold text-amber-300"
            >
              <span className="h-2 w-2 rounded-full bg-amber-400" />
              POLLING
            </span>
          )}
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            title="Toggle 10s auto-refresh"
            className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition ${
              autoRefresh
                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                : 'border-zinc-700 bg-zinc-900 text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${autoRefresh ? 'animate-spin [animation-duration:3s]' : ''}`} />
            Auto-refresh {autoRefresh ? 'on' : 'off'}
          </button>
          <button
            onClick={() => fetchStream()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs text-zinc-300 transition hover:border-zinc-500"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* Filters row */}
      <div className="grid gap-2 rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-3 backdrop-blur sm:grid-cols-2 lg:grid-cols-4">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-zinc-700/60 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 outline-none focus:border-red-500/60"
        >
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s.toUpperCase()}
            </option>
          ))}
        </select>
        <select
          value={source}
          onChange={(e) => setSource(e.target.value)}
          className="rounded-lg border border-zinc-700/60 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 outline-none focus:border-red-500/60"
        >
          <option value="">All sources</option>
          {SOURCE_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={range}
          onChange={(e) => setRange(e.target.value)}
          className="rounded-lg border border-zinc-700/60 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 outline-none focus:border-red-500/60"
        >
          {RANGE_OPTIONS.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search summaries..."
            className="w-full rounded-lg border border-zinc-700/60 bg-zinc-800 py-2 pl-9 pr-3 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-red-500/60"
          />
        </div>
      </div>

      {/* Stream table */}
      <div className="overflow-hidden rounded-xl border border-zinc-700/50 bg-zinc-850/40 backdrop-blur">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-zinc-700/50 bg-zinc-900/90 font-semibold uppercase tracking-wider text-zinc-400">
                <th className="px-4 py-3">Time</th>
                <th className="px-3 py-3">Severity</th>
                <th className="px-3 py-3">Source</th>
                <th className="px-3 py-3">Summary</th>
                <th className="px-3 py-3 text-right">Risk</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/80">
              {loading && rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-zinc-500">
                    <Loader2 className="mx-auto h-5 w-5 animate-spin" />
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-10 text-center text-zinc-500">
                    <p className="text-sm font-medium text-zinc-400">
                      No monitored events yet for this project.
                    </p>
                    <p className="mt-1 text-xs text-zinc-500">
                      Events stream here automatically as traffic passes through the project
                      gateway, mail connectors, and the realtime pipeline.
                    </p>
                  </td>
                </tr>
              ) : (
                rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => openDetail(row)}
                    className="cursor-pointer transition-colors hover:bg-zinc-800/50"
                  >
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-zinc-400">
                      {formatTs(row.ts)}
                    </td>
                    <td className="px-3 py-3">
                      <span
                        className={`inline-block rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase ring-1 ${
                          SEVERITY_STYLES[row.severity ?? 'info'] ?? SEVERITY_STYLES.info
                        }`}
                      >
                        {row.severity ?? '—'}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <span
                        className={`inline-block rounded px-2 py-0.5 font-mono text-[10px] uppercase ring-1 ${
                          SOURCE_STYLES[row.source] ?? SOURCE_STYLES['manual-org']
                        }`}
                      >
                        {row.source}
                      </span>
                    </td>
                    <td className="max-w-md px-3 py-3">
                      <span className="block truncate text-zinc-200" title={row.summary ?? undefined}>
                        {row.summary ?? '—'}
                      </span>
                      <span className="font-mono text-[10px] text-zinc-600">{row.event_type}</span>
                    </td>
                    <td className="px-3 py-3 text-right font-mono font-semibold text-zinc-100">
                      {row.risk_score ?? '—'}
                    </td>
                    <td className="px-4 py-3 text-zinc-400">{row.status ?? '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      <p className="text-center text-[11px] text-zinc-600">
        Showing {rows.length} monitored event{rows.length === 1 ? '' : 's'}
        {projectSlug ? ` · project ${projectSlug}` : ' · all projects (org-wide)'}
      </p>

      {/* Right drawer: event detail */}
      {drawerId && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
          <div
            className="h-full w-full max-w-2xl overflow-y-auto border-l border-zinc-700/80 bg-zinc-900 p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between border-b border-zinc-800 pb-4">
              <div>
                <h3 className="text-base font-bold text-zinc-100">
                  {detail?.analysis.title ?? detail?.row.summary ?? 'Event detail'}
                </h3>
                <p className="mt-0.5 font-mono text-[11px] text-zinc-500">
                  {detail ? `${detail.row.event_type} · ${detail.row.source} · ${formatTs(detail.row.ts)}` : 'Loading…'}
                </p>
              </div>
              <button
                onClick={() => setDrawerId(null)}
                className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {detailLoading ? (
              <div className="flex items-center gap-2 py-8 text-sm text-zinc-500">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading analysis…
              </div>
            ) : detail ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3 text-xs">
                  {(
                    [
                      ['Severity', detail.row.severity ?? '—'],
                      ['Risk score', String(detail.row.risk_score ?? '—')],
                      ['Status', detail.row.status ?? '—'],
                      ['Source', detail.row.source],
                    ] as const
                  ).map(([label, value]) => (
                    <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3">
                      <span className="block text-[10px] uppercase tracking-wider text-zinc-500">{label}</span>
                      <span className="mt-1 block font-mono text-zinc-200">{value}</span>
                    </div>
                  ))}
                </div>

                {(detail.analysis.explanation || detail.analysis.summary) && (
                  <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-4">
                    <h4 className="mb-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-red-400">
                      Why this verdict
                    </h4>
                    <p className="whitespace-pre-line text-sm leading-relaxed text-zinc-300">
                      {detail.analysis.explanation || detail.analysis.summary}
                    </p>
                  </div>
                )}

                {severityEntries.length > 0 && (
                  <div className="overflow-hidden rounded-xl border border-zinc-800">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="bg-zinc-900 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                          <th className="px-3 py-2">Indicator</th>
                          <th className="px-3 py-2">Evidence</th>
                          <th className="px-3 py-2 text-right">Weight</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-800/70">
                        {severityEntries.map((ind, i) => (
                          <tr key={i} className="text-zinc-300">
                            <td className="px-3 py-2 font-mono text-[11px] text-zinc-400">{ind.type}</td>
                            <td className="max-w-md break-words px-3 py-2">
                              {ind.value && <span className="mb-0.5 block font-mono text-[11px] text-zinc-200">{ind.value}</span>}
                              <span className="text-zinc-500">{ind.description}</span>
                            </td>
                            <td className="px-3 py-2 text-right font-mono text-zinc-500">
                              {ind.weight !== undefined ? String(ind.weight) : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {detail.analysis.analysis_result && (
                  <div>
                    <h4 className="mb-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">
                      Stored analysis result
                    </h4>
                    <pre className="max-h-64 overflow-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3.5 font-mono text-[11px] text-zinc-300">
                      {JSON.stringify(detail.analysis.analysis_result, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
