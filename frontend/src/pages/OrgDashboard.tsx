/**
 * ORG-DASHBOARD-P1 — org workspace dashboard.
 *
 * Two tabs hosted inside OrgWorkspaceShell:
 *   Overview      — 3 analyzer cards (24h count + severity bar + engine badge)
 *                   and the last 10 events with a Review jump (P2 builds the
 *                   review page)
 *   Live Counters — read-only realtime counters grid + LIVE/DISCONNECTED
 *                   pill + manual Resync. Zero input elements: pure
 *                   monitoring, no forms, no filters.
 *
 * Counters come from useOrgLiveCounters: one seed fetch, then realtime
 * deltas only (no polling).
 */

import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { orgApi, type OrgEventRow } from '../services/orgApi';
import { useOrgLiveCounters } from '../hooks/useOrgLiveCounters';
import { SEVERITY_STYLES } from '../components/common/SeverityBadge';
import SeverityBadge from '../components/common/SeverityBadge';
import { formatLocal } from '../utils/datetime';

type DashboardTab = 'overview' | 'counters';

const ANALYZERS = [
  { key: 'log' as const, label: 'Log Analysis', engine: 'log_analyzer' },
  { key: 'ato' as const, label: 'Account Takeover', engine: 'account_takeover_detector' },
  { key: 'network' as const, label: 'Network Threat', engine: 'network_threat_detector' },
];

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

const VERDICT_LABELS: Record<string, string> = {
  pending_review: 'Pending review',
  released: 'Released',
  blocked_permanently: 'Blocked',
  false_positive: 'False positive',
};

export default function OrgDashboard() {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  const navigate = useNavigate();
  const [tab, setTab] = useState<DashboardTab>('overview');
  const { counters, isConnected, resync } = useOrgLiveCounters(orgId, projectId);
  const [recent, setRecent] = useState<OrgEventRow[]>([]);

  useEffect(() => {
    if (!orgId || !projectId) return;
    let cancelled = false;
    orgApi
      .listRecentEvents(orgId, projectId, 10)
      .then((rows) => {
        if (!cancelled) setRecent(rows);
      })
      .catch(() => {
        if (!cancelled) setRecent([]);
      });
    return () => {
      cancelled = true;
    };
  }, [orgId, projectId]);

  const totalSev = counters
    ? SEVERITY_ORDER.reduce((sum, s) => sum + counters.by_severity[s], 0)
    : 0;

  return (
    <div className="p-6 space-y-5" data-testid="org-dashboard-page">
      <div className="flex items-center gap-2 border-b border-zinc-800">
        {(['overview', 'counters'] as DashboardTab[]).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            aria-current={tab === t ? 'page' : undefined}
            data-testid={`dashboard-tab-${t}`}
            className={`px-4 py-2 text-sm rounded-t-lg border border-b-0 -mb-px transition-colors ${
              tab === t
                ? 'border-zinc-800 bg-zinc-900 text-zinc-100'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {t === 'overview' ? 'Overview' : 'Live Counters'}
          </button>
        ))}
      </div>

      {tab === 'overview' ? (
        <OverviewTab
          counters={counters}
          totalSev={totalSev}
          recent={recent}
          orgId={orgId}
          projectId={projectId}
          onReview={(eventId) =>
            navigate(`/org/${orgId}/projects/${projectId}/events/${eventId}/review`)
          }
        />
      ) : (
        <CountersTab counters={counters} isConnected={isConnected} onResync={resync} />
      )}
    </div>
  );
}

function OverviewTab({
  counters,
  totalSev,
  recent,
  orgId,
  projectId,
  onReview,
}: {
  counters: ReturnType<typeof useOrgLiveCounters>['counters'];
  totalSev: number;
  recent: OrgEventRow[];
  orgId?: string;
  projectId?: string;
  onReview: (eventId: string) => void;
}) {
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-3">
        {ANALYZERS.map((a) => {
          const count = counters ? counters.by_type[a.key] : null;
          return (
            <div
              key={a.key}
              className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3"
              data-testid={`analyzer-card-${a.key}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm text-zinc-300">{a.label}</span>
                <span className="text-[10px] uppercase tracking-wider rounded bg-zinc-800 px-1.5 py-0.5 text-zinc-400">
                  {a.engine}
                </span>
              </div>
              <div className="text-2xl font-semibold text-zinc-100" data-testid={`analyzer-count-${a.key}`}>
                {count === null ? '—' : count}
              </div>
              <div className="text-xs text-zinc-500">events (24h)</div>
              <div className="flex h-2 w-full overflow-hidden rounded-full bg-zinc-800">
                {SEVERITY_ORDER.map((s) => {
                  const value = counters ? counters.by_severity[s] : 0;
                  const width = totalSev > 0 ? (value / totalSev) * 100 : 0;
                  return (
                    <div
                      key={s}
                      className={SEVERITY_STYLES[s].bg}
                      style={{ width: `${width}%` }}
                      title={`${s}: ${value}`}
                    />
                  );
                })}
              </div>
              <div className="flex gap-3 text-[10px] text-zinc-500">
                {SEVERITY_ORDER.map((s) => (
                  <span key={s} className="inline-flex items-center gap-1">
                    <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_STYLES[s].dot}`} />
                    {counters ? counters.by_severity[s] : 0} {s}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
        <div className="px-4 py-3 border-b border-zinc-800 text-sm text-zinc-300">
          Recent events <span className="text-zinc-500">(last 10)</span>
        </div>
        <table className="w-full text-sm" data-testid="recent-events-table">
          <thead>
            <tr className="text-left text-xs text-zinc-500 border-b border-zinc-800">
              <th className="px-4 py-2 font-medium">Timestamp</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Severity</th>
              <th className="px-4 py-2 font-medium">Verdict</th>
              <th className="px-4 py-2 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {recent.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-zinc-500">
                  No events yet — ship traffic to the gateway to populate the feed.
                </td>
              </tr>
            )}
            {recent.map((e) => (
              <tr key={e.id} className="border-b border-zinc-800/60 last:border-0">
                <td className="px-4 py-2 text-zinc-400 whitespace-nowrap">{formatLocal(e.created_at)}</td>
                <td className="px-4 py-2 text-zinc-300">{e.event_type}</td>
                <td className="px-4 py-2">
                  <SeverityBadge severity={e.severity as never} />
                </td>
                <td className="px-4 py-2 text-zinc-400">{VERDICT_LABELS[e.verdict] ?? e.verdict}</td>
                <td className="px-4 py-2 text-right">
                  <button
                    type="button"
                    onClick={() => onReview(e.id)}
                    data-testid={`review-btn-${e.id}`}
                    className="text-xs rounded-lg border border-zinc-700 px-2.5 py-1 text-zinc-300 hover:bg-zinc-800"
                  >
                    Review
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {/* orgId/projectId retained for P2's review-page deep links */}
      <span className="hidden">{`${orgId ?? ''}${projectId ?? ''}`}</span>
    </div>
  );
}

function CountersTab({
  counters,
  isConnected,
  onResync,
}: {
  counters: ReturnType<typeof useOrgLiveCounters>['counters'];
  isConnected: boolean;
  onResync: () => void;
}) {
  const value = (v: number | undefined) => (v === undefined ? '—' : String(v));
  const tiles: Array<{ label: string; value: number | undefined; testid: string }> = counters
    ? [
        { label: 'Total events (24h)', value: counters.total_24h, testid: 'counter-total' },
        { label: 'Critical', value: counters.by_severity.critical, testid: 'counter-critical' },
        { label: 'High', value: counters.by_severity.high, testid: 'counter-high' },
        { label: 'Medium', value: counters.by_severity.medium, testid: 'counter-medium' },
        { label: 'Low', value: counters.by_severity.low, testid: 'counter-low' },
        { label: 'Log events', value: counters.by_type.log, testid: 'counter-log' },
        { label: 'ATO events', value: counters.by_type.ato, testid: 'counter-ato' },
        { label: 'Network events', value: counters.by_type.network, testid: 'counter-network' },
        { label: 'Pending review', value: counters.pending_review, testid: 'counter-pending' },
        {
          label: 'Blocked indicators',
          value: counters.blocked_indicators_count,
          testid: 'counter-blocked-indicators',
        },
      ]
    : [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span
          data-testid="live-status-pill"
          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs ring-1 ${
            isConnected
              ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/40'
              : 'bg-amber-500/10 text-amber-300 ring-amber-500/40'
          }`}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${isConnected ? 'bg-emerald-400' : 'bg-amber-400'}`}
          />
          {isConnected ? 'LIVE' : 'DISCONNECTED'}
        </span>
        <button
          type="button"
          onClick={onResync}
          data-testid="resync-btn"
          className="text-xs rounded-lg border border-zinc-700 px-3 py-1.5 text-zinc-300 hover:bg-zinc-800"
        >
          Resync
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-5" data-testid="counters-grid">
        {counters === null && (
          <div className="text-sm text-zinc-500 sm:col-span-3 lg:col-span-5">
            Counters not loaded yet — press Resync.
          </div>
        )}
        {tiles.map((t) => (
          <div
            key={t.testid}
            data-testid={t.testid}
            className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
          >
            <div className="text-2xl font-semibold text-zinc-100">{value(t.value)}</div>
            <div className="mt-1 text-xs text-zinc-500">{t.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
