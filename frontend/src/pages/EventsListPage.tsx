/**
 * ORG-DASHBOARD-P3 — project events list with filters + pagination.
 *
 * Route: /org/:orgId/projects/:projectId/events (hosted in OrgWorkspaceShell;
 * sidebar triad item "Events" — review pages highlight the same family via
 * startsWith).
 *
 * Toolbar: debounced (300 ms) search + event_type / severity / verdict
 * selects + Refresh. Table: Created (relative, absolute on hover) | Type
 * badge | Severity badge | Risk | Verdict badge | Review link.
 *
 * Pagination follows the backend contract — offset/limit with a total
 * (there is no cursor param server-side): "Load more" appends the next
 * offset page, header shows "N of M" from total. The dashboard owns the
 * live feed; this page is deliberately static per query (no realtime
 * prepend) — Refresh re-queries.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Search, RotateCw } from 'lucide-react';
import {
  appendEvents,
  eventsQueryParams,
  orgApi,
  type EventsListFilters,
  type OrgEventRow,
} from '../services/orgApi';
import SeverityBadge from '../components/common/SeverityBadge';
import { formatLocal } from '../utils/datetime';
import {
  EVENT_TYPE_LABELS,
  VERDICT_CHIP_CLASSES,
  VERDICT_LABELS,
  relativeTime,
} from './eventsListHelpers';

const PAGE_SIZE = 50;

interface FilterState {
  q: string;
  eventType: string;
  severity: string;
  verdict: string;
}

const EMPTY_FILTERS: FilterState = { q: '', eventType: '', severity: '', verdict: '' };

export default function EventsListPage() {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS);
  const [debouncedQ, setDebouncedQ] = useState('');
  const [rows, setRows] = useState<OrgEventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const reloadRef = useRef(0);

  // Debounce the search input (300 ms) — filters other than q apply instantly.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(filters.q.trim()), 300);
    return () => clearTimeout(t);
  }, [filters.q]);

  const fetchPage = useCallback(
    async (nextOffset: number, append: boolean) => {
      if (!orgId || !projectId) return;
      setLoading(true);
      setError(false);
      try {
        const listFilters: EventsListFilters = {
          eventType: filters.eventType || undefined,
          severity: filters.severity || undefined,
          verdict: filters.verdict || undefined,
          q: debouncedQ || undefined,
          limit: PAGE_SIZE,
          offset: nextOffset,
        };
        const data = await orgApi.listEvents(orgId, projectId, listFilters);
        setRows((prev) => (append ? appendEvents(prev, data.events) : data.events));
        setTotal(data.total);
        setOffset(nextOffset);
      } catch {
        setError(true);
        if (!append) setRows([]);
      } finally {
        setLoading(false);
      }
    },
    [orgId, projectId, filters.eventType, filters.severity, filters.verdict, debouncedQ]
  );

  // Re-query page 1 whenever any filter (incl. debounced search) changes.
  useEffect(() => {
    void fetchPage(0, false);
  }, [fetchPage, reloadRef.current]);

  const hasMore = rows.length < total;
  const activeFilterCount =
    (filters.eventType ? 1 : 0) + (filters.severity ? 1 : 0) + (filters.verdict ? 1 : 0) + (debouncedQ ? 1 : 0);

  function clearFilters() {
    setFilters(EMPTY_FILTERS);
    setDebouncedQ('');
  }

  return (
    <div className="p-6 space-y-4" data-testid="events-list-page">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Events</h1>
        {total > 0 && (
          <span className="text-xs text-zinc-500" data-testid="events-count">
            {Math.min(rows.length, total)} of {total}
          </span>
        )}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2" data-testid="events-toolbar">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-zinc-500" />
          <input
            type="text"
            value={filters.q}
            onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
            placeholder="Search payloads and indicators…"
            data-testid="events-search"
            className="w-64 rounded-lg border border-zinc-800 bg-zinc-900/60 py-1.5 pl-8 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-red-500/40"
          />
        </div>

        <select
          value={filters.eventType}
          onChange={(e) => setFilters((f) => ({ ...f, eventType: e.target.value }))}
          data-testid="filter-type"
          className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-2.5 py-1.5 text-sm text-zinc-300"
        >
          <option value="">Type: All</option>
          <option value="network_event">Network</option>
          <option value="ato_event">ATO</option>
          <option value="log_event">Log</option>
        </select>

        <select
          value={filters.severity}
          onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}
          data-testid="filter-severity"
          className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-2.5 py-1.5 text-sm text-zinc-300"
        >
          <option value="">Severity: All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={filters.verdict}
          onChange={(e) => setFilters((f) => ({ ...f, verdict: e.target.value }))}
          data-testid="filter-verdict"
          className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-2.5 py-1.5 text-sm text-zinc-300"
        >
          <option value="">Verdict: All</option>
          <option value="pending_review">Pending review</option>
          <option value="released">Released</option>
          <option value="blocked_permanently">Blocked permanently</option>
          <option value="false_positive">False positive</option>
        </select>

        <button
          type="button"
          data-testid="events-refresh"
          onClick={() => void fetchPage(0, false)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800"
        >
          <RotateCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm text-red-300" data-testid="events-error">
          Failed to load events — press Refresh to retry.
        </div>
      )}

      {/* Table */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
        <table className="w-full text-sm" data-testid="events-table">
          <thead>
            <tr className="text-left text-xs text-zinc-500 border-b border-zinc-800">
              <th className="px-4 py-2 font-medium">Created</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Severity</th>
              <th className="px-4 py-2 font-medium">Risk</th>
              <th className="px-4 py-2 font-medium">Verdict</th>
              <th className="px-4 py-2 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && !loading && !error && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-zinc-500" data-testid="events-empty">
                  No events match filters
                  {activeFilterCount > 0 && (
                    <span className="ml-2">
                      <button
                        type="button"
                        data-testid="clear-filters"
                        onClick={clearFilters}
                        className="rounded-lg border border-zinc-700 px-2.5 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
                      >
                        Clear filters
                      </button>
                    </span>
                  )}
                </td>
              </tr>
            )}
            {rows.map((e) => (
              <tr key={e.id} className="border-b border-zinc-800/60 last:border-0">
                <td className="px-4 py-2 text-zinc-400 whitespace-nowrap" title={formatLocal(e.created_at)}>
                  {relativeTime(e.created_at)}
                </td>
                <td className="px-4 py-2">
                  <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300">
                    {EVENT_TYPE_LABELS[e.event_type] ?? e.event_type}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <SeverityBadge severity={e.severity as never} />
                </td>
                <td className="px-4 py-2 text-zinc-300">{e.analysis_result?.risk_score ?? '—'}</td>
                <td className="px-4 py-2">
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-xs ring-1 ${VERDICT_CHIP_CLASSES[e.verdict] ?? 'bg-zinc-800 text-zinc-300 ring-zinc-700'}`}
                  >
                    {VERDICT_LABELS[e.verdict] ?? e.verdict}
                  </span>
                </td>
                <td className="px-4 py-2 text-right">
                  <Link
                    to={`/org/${orgId}/projects/${projectId}/events/${e.id}/review`}
                    data-testid={`review-link-${e.id}`}
                    className="text-xs rounded-lg border border-zinc-700 px-2.5 py-1 text-zinc-300 hover:bg-zinc-800"
                  >
                    Review
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {rows.length > 0 && (
          <div className="flex items-center justify-center border-t border-zinc-800 px-4 py-3">
            {hasMore ? (
              <button
                type="button"
                data-testid="load-more"
                disabled={loading}
                onClick={() => void fetchPage(offset + PAGE_SIZE, true)}
                className="rounded-lg border border-zinc-700 px-4 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-40"
              >
                {loading ? 'Loading…' : 'Load more'}
              </button>
            ) : (
              <span className="text-xs text-zinc-600" data-testid="end-of-list">
                All {total} events loaded
              </span>
            )}
          </div>
        )}
      </div>
      {/* query string builder is exercised for testability/debugging */}
      <span className="hidden">{eventsQueryParams({ limit: 1 })}</span>
    </div>
  );
}
