/**
 * ATO-UI-OVERHAUL — Account Takeover list view (default sidebar target).
 *
 * Searchable table of recent org-flow ATO events (search filters in
 * real-time by event id or account email, client-side over the server-
 * scoped list). Clicking a row opens the read-only detail view at
 * /org/:orgId/projects/:projectId/analysis/account-takeover/:eventId.
 * The organization scope is resolved server-side from the session —
 * no org id in any request body or query parameter.
 */

import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Search, ShieldAlert } from 'lucide-react';
import { orgApi, type AtoEventSummary } from '../services/orgApi';
import SeverityBadge from '../components/common/SeverityBadge';
import { formatLocal } from '../utils/datetime';
import {
  atoScoreTone,
  atoStatusTone,
  filterAtoEvents,
} from './orgAtoHelpers';

export default function OrgAccountTakeoverList() {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  const navigate = useNavigate();
  const [events, setEvents] = useState<AtoEventSummary[] | null>(null);
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!orgId) return;
    let cancelled = false;
    orgApi
      .listAtoEvents(orgId)
      .then((rows) => {
        if (!cancelled) setEvents(rows);
      })
      .catch((err) => {
        if (!cancelled) {
          setEvents([]);
          setError(err instanceof Error ? err.message : 'Failed to load ATO events.');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [orgId]);

  const filtered = filterAtoEvents(events ?? [], query);

  return (
    <div className="p-6 space-y-5" data-testid="org-ato-list-page">
      <div className="flex items-center gap-3">
        <ShieldAlert className="text-red-400" style={{ width: 24, height: 24 }} />
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Account Takeover</h1>
          <p className="text-sm text-zinc-500">
            Abnormal-behaviour analyses for this project. Scope is resolved
            server-side from your session.
          </p>
        </div>
      </div>

      {/* Top bar: real-time search by event id or account email */}
      <div className="relative max-w-md">
        <Search
          className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500"
          style={{ width: 15, height: 15 }}
        />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by event ID or email…"
          data-testid="ato-search-input"
          className="w-full rounded-lg border border-zinc-700 bg-zinc-950 py-2 pl-9 pr-3 text-sm text-zinc-100 placeholder:text-zinc-600"
        />
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300" data-testid="ato-list-error">
          {error}
        </div>
      )}

      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
        <table className="w-full text-sm" data-testid="ato-list-table">
          <thead>
            <tr className="text-left text-xs text-zinc-500 border-b border-zinc-800">
              <th className="px-4 py-3 font-medium">Timestamp</th>
              <th className="px-4 py-3 font-medium">Account</th>
              <th className="px-4 py-3 font-medium">Risk Score</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Severity</th>
            </tr>
          </thead>
          <tbody>
            {events === null && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-zinc-500">
                  Loading ATO events…
                </td>
              </tr>
            )}
            {events !== null && filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-zinc-500" data-testid="ato-list-empty">
                  {query
                    ? `No ATO events match “${query}”.`
                    : 'No account-takeover events yet — run scenarios/scenario-3 to seed traffic.'}
                </td>
              </tr>
            )}
            {filtered.map((event) => {
              const status = atoStatusTone(event.action_taken);
              return (
                <tr
                  key={event.id}
                  onClick={() =>
                    navigate(
                      `/org/${orgId}/projects/${projectId}/analysis/account-takeover/${event.id}`
                    )
                  }
                  data-testid="ato-list-row"
                  data-ato-event-id={event.id}
                  className="cursor-pointer border-b border-zinc-800/60 last:border-0 hover:bg-zinc-800/40"
                >
                  <td className="px-4 py-3 text-zinc-400 whitespace-nowrap">{formatLocal(event.timestamp)}</td>
                  <td className="px-4 py-3 text-zinc-200">{event.user_email}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold font-mono ${atoScoreTone(event.risk_score)}`}
                      data-testid="ato-score-badge"
                    >
                      {event.risk_score}/100
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ${status.className}`}
                      data-testid="ato-status-badge"
                    >
                      {status.label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={(event.severity ?? 'low') as never} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
