import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  RefreshCw,
  Search,
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { useUiStore } from '../store/uiStore';
import { orgApi, type OrgEvent } from '../services/orgApi';

export default function OrgEventsList() {
  const { orgId: paramOrgId } = useParams<{ orgId?: string }>();
  const navigate = useNavigate();
  const addToast = useUiStore((s) => s.addToast);
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const activeProjectId = useAuthStore((s) => s.activeProjectId);

  const orgId = paramOrgId || activeOrganization?.id || '';

  const [events, setEvents] = useState<OrgEvent[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);

  // Filters
  const [eventType, setEventType] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [verdict, setVerdict] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const loadEvents = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const data = await orgApi.listEvents(orgId, {
        projectId: activeProjectId || undefined,
        eventType: eventType || undefined,
        severity: severity || undefined,
        verdict: verdict || undefined,
        q: searchQuery.trim() || undefined,
        limit: 50,
      });
      setEvents(data.events);
      setTotal(data.total);
    } catch (err: any) {
      addToast(err?.message || 'Failed to load events', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, activeProjectId, eventType, severity, verdict, searchQuery, addToast]);

  useEffect(() => {
    void loadEvents();
  }, [loadEvents]);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text">Security Events</h1>
          <p className="text-xs text-text-muted mt-1">
            Browse and triage telemetry events ingested via the project gateway. Total: {total}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadEvents()}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="bg-surface border border-border rounded-lg p-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
        {/* Search */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search source or ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-zinc-900 border border-border rounded-md pl-8 pr-3 py-1.5 text-xs text-text focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        {/* Type */}
        <select
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          className="bg-zinc-900 border border-border rounded-md px-3 py-1.5 text-xs text-text"
        >
          <option value="">All Event Types</option>
          <option value="log">Log Analysis</option>
          <option value="ato">Account Takeover</option>
          <option value="network">Network Threat</option>
        </select>

        {/* Severity */}
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="bg-zinc-900 border border-border rounded-md px-3 py-1.5 text-xs text-text"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Verdict */}
        <select
          value={verdict}
          onChange={(e) => setVerdict(e.target.value)}
          className="bg-zinc-900 border border-border rounded-md px-3 py-1.5 text-xs text-text"
        >
          <option value="">All Verdicts</option>
          <option value="pending_review">Pending Review</option>
          <option value="released">Released</option>
          <option value="blocked_permanently">Blocked Permanently</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>

      {/* Events Table */}
      <div className="bg-surface border border-border rounded-lg overflow-hidden">
        {loading ? (
          <p className="text-xs text-text-muted py-12 text-center">Loading events...</p>
        ) : events.length === 0 ? (
          <p className="text-xs text-text-muted py-12 text-center">
            No events match your current filter criteria.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-border text-text-muted bg-zinc-900/40">
                  <th className="py-2.5 px-4">Event Type</th>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">Verdict</th>
                  <th className="py-2.5 px-4">Source</th>
                  <th className="py-2.5 px-4">Ingested At</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-zinc-900/30 transition-colors">
                    <td className="py-3 px-4 font-semibold text-text uppercase">
                      {ev.event_type}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          ev.severity === 'critical'
                            ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                            : ev.severity === 'high'
                            ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                            : ev.severity === 'medium'
                            ? 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30'
                            : 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                        }`}
                      >
                        {ev.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-zinc-300">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-medium ${
                          ev.verdict === 'pending_review'
                            ? 'bg-amber-500/10 text-amber-300'
                            : ev.verdict === 'released'
                            ? 'bg-emerald-500/10 text-emerald-300'
                            : ev.verdict === 'blocked_permanently'
                            ? 'bg-red-500/10 text-red-300'
                            : 'bg-zinc-800 text-zinc-300'
                        }`}
                      >
                        {ev.verdict}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-text-muted">{ev.source}</td>
                    <td className="py-3 px-4 text-text-muted">
                      {new Date(ev.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={() =>
                          navigate(
                            `/org/${orgId}/projects/${ev.project_id}/events/${ev.id}`
                          )
                        }
                        className="px-2.5 py-1 text-[11px] font-medium rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors"
                      >
                        Review
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
