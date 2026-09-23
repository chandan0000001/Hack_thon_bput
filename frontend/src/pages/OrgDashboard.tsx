import { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  ExternalLink,
  FolderOpen,
  Radio,
  RefreshCw,
  ShieldAlert,
  Terminal,
  Zap,
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { useUiStore } from '../store/uiStore';
import { orgApi, type OrgDashboardData, type OrgProject } from '../services/orgApi';
import { useOrgLiveCounters } from '../hooks/useOrgLiveCounters';

export default function OrgDashboard() {
  const navigate = useNavigate();
  const addToast = useUiStore((s) => s.addToast);
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const activeProject = useAuthStore((s) => s.activeProject);
  const switchProject = useAuthStore((s) => s.switchProject);

  const [projects, setProjects] = useState<OrgProject[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(activeProject?.id || null);
  const [activeTab, setActiveTab] = useState<'overview' | 'live'>('overview');

  const [overviewData, setOverviewData] = useState<OrgDashboardData | null>(null);
  const [overviewLoading, setOverviewLoading] = useState<boolean>(false);

  const orgId = activeOrganization?.id || null;
  const projectId = selectedProjectId || activeProject?.id || null;

  // Live counters hook (zero polling, seed + realtime)
  const { counters, isConnected, isLoading: countersLoading, resync } = useOrgLiveCounters(
    orgId,
    projectId
  );

  // Load projects for active org
  useEffect(() => {
    if (!orgId) return;
    orgApi
      .listProjects(orgId)
      .then((res) => {
        setProjects(res);
        if (!selectedProjectId && res.length > 0) {
          setSelectedProjectId(res[0].id);
        }
      })
      .catch((err) => {
        console.error('Failed to load projects:', err);
      });
  }, [orgId, selectedProjectId]);

  // Load overview data
  const loadOverview = useCallback(async () => {
    if (!orgId) return;
    setOverviewLoading(true);
    try {
      const data = await orgApi.getDashboardOverview(orgId, projectId || undefined);
      setOverviewData(data);
    } catch (err: any) {
      addToast(err?.message || 'Failed to load dashboard overview', 'high');
    } finally {
      setOverviewLoading(false);
    }
  }, [orgId, projectId, addToast]);

  useEffect(() => {
    if (activeTab === 'overview') {
      void loadOverview();
    }
  }, [activeTab, loadOverview]);

  const handleProjectChange = async (newPid: string) => {
    setSelectedProjectId(newPid);
    try {
      await switchProject(newPid);
    } catch {
      // ignore
    }
  };

  const handleManualResync = async () => {
    await resync();
    addToast('Live counters resynced', 'safe');
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header with Project Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text">Organization Dashboard</h1>
          <p className="text-xs text-text-muted mt-1">
            Workspace: <span className="font-semibold text-text">{activeOrganization?.name || 'Default Organization'}</span>
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <FolderOpen className="w-4 h-4 text-primary" />
            <span>Project:</span>
          </div>
          <select
            value={selectedProjectId || ''}
            onChange={(e) => void handleProjectChange(e.target.value)}
            className="bg-surface border border-border text-xs rounded-md px-3 py-1.5 text-text focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {projects.length === 0 ? (
              <option value="">No projects</option>
            ) : (
              projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.slug})
                </option>
              ))
            )}
          </select>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex items-center gap-2 border-b border-border">
        <button
          type="button"
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === 'overview'
              ? 'border-primary text-primary'
              : 'border-transparent text-text-muted hover:text-text'
          }`}
        >
          Overview
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('live')}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'live'
              ? 'border-primary text-primary'
              : 'border-transparent text-text-muted hover:text-text'
          }`}
        >
          <span>Live Counters</span>
          {isConnected ? (
            <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              LIVE
            </span>
          ) : (
            <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-zinc-800 text-zinc-400 border border-zinc-700">
              OFFLINE
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* 3 Analyzer Cards */}
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">
              Analyzers
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Log Analyzer */}
              <div className="bg-surface border border-border rounded-lg p-5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-5 h-5 text-sky-400" />
                      <h3 className="text-sm font-semibold text-text">Log Analysis</h3>
                    </div>
                    {overviewData?.analyzers?.log?.available ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        ACTIVE
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        COMING SOON
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-text-muted mt-2">
                    Engine: <span className="font-mono text-zinc-300">{overviewData?.analyzers?.log?.engine || 'regex_rules'}</span>
                  </p>
                </div>
                <div className="mt-4 pt-4 border-t border-border flex items-baseline justify-between">
                  <span className="text-xs text-text-muted">24h Events</span>
                  <span className="text-xl font-bold text-text">
                    {overviewData?.analyzers?.log?.count_24h ?? counters.by_type.log}
                  </span>
                </div>
              </div>

              {/* ATO Analyzer */}
              <div className="bg-surface border border-border rounded-lg p-5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-5 h-5 text-amber-400" />
                      <h3 className="text-sm font-semibold text-text">Account Takeover</h3>
                    </div>
                    {overviewData?.analyzers?.ato?.available ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        ACTIVE
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        COMING SOON
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-text-muted mt-2">
                    Engine: <span className="font-mono text-zinc-300">{overviewData?.analyzers?.ato?.engine || 'heuristic_rules'}</span>
                  </p>
                </div>
                <div className="mt-4 pt-4 border-t border-border flex items-baseline justify-between">
                  <span className="text-xs text-text-muted">24h Events</span>
                  <span className="text-xl font-bold text-text">
                    {overviewData?.analyzers?.ato?.count_24h ?? counters.by_type.ato}
                  </span>
                </div>
              </div>

              {/* Network Threat Analyzer */}
              <div className="bg-surface border border-border rounded-lg p-5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Zap className="w-5 h-5 text-indigo-400" />
                      <h3 className="text-sm font-semibold text-text">Network Threat</h3>
                    </div>
                    {overviewData?.analyzers?.network?.available ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        ACTIVE
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        COMING SOON
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-text-muted mt-2">
                    Engine: <span className="font-mono text-zinc-300">{overviewData?.analyzers?.network?.engine || 'zeek_suricata_rules'}</span>
                  </p>
                </div>
                <div className="mt-4 pt-4 border-t border-border flex items-baseline justify-between">
                  <span className="text-xs text-text-muted">24h Events</span>
                  <span className="text-xl font-bold text-text">
                    {overviewData?.analyzers?.network?.count_24h ?? counters.by_type.network}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Severity Breakdown Bar */}
          <div className="bg-surface border border-border rounded-lg p-5">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-4">
              Severity Distribution (24h)
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="bg-zinc-900/50 border border-red-500/20 rounded p-3">
                <span className="text-[11px] text-red-400 font-semibold uppercase">Critical</span>
                <p className="text-2xl font-bold text-red-300 mt-1">
                  {overviewData?.severity_mix?.critical ?? counters.by_severity.critical}
                </p>
              </div>
              <div className="bg-zinc-900/50 border border-amber-500/20 rounded p-3">
                <span className="text-[11px] text-amber-400 font-semibold uppercase">High</span>
                <p className="text-2xl font-bold text-amber-300 mt-1">
                  {overviewData?.severity_mix?.high ?? counters.by_severity.high}
                </p>
              </div>
              <div className="bg-zinc-900/50 border border-yellow-500/20 rounded p-3">
                <span className="text-[11px] text-yellow-400 font-semibold uppercase">Medium</span>
                <p className="text-2xl font-bold text-yellow-300 mt-1">
                  {overviewData?.severity_mix?.medium ?? counters.by_severity.medium}
                </p>
              </div>
              <div className="bg-zinc-900/50 border border-blue-500/20 rounded p-3">
                <span className="text-[11px] text-blue-400 font-semibold uppercase">Low</span>
                <p className="text-2xl font-bold text-blue-300 mt-1">
                  {overviewData?.severity_mix?.low ?? counters.by_severity.low}
                </p>
              </div>
            </div>
          </div>

          {/* Recent Events Table */}
          <div className="bg-surface border border-border rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
                Recent Ingested Events (Latest 10)
              </h2>
              <Link
                to={orgId ? `/org/${orgId}/events` : '/org/events'}
                className="text-xs text-primary hover:underline flex items-center gap-1"
              >
                <span>View all</span>
                <ExternalLink className="w-3 h-3" />
              </Link>
            </div>

            {overviewLoading ? (
              <p className="text-xs text-text-muted py-8 text-center">Loading recent events...</p>
            ) : !overviewData?.recent_events || overviewData.recent_events.length === 0 ? (
              <p className="text-xs text-text-muted py-8 text-center">No events recorded in this project yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-border text-text-muted">
                      <th className="py-2.5 px-3">Event Type</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Verdict</th>
                      <th className="py-2.5 px-3">Time</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50">
                    {overviewData.recent_events.map((ev) => (
                      <tr key={ev.id} className="hover:bg-zinc-900/30 transition-colors">
                        <td className="py-2.5 px-3 font-medium text-text uppercase">
                          {ev.event_type}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                              ev.severity === 'critical'
                                ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                                : ev.severity === 'high'
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                : ev.severity === 'medium'
                                ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                                : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                            }`}
                          >
                            {ev.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-400">
                          {ev.verdict}
                        </td>
                        <td className="py-2.5 px-3 text-text-muted">
                          {new Date(ev.created_at).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            type="button"
                            onClick={() =>
                              navigate(
                                `/org/${orgId}/projects/${ev.project_id || projectId}/events/${ev.id}`
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
      )}

      {/* Tab 2: Live Counters (HARD RULE: ZERO input/textarea/select/form elements in this view) */}
      {activeTab === 'live' && (
        <div id="org-live-counters-view" className="space-y-6">
          {/* Status Header */}
          <div className="bg-surface border border-border rounded-lg p-5 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Radio className={`w-5 h-5 ${isConnected ? 'text-emerald-400 animate-pulse' : 'text-zinc-500'}`} />
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-sm font-semibold text-text">Realtime Telemetry Stream</h2>
                  {isConnected ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      LIVE
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-zinc-800 text-zinc-400 border border-zinc-700">
                      DISCONNECTED
                    </span>
                  )}
                </div>
                <p className="text-xs text-text-muted mt-0.5">
                  Subscribed to Postgres changes on org_events. Zero polling loops.
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={handleManualResync}
              disabled={countersLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${countersLoading ? 'animate-spin' : ''}`} />
              <span>Resync</span>
            </button>
          </div>

          {/* Key Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-surface border border-border rounded-lg p-5">
              <span className="text-xs font-semibold uppercase tracking-wider text-text-muted">
                Total Events (24h)
              </span>
              <p className="text-3xl font-extrabold text-text mt-2">{counters.total_24h}</p>
              <span className="text-[11px] text-text-muted mt-1 block">
                Aggregated across all analyzer engines
              </span>
            </div>

            <div className="bg-surface border border-border rounded-lg p-5">
              <span className="text-xs font-semibold uppercase tracking-wider text-amber-400">
                Pending Review
              </span>
              <p className="text-3xl font-extrabold text-amber-300 mt-2">{counters.pending_review}</p>
              <span className="text-[11px] text-text-muted mt-1 block">
                Awaiting manual analyst triage or verdict
              </span>
            </div>

            <div className="bg-surface border border-border rounded-lg p-5">
              <span className="text-xs font-semibold uppercase tracking-wider text-red-400">
                Blocked Indicators
              </span>
              <p className="text-3xl font-extrabold text-red-300 mt-2">
                {counters.blocked_indicators_count}
              </p>
              <span className="text-[11px] text-text-muted mt-1 block">
                Active IOCs enforced at project gateway
              </span>
            </div>
          </div>

          {/* Severity Counters Grid */}
          <div className="bg-surface border border-border rounded-lg p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-4">
              Realtime Severities
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="bg-zinc-900/40 border border-red-500/20 rounded-md p-4">
                <span className="text-xs font-semibold text-red-400">Critical</span>
                <p className="text-2xl font-bold text-red-200 mt-1">{counters.by_severity.critical}</p>
              </div>
              <div className="bg-zinc-900/40 border border-amber-500/20 rounded-md p-4">
                <span className="text-xs font-semibold text-amber-400">High</span>
                <p className="text-2xl font-bold text-amber-200 mt-1">{counters.by_severity.high}</p>
              </div>
              <div className="bg-zinc-900/40 border border-yellow-500/20 rounded-md p-4">
                <span className="text-xs font-semibold text-yellow-400">Medium</span>
                <p className="text-2xl font-bold text-yellow-200 mt-1">{counters.by_severity.medium}</p>
              </div>
              <div className="bg-zinc-900/40 border border-blue-500/20 rounded-md p-4">
                <span className="text-xs font-semibold text-blue-400">Low</span>
                <p className="text-2xl font-bold text-blue-200 mt-1">{counters.by_severity.low}</p>
              </div>
            </div>
          </div>

          {/* Analyzers Ingestion Breakdown */}
          <div className="bg-surface border border-border rounded-lg p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-4">
              Ingested Event Types (24h)
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-zinc-900/40 border border-border rounded-md p-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-text">Log Analysis</span>
                  <span className="text-[10px] font-mono text-zinc-400">log</span>
                </div>
                <p className="text-2xl font-bold text-sky-400 mt-2">{counters.by_type.log}</p>
              </div>
              <div className="bg-zinc-900/40 border border-border rounded-md p-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-text">Account Takeover</span>
                  <span className="text-[10px] font-mono text-zinc-400">ato</span>
                </div>
                <p className="text-2xl font-bold text-amber-400 mt-2">{counters.by_type.ato}</p>
              </div>
              <div className="bg-zinc-900/40 border border-border rounded-md p-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-text">Network Threats</span>
                  <span className="text-[10px] font-mono text-zinc-400">network</span>
                </div>
                <p className="text-2xl font-bold text-indigo-400 mt-2">{counters.by_type.network}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
