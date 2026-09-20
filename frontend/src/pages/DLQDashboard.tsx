import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertOctagon,
  ArrowRight,
  Check,
  Clock,
  Copy,
  ExternalLink,
  Layers,
  RefreshCw,
  RotateCw,
  Search,
  Trash2,
  X,
  Zap,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/common/PageHeader';
import { PanelSkeleton } from '../components/common/LoadingSkeleton';
import * as api from '../services/api';
import type { DlqJob, DlqStats } from '../types';
import { getSupabase } from '../lib/supabaseClient';

export default function DLQDashboard() {
  const [stats, setStats] = useState<DlqStats | null>(null);
  const [jobs, setJobs] = useState<DlqJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Filters
  const [jobTypeFilter, setJobTypeFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected job for detail drawer
  const [selectedJob, setSelectedJob] = useState<DlqJob | null>(null);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Realtime state
  const [isRealtimeConnected, setIsRealtimeConnected] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [liveEventsCount, setLiveEventsCount] = useState(0);

  // Copy helper
  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Fetch stats and jobs
  const fetchData = useCallback(
    async (isManualRefresh = false) => {
      if (isManualRefresh) setRefreshing(true);
      setError(null);
      try {
        const [statsData, jobsData] = await Promise.all([
          api.getDlqStats(),
          api.getDlqJobs(jobTypeFilter !== 'all' ? { job_type: jobTypeFilter } : undefined),
        ]);
        setStats(statsData);
        setJobs(jobsData.jobs);
        if (selectedJob) {
          // If drawer is open, keep selected job data fresh
          const updated = jobsData.jobs.find((j) => j.job_id === selectedJob.job_id);
          if (updated) setSelectedJob(updated);
        }
      } catch (err: any) {
        setError(err?.message || 'Failed to load DLQ data');
      } finally {
        setLoading(false);
        if (isManualRefresh) setRefreshing(false);
      }
    },
    [jobTypeFilter, selectedJob],
  );

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Realtime subscription setup
  useEffect(() => {
    let supabase: any = null;
    try {
      supabase = getSupabase();
    } catch {
      setIsPolling(true);
    }

    if (!supabase) {
      const interval = setInterval(() => {
        fetchData();
      }, 15000);
      return () => clearInterval(interval);
    }

    const channel = supabase
      .channel('dlq-job-queue-changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'job_queue' },
        () => {
          setLiveEventsCount((c) => c + 1);
          fetchData();
        },
      )
      .subscribe((status: string) => {
        if (status === 'SUBSCRIBED') {
          setIsRealtimeConnected(true);
          setIsPolling(false);
        } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
          setIsRealtimeConnected(false);
          setIsPolling(true);
        }
      });

    // Fallback polling interval every 20s
    const pollInterval = setInterval(() => {
      fetchData();
    }, 20000);

    return () => {
      supabase.removeChannel(channel);
      clearInterval(pollInterval);
    };
  }, [fetchData]);

  // Actions: Retry
  const handleRetry = async (jobId: string) => {
    setActionInProgress(jobId);
    setActionSuccess(null);
    setError(null);
    try {
      await api.retryDlqJob(jobId);
      setActionSuccess(`Job ${jobId} successfully re-enqueued to Redis with reset retry count.`);
      await fetchData();
      if (selectedJob?.job_id === jobId) {
        setSelectedJob(null);
      }
    } catch (err: any) {
      setError(err?.message || `Failed to retry job ${jobId}`);
    } finally {
      setActionInProgress(null);
    }
  };

  // Actions: Delete
  const handleDelete = async (jobId: string) => {
    if (!window.confirm(`Are you sure you want to soft-delete job ${jobId}? It will be marked deleted in the audit trail.`)) {
      return;
    }
    setActionInProgress(jobId);
    setActionSuccess(null);
    setError(null);
    try {
      await api.deleteDlqJob(jobId);
      setActionSuccess(`Job ${jobId} marked as soft-deleted.`);
      await fetchData();
      if (selectedJob?.job_id === jobId) {
        setSelectedJob(null);
      }
    } catch (err: any) {
      setError(err?.message || `Failed to delete job ${jobId}`);
    } finally {
      setActionInProgress(null);
    }
  };

  // Filtered jobs
  const filteredJobs = useMemo(() => {
    let list = jobs;
    if (jobTypeFilter !== 'all') {
      list = list.filter((j) => j.job_type === jobTypeFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (j) =>
          j.job_id.toLowerCase().includes(q) ||
          j.owner_user_id.toLowerCase().includes(q) ||
          (j.error && j.error.toLowerCase().includes(q)) ||
          j.job_type.toLowerCase().includes(q),
      );
    }
    return list;
  }, [jobs, jobTypeFilter, searchQuery]);

  // Calculate age helper
  const getAgeString = (isoDate: string) => {
    const diffMs = Date.now() - new Date(isoDate).getTime();
    const diffHours = diffMs / (1000 * 60 * 60);
    if (diffHours < 1) {
      const mins = Math.max(1, Math.round(diffMs / (1000 * 60)));
      return `${mins}m ago`;
    }
    if (diffHours < 24) {
      return `${diffHours.toFixed(1)}h ago`;
    }
    const days = Math.round(diffHours / 24);
    return `${days}d ago`;
  };

  // Relative ETA until the next scheduled retry (null when not scheduled).
  const formatRetryEta = (iso?: string | null) => {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return null;
    const diffSec = (t - Date.now()) / 1000;
    if (diffSec <= 0) return 'now';
    if (diffSec < 90) return 'in ~1m';
    const diffMin = Math.round(diffSec / 60);
    if (diffMin < 60) return `in ${diffMin}m`;
    const hours = Math.floor(diffMin / 60);
    if (hours < 24) return `in ${hours}h`;
    return `in ${Math.round(hours / 24)}d`;
  };

  // Color helper for job types
  const getJobTypeBadge = (jobType: string) => {
    switch (jobType) {
      case 'gmail_sync':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'email_fetch':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'email_analysis':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      default:
        return 'bg-zinc-800 text-zinc-300 border-zinc-700';
    }
  };

  // Correlation ID extractor
  const getCorrelationId = (job: DlqJob): string | null => {
    return job.payload?.correlation_id || null;
  };

  return (
    <div className="relative pb-16">
      {/* Top Header */}
      <PageHeader
        title="Dead Letter Queue (DLQ)"
        description="Admin operations console: inspect poison messages, analyze retry backoff traces, and trigger manual re-enqueues or soft-deletes."
        actions={
          <div className="flex items-center gap-3">
            {/* Realtime / Polling indicator */}
            {isRealtimeConnected ? (
              <span
                title="Subscribed to live job_queue status changes"
                className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-400"
              >
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                LIVE
                {liveEventsCount > 0 && <span className="text-[10px] opacity-80">({liveEventsCount})</span>}
              </span>
            ) : isPolling ? (
              <span
                title="Polling fallback active (20s)"
                className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs font-semibold text-amber-300"
              >
                <span className="h-2 w-2 rounded-full bg-amber-400" />
                POLLING
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-700 bg-zinc-800/60 px-2.5 py-1 text-xs font-semibold text-zinc-400">
                <span className="h-2 w-2 rounded-full bg-zinc-500 animate-ping" />
                CONNECTING
              </span>
            )}

            {/* Refresh button */}
            <button
              id="dlq-refresh-btn"
              onClick={() => fetchData(true)}
              disabled={refreshing}
              className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800/70 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-700/70 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin text-blue-400' : ''}`} />
              Refresh
            </button>
          </div>
        }
      />

      {/* Success / Error Alerts */}
      {actionSuccess && (
        <div className="mb-4 flex items-center justify-between rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm text-emerald-300">
          <div className="flex items-center gap-2">
            <Check className="h-4 w-4 text-emerald-400" />
            <span>{actionSuccess}</span>
          </div>
          <button onClick={() => setActionSuccess(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}
      {error && (
        <div className="mb-4 flex items-center justify-between rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-red-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Stats Cards Row */}
      {loading && !stats ? (
        <PanelSkeleton />
      ) : (
        <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {/* Card 1: Total Dead Letters */}
          <div className="relative overflow-hidden rounded-xl border border-red-500/30 bg-zinc-850/80 p-4 shadow-lg backdrop-blur">
            <div className="pointer-events-none absolute -right-6 -top-6 h-24 w-24 rounded-full bg-red-500/15 blur-2xl" />
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Total Dead Letters</span>
                <div className="mt-2 text-3xl font-extrabold text-red-400">
                  {stats?.total_dead_letter ?? 0}
                </div>
              </div>
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/20 text-red-400 ring-1 ring-red-500/30">
                <AlertOctagon className="h-5 w-5" />
              </div>
            </div>
            <div className="mt-3 text-xs text-zinc-400">
              {(stats?.total_dead_letter ?? 0) === 0 ? (
                <span className="text-emerald-400 font-medium">✓ DLQ healthy & clean</span>
              ) : (
                <span className="text-red-400 font-medium">Poison / exhausted retries</span>
              )}
            </div>
          </div>

          {/* Card 2: Oldest Dead Letter */}
          <div className="relative overflow-hidden rounded-xl border border-zinc-700/50 bg-zinc-850/80 p-4 shadow-lg backdrop-blur">
            <div className="pointer-events-none absolute -right-6 -top-6 h-24 w-24 rounded-full bg-amber-500/10 blur-2xl" />
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Oldest Age</span>
                <div className="mt-2 text-3xl font-extrabold text-amber-300">
                  {stats && stats.oldest_age_hours > 0 ? `${stats.oldest_age_hours.toFixed(1)}h` : '0h'}
                </div>
              </div>
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/30">
                <Clock className="h-5 w-5" />
              </div>
            </div>
            <div className="mt-3 text-xs text-zinc-400">Elapsed time since creation</div>
          </div>

          {/* Card 3 & 4: Breakdown by job type */}
          <div className="relative col-span-1 sm:col-span-2 overflow-hidden rounded-xl border border-zinc-700/50 bg-zinc-850/80 p-4 shadow-lg backdrop-blur">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Breakdown by Job Type</span>
              <Layers className="h-4 w-4 text-zinc-400" />
            </div>
            <div className="mt-3 flex flex-wrap gap-2.5">
              {stats?.by_job_type && Object.keys(stats.by_job_type).length > 0 ? (
                Object.entries(stats.by_job_type).map(([jtype, cnt]) => (
                  <div
                    key={jtype}
                    onClick={() => setJobTypeFilter(jobTypeFilter === jtype ? 'all' : jtype)}
                    className={`cursor-pointer flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs transition-all ${
                      jobTypeFilter === jtype
                        ? 'border-blue-500 bg-blue-500/20 text-blue-300 ring-1 ring-blue-500'
                        : 'border-zinc-700/70 bg-zinc-800/80 text-zinc-300 hover:border-zinc-600'
                    }`}
                  >
                    <span className="font-mono font-medium">{jtype}</span>
                    <span className="rounded-full bg-zinc-900 px-2 py-0.5 font-bold text-zinc-200">{cnt}</span>
                  </div>
                ))
              ) : (
                <div className="text-xs text-zinc-500">No active job types in DLQ</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-700/50 bg-zinc-850/60 p-3 backdrop-blur">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Type:</span>
          {['all', 'gmail_sync', 'email_fetch', 'email_analysis'].map((type) => (
            <button
              key={type}
              onClick={() => setJobTypeFilter(type)}
              className={`rounded-lg px-2.5 py-1 text-xs font-medium transition-colors ${
                jobTypeFilter === type
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200'
              }`}
            >
              {type === 'all' ? 'All Jobs' : type}
            </button>
          ))}
        </div>

        <div className="relative min-w-[240px]">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-zinc-500" />
          <input
            type="text"
            placeholder="Search ID, User, or Error..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-900/80 py-1.5 pl-8 pr-3 text-xs text-zinc-200 placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Jobs Table */}
      <div className="overflow-hidden rounded-xl border border-zinc-700/50 bg-zinc-850/40 shadow-xl backdrop-blur">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-zinc-700/50 bg-zinc-900/90 text-zinc-400 font-semibold uppercase tracking-wider">
                <th className="px-4 py-3">Job ID</th>
                <th className="px-4 py-3">Job Type</th>
                <th className="px-4 py-3">Owner User ID</th>
                <th className="px-4 py-3">Error (Failure Cause)</th>
                <th className="px-4 py-3 text-center">Retries</th>
                <th className="px-4 py-3">Next Retry</th>
                <th className="px-4 py-3">Age</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/80">
              {loading ? (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-zinc-500">
                    Loading dead-letter jobs...
                  </td>
                </tr>
              ) : filteredJobs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-10 text-center text-zinc-500">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Zap className="h-8 w-8 text-zinc-600" />
                      <p className="text-sm font-medium text-zinc-400">No dead letter jobs match the filters</p>
                      <p className="text-xs text-zinc-500">All asynchronous workers are executing normally.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredJobs.map((job) => {
                  const isActioning = actionInProgress === job.job_id;
                  return (
                    <tr
                      key={job.job_id}
                      className="hover:bg-zinc-800/50 transition-colors group cursor-pointer"
                      onClick={() => setSelectedJob(job)}
                    >
                      {/* Job ID */}
                      <td className="px-4 py-3 font-mono font-medium text-zinc-200">
                        <div className="flex items-center gap-1.5">
                          <span title={job.job_id} className="text-blue-400 hover:underline">
                            {job.job_id.length > 16 ? `${job.job_id.slice(0, 16)}…` : job.job_id}
                          </span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              copyToClipboard(job.job_id, `id-${job.job_id}`);
                            }}
                            className="text-zinc-500 hover:text-zinc-300 opacity-0 group-hover:opacity-100 transition-opacity"
                            title="Copy Job ID"
                          >
                            {copiedKey === `id-${job.job_id}` ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </div>
                      </td>

                      {/* Job Type */}
                      <td className="px-4 py-3">
                        <span
                          className={`inline-block rounded-md border px-2 py-0.5 text-[11px] font-mono font-semibold uppercase tracking-wider ${getJobTypeBadge(
                            job.job_type,
                          )}`}
                        >
                          {job.job_type}
                        </span>
                      </td>

                      {/* Owner */}
                      <td className="px-4 py-3 font-mono text-zinc-400" title={job.owner_user_id}>
                        {job.owner_user_id.length > 14
                          ? `${job.owner_user_id.slice(0, 14)}…`
                          : job.owner_user_id}
                      </td>

                      {/* Error */}
                      <td className="px-4 py-3 max-w-xs truncate text-red-300/90 font-mono" title={job.error || 'None'}>
                        {job.error ? (
                          job.error.length > 55 ? `${job.error.slice(0, 55)}…` : job.error
                        ) : (
                          <span className="text-zinc-600">None</span>
                        )}
                      </td>

                      {/* Retry Count */}
                      <td className="px-4 py-3 text-center">
                        <span
                          className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-bold font-mono ${
                            job.retry_count === 0
                              ? 'bg-purple-500/20 text-purple-300 ring-1 ring-purple-500/40'
                              : 'bg-zinc-800 text-zinc-300 ring-1 ring-zinc-700'
                          }`}
                          title={job.retry_count === 0 ? 'Poison/Auth error: immediate dead letter' : `Retried ${job.retry_count} times`}
                        >
                          {job.retry_count}
                        </span>
                      </td>

                      {/* Next Retry ETA */}
                      <td className="px-4 py-3 whitespace-nowrap font-mono text-zinc-400">
                        {(() => {
                          const eta = formatRetryEta(job.next_retry_at);
                          if (!eta) return <span className="text-zinc-600">—</span>;
                          return (
                            <span
                              className={eta === 'now' ? 'font-semibold text-amber-300' : ''}
                              title={job.next_retry_at ? new Date(job.next_retry_at).toLocaleString() : undefined}
                            >
                              {eta}
                            </span>
                          );
                        })()}
                      </td>

                      {/* Age */}
                      <td className="px-4 py-3 text-zinc-400 whitespace-nowrap">
                        {getAgeString(job.created_at)}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Retry */}
                          <button
                            id={`retry-btn-${job.job_id}`}
                            onClick={() => handleRetry(job.job_id)}
                            disabled={isActioning}
                            className="inline-flex items-center gap-1 rounded-md border border-blue-500/30 bg-blue-500/10 px-2 py-1 text-xs font-semibold text-blue-400 hover:bg-blue-500/20 transition-colors disabled:opacity-50"
                            title="Reset retry count to 0, mark queued, and re-enqueue to Redis"
                          >
                            <RotateCw className={`h-3 w-3 ${isActioning ? 'animate-spin' : ''}`} />
                            Retry
                          </button>

                          {/* Delete */}
                          <button
                            id={`delete-btn-${job.job_id}`}
                            onClick={() => handleDelete(job.job_id)}
                            disabled={isActioning}
                            className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-800/80 px-2 py-1 text-xs font-medium text-zinc-400 hover:text-red-400 hover:border-red-500/40 transition-colors disabled:opacity-50"
                            title="Soft delete from DLQ (retains audit trail)"
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>

                          {/* View Detail */}
                          <button
                            onClick={() => setSelectedJob(job)}
                            className="rounded-md p-1 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 transition-colors"
                            title="View full payload and error stack"
                          >
                            <ArrowRight className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Drawer (Slide-Over) */}
      {selectedJob && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
          <div
            className="w-full max-w-2xl h-full overflow-y-auto border-l border-zinc-700/80 bg-zinc-900 p-6 shadow-2xl flex flex-col justify-between animate-in slide-in-from-right duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div>
              {/* Drawer Header */}
              <div className="flex items-start justify-between border-b border-zinc-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`rounded-md border px-2 py-0.5 text-xs font-mono font-semibold uppercase ${getJobTypeBadge(
                        selectedJob.job_type,
                      )}`}
                    >
                      {selectedJob.job_type}
                    </span>
                    <span className="rounded-md border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-xs font-bold text-red-400">
                      DEAD_LETTER
                    </span>
                  </div>
                  <h3 className="mt-2 text-lg font-bold text-zinc-100 break-all font-mono">
                    {selectedJob.job_id}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedJob(null)}
                  className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Action Toolbar in Drawer */}
              <div className="my-4 flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-850/70 p-3">
                <span className="text-xs text-zinc-400">Admin Operations:</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleRetry(selectedJob.job_id)}
                    disabled={actionInProgress === selectedJob.job_id}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/50 bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white shadow hover:bg-blue-500 transition-colors disabled:opacity-50"
                  >
                    <RotateCw
                      className={`h-3.5 w-3.5 ${actionInProgress === selectedJob.job_id ? 'animate-spin' : ''}`}
                    />
                    Manual Re-enqueue (Retry)
                  </button>
                  <button
                    onClick={() => handleDelete(selectedJob.job_id)}
                    disabled={actionInProgress === selectedJob.job_id}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-500/20 transition-colors disabled:opacity-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Soft Delete
                  </button>
                </div>
              </div>

              {/* Metadata Grid */}
              <div className="grid grid-cols-2 gap-3 text-xs mb-5">
                <div className="rounded-lg border border-zinc-800 bg-zinc-850/50 p-3">
                  <span className="text-zinc-500 block mb-1">Owner User ID</span>
                  <span className="font-mono text-zinc-200 font-medium">{selectedJob.owner_user_id}</span>
                </div>
                <div className="rounded-lg border border-zinc-800 bg-zinc-850/50 p-3">
                  <span className="text-zinc-500 block mb-1">Retry Count</span>
                  <span className="font-mono text-zinc-200 font-medium">
                    {selectedJob.retry_count} {selectedJob.retry_count === 0 ? '(Immediate poison/auth stop)' : ''}
                  </span>
                </div>
                <div className="rounded-lg border border-zinc-800 bg-zinc-850/50 p-3">
                  <span className="text-zinc-500 block mb-1">Created At</span>
                  <span className="font-mono text-zinc-300">{new Date(selectedJob.created_at).toLocaleString()}</span>
                </div>
                <div className="rounded-lg border border-zinc-800 bg-zinc-850/50 p-3">
                  <span className="text-zinc-500 block mb-1">Updated At</span>
                  <span className="font-mono text-zinc-300">{new Date(selectedJob.updated_at).toLocaleString()}</span>
                </div>
              </div>

              {/* Correlation ID & Audit Log Link */}
              {getCorrelationId(selectedJob) && (
                <div className="mb-5 rounded-lg border border-blue-500/30 bg-blue-500/5 p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-xs text-zinc-400 block">Correlation ID:</span>
                      <span className="font-mono text-xs font-bold text-blue-300">
                        {getCorrelationId(selectedJob)}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() =>
                          copyToClipboard(getCorrelationId(selectedJob)!, 'corr-id')
                        }
                        className="rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-[11px] text-zinc-300 hover:text-white"
                      >
                        {copiedKey === 'corr-id' ? 'Copied' : 'Copy'}
                      </button>
                      <Link
                        to={`/audit-logs`}
                        className="inline-flex items-center gap-1 rounded border border-blue-500/40 bg-blue-500/20 px-2.5 py-1 text-[11px] font-semibold text-blue-300 hover:bg-blue-500/30"
                      >
                        View in Audit Logs
                        <ExternalLink className="h-3 w-3" />
                      </Link>
                    </div>
                  </div>
                </div>
              )}

              {/* Error Stack Trace */}
              <div className="mb-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">
                    Error / Exception Trace
                  </span>
                  {selectedJob.error && (
                    <button
                      onClick={() => copyToClipboard(selectedJob.error || '', 'err-stack')}
                      className="text-xs text-zinc-400 hover:text-zinc-200 inline-flex items-center gap-1"
                    >
                      <Copy className="h-3 w-3" />
                      {copiedKey === 'err-stack' ? 'Copied' : 'Copy Stack'}
                    </button>
                  )}
                </div>
                <div className="rounded-lg border border-red-500/30 bg-red-950/25 p-3.5 text-xs font-mono text-red-300 overflow-x-auto whitespace-pre-wrap max-h-56">
                  {selectedJob.error || 'No error trace recorded for this job.'}
                </div>
              </div>

              {/* Retry History */}
              <div className="mb-5">
                <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider block mb-2">
                  Retry History
                </span>
                {selectedJob.retry_history && selectedJob.retry_history.length > 0 ? (
                  <div className="space-y-2">
                    {selectedJob.retry_history.map((rh, idx) => (
                      <div
                        key={idx}
                        className="rounded-lg border border-zinc-800 bg-zinc-850/60 p-2.5 text-xs"
                      >
                        <div className="flex items-center justify-between text-zinc-400 mb-1">
                          <span className="font-semibold text-zinc-200">Attempt #{rh.attempt}</span>
                          <span className="font-mono text-[11px]">{new Date(rh.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <p className="font-mono text-red-400/90 text-[11px]">{rh.error}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-lg border border-zinc-800 bg-zinc-850/40 p-3 text-xs text-zinc-500">
                    No retry attempts recorded (single-shot execution or non-retryable error).
                  </div>
                )}
              </div>

              {/* Full Payload */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                    Full Job Payload
                  </span>
                  <button
                    onClick={() =>
                      copyToClipboard(JSON.stringify(selectedJob.payload, null, 2), 'payload-json')
                    }
                    className="text-xs text-zinc-400 hover:text-zinc-200 inline-flex items-center gap-1"
                  >
                    <Copy className="h-3 w-3" />
                    {copiedKey === 'payload-json' ? 'Copied' : 'Copy JSON'}
                  </button>
                </div>
                <pre className="rounded-lg border border-zinc-800 bg-zinc-950 p-3.5 text-[11px] font-mono text-zinc-300 overflow-x-auto max-h-64">
                  {JSON.stringify(selectedJob.payload, null, 2)}
                </pre>
              </div>
            </div>

            {/* Footer close button */}
            <div className="border-t border-zinc-800 pt-4 flex justify-end">
              <button
                onClick={() => setSelectedJob(null)}
                className="rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-xs font-medium text-zinc-300 hover:bg-zinc-700 transition-colors"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
