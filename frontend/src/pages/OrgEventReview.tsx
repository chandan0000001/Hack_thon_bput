import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  AlertOctagon,
  ArrowLeft,
  Ban,
  Clock,
  FileCode,
  RotateCcw,
  Shield,
  ShieldCheck,
  Tag,
  User,
} from 'lucide-react';
import { orgApi, type OrgEvent } from '../services/orgApi';
import { useUiStore } from '../store/uiStore';

export default function OrgEventReview() {
  const { orgId, pid, eid } = useParams<{ orgId: string; pid: string; eid: string }>();
  const navigate = useNavigate();
  const addToast = useUiStore((s) => s.addToast);

  const [event, setEvent] = useState<OrgEvent | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [acting, setActing] = useState<boolean>(false);
  const [actionReason, setActionReason] = useState<string>('');

  const loadEvent = useCallback(async () => {
    if (!orgId || !pid || !eid) return;
    setLoading(true);
    try {
      const data = await orgApi.getEventDetail(orgId, pid, eid);
      setEvent(data);
    } catch (err: any) {
      addToast(err?.message || 'Failed to load event details', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, pid, eid, addToast]);

  useEffect(() => {
    void loadEvent();
  }, [loadEvent]);

  const handleAction = async (action: 'released' | 'blocked_permanently' | 'false_positive') => {
    if (!orgId || !pid || !eid) return;
    setActing(true);
    try {
      await orgApi.updateEventVerdict(orgId, pid, eid, action, actionReason.trim() || undefined);
      addToast(`Event verdict updated to ${action.replace('_', ' ')}`, 'safe');
      setActionReason('');
      await loadEvent();
    } catch (err: any) {
      addToast(err?.message || `Failed to update event verdict`, 'high');
    } finally {
      setActing(false);
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <p className="text-xs text-text-muted">Loading event details...</p>
      </div>
    );
  }

  if (!event) {
    return (
      <div className="p-6 space-y-4">
        <p className="text-sm text-text-muted">Event not found.</p>
        <button
          type="button"
          onClick={() => navigate(-1)}
          className="text-xs text-primary flex items-center gap-1"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Go back</span>
        </button>
      </div>
    );
  }

  const analysis = (event.analysis_result || {}) as Record<string, unknown>;
  const mitreTags = Array.isArray(analysis.mitre) ? analysis.mitre : [];
  const indicators = Array.isArray(analysis.indicators) ? analysis.indicators : [];
  const isIndicatorBlocked = Boolean(event.indicator_blocked);

  return (
    <div className="space-y-6 p-6 max-w-7xl mx-auto">
      {/* Back Button & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-5">
        <div className="space-y-1">
          <button
            type="button"
            onClick={() => navigate(-1)}
            className="text-xs text-text-muted hover:text-text flex items-center gap-1.5 transition-colors mb-2"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Events</span>
          </button>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-text">Event Review</h1>
            <span className="font-mono text-xs px-2 py-0.5 rounded bg-zinc-900 border border-border text-zinc-400">
              {event.id}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider ${
              event.severity === 'critical'
                ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                : event.severity === 'high'
                ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                : event.severity === 'medium'
                ? 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30'
                : 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
            }`}
          >
            {event.severity}
          </span>
          <span
            className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider ${
              event.verdict === 'pending_review'
                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                : event.verdict === 'released'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                : event.verdict === 'blocked_permanently'
                ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                : 'bg-zinc-800 text-zinc-300 border border-zinc-700'
            }`}
          >
            {event.verdict.replace('_', ' ')}
          </span>
        </div>
      </div>

      {/* Blocked Indicator Warning Banner */}
      {isIndicatorBlocked && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertOctagon className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h3 className="text-xs font-bold text-red-300 uppercase tracking-wider">
              Permanent Blocklist Match
            </h3>
            <p className="text-xs text-red-200/80 leading-relaxed">
              An indicator extracted from this event matches an entry in your organization&apos;s active blocklist.
              Releasing this event is strictly prevented by security policy until the indicator is unblocked.
            </p>
          </div>
        </div>
      )}

      {/* 2-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Metadata & Raw Payload (2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Metadata Card */}
          <div className="bg-surface border border-border rounded-lg p-5">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-4">
              Event Metadata
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
              <div>
                <span className="text-text-muted block">Type</span>
                <span className="font-semibold text-text uppercase mt-0.5 block">{event.event_type}</span>
              </div>
              <div>
                <span className="text-text-muted block">Source</span>
                <span className="font-semibold text-text mt-0.5 block">{event.source}</span>
              </div>
              <div>
                <span className="text-text-muted block">Ingested At</span>
                <span className="text-zinc-300 mt-0.5 block">
                  {new Date(event.created_at).toLocaleString()}
                </span>
              </div>
              <div>
                <span className="text-text-muted block">Engine</span>
                <span className="font-mono text-zinc-300 mt-0.5 block">
                  {String(analysis.engine || 'default')}
                </span>
              </div>
            </div>
          </div>

          {/* Analysis & Indicators */}
          <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
              Analyzer Intelligence & Extracted IOCs
            </h2>

            {/* MITRE Tags */}
            {mitreTags.length > 0 && (
              <div className="space-y-2">
                <span className="text-[11px] font-medium text-text-muted flex items-center gap-1.5">
                  <Tag className="w-3.5 h-3.5" />
                  <span>MITRE ATT&CK Techniques:</span>
                </span>
                <div className="flex flex-wrap gap-2">
                  {mitreTags.map((tag: string, i: number) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Extracted Indicators */}
            <div className="space-y-2">
              <span className="text-[11px] font-medium text-text-muted flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" />
                <span>Extracted Indicators:</span>
              </span>
              {indicators.length === 0 ? (
                <p className="text-xs text-text-muted italic">No specific indicators extracted.</p>
              ) : (
                <div className="space-y-1.5">
                  {indicators.map((ind: any, i: number) => (
                    <div
                      key={i}
                      className="flex items-center justify-between p-2 rounded bg-zinc-900 border border-border text-xs"
                    >
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold bg-zinc-800 text-zinc-300">
                          {ind.type || 'indicator'}
                        </span>
                        <span className="font-mono text-text">{ind.value}</span>
                      </div>
                      {isIndicatorBlocked && (
                        <span className="text-[10px] text-red-400 font-semibold uppercase">
                          MATCHES BLOCKLIST
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Raw Payload JSON */}
          <div className="bg-surface border border-border rounded-lg p-5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5">
                <FileCode className="w-4 h-4" />
                <span>Raw Ingested Data</span>
              </span>
            </div>
            <pre className="bg-zinc-950 border border-border rounded-lg p-4 text-[11px] font-mono text-zinc-300 overflow-x-auto max-h-96 leading-relaxed">
              {JSON.stringify(event.raw_data, null, 2)}
            </pre>
          </div>
        </div>

        {/* Right Column: Actions & Review History (1 col) */}
        <div className="space-y-6">
          {/* Action Card */}
          <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
              Analyst Actions
            </h2>

            <div className="space-y-2">
              <label className="block text-[11px] font-medium text-text-muted">
                Action Reason / Notes (Optional)
              </label>
              <textarea
                rows={3}
                value={actionReason}
                onChange={(e) => setActionReason(e.target.value)}
                placeholder="Document justification for verdict..."
                className="w-full bg-zinc-900 border border-border rounded-md px-3 py-2 text-xs text-text focus:outline-none focus:ring-1 focus:ring-primary resize-none"
              />
            </div>

            <div className="space-y-2.5 pt-2">
              {/* Release Button */}
              <button
                type="button"
                disabled={acting || isIndicatorBlocked}
                onClick={() => handleAction('released')}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md bg-emerald-600 hover:bg-emerald-500 text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                title={isIndicatorBlocked ? 'Cannot release: indicator is permanently blocked' : ''}
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Release Event</span>
              </button>

              {/* Block Permanently */}
              <button
                type="button"
                disabled={acting}
                onClick={() => handleAction('blocked_permanently')}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md bg-red-600 hover:bg-red-500 text-white transition-colors disabled:opacity-50"
              >
                <Ban className="w-4 h-4" />
                <span>Block Permanently (Add to IOCs)</span>
              </button>

              {/* False Positive */}
              <button
                type="button"
                disabled={acting}
                onClick={() => handleAction('false_positive')}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors disabled:opacity-50"
              >
                <RotateCcw className="w-4 h-4" />
                <span>Mark False Positive</span>
              </button>
            </div>
          </div>

          {/* Action History Card */}
          <div className="bg-surface border border-border rounded-lg p-5 space-y-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
              Triage History
            </h2>
            {event.acted_at ? (
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2 text-text">
                  <User className="w-3.5 h-3.5 text-primary" />
                  <span className="font-medium">Acted by: {event.acted_by || 'Analyst'}</span>
                </div>
                <div className="flex items-center gap-2 text-text-muted">
                  <Clock className="w-3.5 h-3.5" />
                  <span>{new Date(event.acted_at).toLocaleString()}</span>
                </div>
                {event.user_action && (
                  <div className="p-2 rounded bg-zinc-900 border border-border mt-2 font-mono text-[11px] text-zinc-300">
                    Action: {event.user_action}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-text-muted italic">
                No analyst triage action recorded yet. Currently in pending review.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
