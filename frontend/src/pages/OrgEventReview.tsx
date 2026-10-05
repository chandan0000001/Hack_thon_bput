/**
 * ORG-DASHBOARD-P2 — Event Review page (full inspection + triage).
 *
 * Replaces the P1 stub. Route: /org/:orgId/projects/:projectId/events/:eventId/review
 * (registered inside OrgGuard + OrgWorkspaceShell since P1).
 *
 * Guards (in addition to OrgGuard's session check):
 *   - 403 from any org API  -> /org/select            (non-member)
 *   - 404 event detail      -> workspace (no dedicated
 *     events-list route exists yet, so the workspace dashboard is the
 *     events surface)
 *
 * Data: GET event detail on mount; PATCH {action} for triage (backend
 * contract — R5's {user_action} maps to the API's `action` field);
 * blocked-indicator match via GET /org/{org}/blocked-indicators?q={value}
 * with exact-match filtering (the endpoint's q is substring).
 */

import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  orgApi,
  type OrgEventDetail,
} from '../services/orgApi';
import { ApiError } from '../services/http';
import SeverityBadge from '../components/common/SeverityBadge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { formatLocal } from '../utils/datetime';
import { useAuthStore } from '../store/authStore';
import {
  buildActionHistory,
  canAct,
  highlightJson,
  indicatorSeverity,
  indicatorType,
  indicatorValue,
  matchBlockedValues,
} from './orgEventReviewHelpers';

type TriageAction = 'released' | 'blocked_permanently' | 'false_positive';

const VERDICT_LABELS: Record<string, string> = {
  pending_review: 'Pending review',
  released: 'Released',
  blocked_permanently: 'Blocked permanently',
  false_positive: 'False positive',
};

const ACTION_LABELS: Record<string, string> = {
  released: 'Released',
  blocked_permanently: 'Blocked permanently',
  false_positive: 'Marked false positive',
};

export default function OrgEventReview() {
  const { orgId, projectId, eventId } = useParams<{
    orgId: string;
    projectId: string;
    eventId: string;
  }>();
  const navigate = useNavigate();
  const role = useAuthStore((s) => s.role);

  const [event, setEvent] = useState<OrgEventDetail | null>(null);
  const [blockedValues, setBlockedValues] = useState<string[]>([]);
  const [acting, setActing] = useState<TriageAction | null>(null);
  const [flash, setFlash] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyText = (text: string) => {
    // clipboard write can reject (document not focused / no permission)
    void navigator.clipboard?.writeText(text).catch(() => {});
  };

  useEffect(() => {
    if (!orgId || !projectId || !eventId) return;
    let cancelled = false;
    (async () => {
      try {
        const detail = await orgApi.getEventDetail(orgId, projectId, eventId);
        if (cancelled) return;
        setEvent(detail);

        // R4: check each indicator value against the org blocked list
        const values = (detail.analysis_result?.indicators ?? []).map(indicatorValue).filter(Boolean);
        const matched: string[] = [];
        for (const value of values) {
          try {
            const rows = await orgApi.listBlockedIndicators(orgId, value);
            matched.push(...matchBlockedValues([value], rows));
          } catch {
            // blocked-list lookup is advisory; release still gated by the 409
          }
        }
        if (!cancelled) setBlockedValues(Array.from(new Set(matched)));
      } catch (err) {
        if (cancelled) return;
        const status = err instanceof ApiError ? err.status : undefined;
        if (status === 403) navigate('/org/select', { replace: true });
        else navigate(`/org/${orgId}/projects/${projectId}/workspace`, { replace: true });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [orgId, projectId, eventId, navigate]);

  const primaryBlocked = blockedValues[0] ?? null;
  const releaseDisabled = blockedValues.length > 0 || event?.indicator_blocked === true;

  async function act(action: TriageAction) {
    if (!orgId || !projectId || !eventId || !event) return;
    setActing(action);
    setFlash(null);
    try {
      const updated = await orgApi.updateEventVerdict(orgId, projectId, eventId, action);
      setEvent({ ...event, ...updated });
      if (action === 'blocked_permanently') {
        const firstIndicator = event.analysis_result?.indicators?.[0]
          ? indicatorValue(event.analysis_result.indicators[0])
          : null;
        setFlash({
          kind: 'ok',
          text: firstIndicator
            ? `Indicator ${primaryBlocked ?? firstIndicator} added to blocked list`
            : 'Event blocked permanently (no extractable indicators to add)',
        });
      } else {
        setFlash({ kind: 'ok', text: `Verdict updated: ${VERDICT_LABELS[action] ?? action}` });
      }
    } catch (err) {
      const status = err instanceof ApiError ? err.status : undefined;
      if (status === 409) {
        setFlash({
          kind: 'err',
          text: `Cannot release: indicator ${primaryBlocked ?? ''} is permanently blocked`,
        });
      } else {
        setFlash({ kind: 'err', text: 'Action failed — try again' });
      }
    } finally {
      setActing(null);
    }
  }

  if (!event) {
    return (
      <div className="p-6 text-sm text-zinc-500" data-testid="event-review-loading">
        Loading event…
      </div>
    );
  }

  const analysis = event.analysis_result ?? {};
  const indicators = analysis.indicators ?? [];
  const mitre = analysis.mitre ?? [];
  const history = buildActionHistory(event);
  const triage = canAct(role);

  return (
    <div className="p-6" data-testid="event-review-page">
      <div className="grid gap-5 lg:grid-cols-5">
        {/* ── Left panel (60%): inspection ─────────────────────────────── */}
        <div className="space-y-4 lg:col-span-3">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <code className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-200" data-testid="event-id">
                {event.id}
              </code>
              <button
                type="button"
                data-testid="copy-id-btn"
                onClick={() => {
                  copyText(event.id);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }}
                className="text-xs rounded-lg border border-zinc-700 px-2 py-0.5 text-zinc-400 hover:bg-zinc-800"
              >
                {copied ? 'Copied' : 'Copy'}
              </button>
              <span className="text-xs text-zinc-500">{formatLocal(event.created_at)}</span>
              <span className="ml-auto text-[10px] uppercase tracking-wider rounded bg-zinc-800 px-1.5 py-0.5 text-zinc-400" data-testid="source-badge">
                {event.source}
              </span>
            </div>

            <div className="grid gap-3 sm:grid-cols-2" data-testid="event-metadata">
              <div>
                <div className="text-xs text-zinc-500">Event type</div>
                <div className="text-sm text-zinc-200" data-testid="event-type">{event.event_type}</div>
              </div>
              <div>
                <div className="text-xs text-zinc-500">Severity</div>
                <div className="mt-0.5"><SeverityBadge severity={event.severity as never} /></div>
              </div>
              <div>
                <div className="text-xs text-zinc-500">Verdict</div>
                <div className="mt-0.5 text-sm text-zinc-200" data-testid="event-verdict">{VERDICT_LABELS[event.verdict] ?? event.verdict}</div>
              </div>
              <div>
                <div className="text-xs text-zinc-500">Risk score</div>
                <div className="text-sm text-zinc-200" data-testid="event-risk">{analysis.risk_score ?? '—'}</div>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
            <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
              <span className="text-sm text-zinc-300">Raw data</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  data-testid="toggle-raw-btn"
                  onClick={() => setShowRaw((v) => !v)}
                  className="text-xs rounded-lg border border-zinc-700 px-2 py-0.5 text-zinc-400 hover:bg-zinc-800"
                >
                  {showRaw ? 'Collapse' : 'Expand'}
                </button>
                <button
                  type="button"
                  data-testid="copy-raw-btn"
                  onClick={() => copyText(JSON.stringify(event.raw_data, null, 2))}
                  className="text-xs rounded-lg border border-zinc-700 px-2 py-0.5 text-zinc-400 hover:bg-zinc-800"
                >
                  Copy
                </button>
              </div>
            </div>
            {showRaw && (
              <pre
                className="max-h-96 overflow-auto px-4 py-3 text-xs text-zinc-400 whitespace-pre-wrap"
                data-testid="raw-json"
                dangerouslySetInnerHTML={{ __html: highlightJson(event.raw_data) }}
              />
            )}
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-zinc-300">Analysis result</span>
              {analysis.engine && (
                <span className="text-[10px] uppercase tracking-wider rounded bg-zinc-800 px-1.5 py-0.5 text-zinc-400" data-testid="engine-badge">
                  {analysis.engine}
                </span>
              )}
            </div>
            <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/40 p-3" data-testid="explanation-container">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 mb-1">
                AI Explanation
              </div>
              {analysis.explanation ? (
                <p className="text-xs text-zinc-300 leading-relaxed">{analysis.explanation}</p>
              ) : (
                <LoadingSpinner text="Generating AI explanation..." />
              )}
            </div>
            {indicators.length === 0 && <div className="text-xs text-zinc-500">No indicators reported.</div>}
            <ul className="space-y-2" data-testid="indicator-list">
              {indicators.map((ind, i) => (
                <li key={i} className="rounded-lg border border-zinc-800 px-3 py-2 flex items-center gap-2 flex-wrap">
                  <span className="text-xs text-zinc-300">{indicatorType(ind)}</span>
                  <code className="text-xs text-zinc-400">{indicatorValue(ind)}</code>
                  <span className="ml-auto"><SeverityBadge severity={indicatorSeverity(ind) as never} /></span>
                </li>
              ))}
            </ul>
            {mitre.length > 0 && (
              <div className="flex gap-2 flex-wrap" data-testid="mitre-tags">
                {mitre.map((m, i) => (
                  <span key={i} className="rounded bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-300">
                    {m.id ? `${m.id} ${m.name ?? ''}` : m.name}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Right panel (40%): triage ────────────────────────────────── */}
        <div className="space-y-4 lg:col-span-2">
          {blockedValues.length > 0 && (
            <div
              className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-xs text-amber-300"
              data-testid="blocked-warning-banner"
            >
              ⚠️ Indicator {primaryBlocked} is permanently blocked. Release will fail.
            </div>
          )}

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3" data-testid="triage-panel">
            <div className="flex items-center justify-between">
              <span className="text-xs text-zinc-500">Current verdict</span>
              <span
                data-testid="verdict-badge"
                className={`rounded-full px-2.5 py-0.5 text-xs ring-1 ${
                  event.verdict === 'pending_review'
                    ? 'bg-amber-500/10 text-amber-300 ring-amber-500/40'
                    : event.verdict === 'blocked_permanently'
                      ? 'bg-red-500/10 text-red-300 ring-red-500/40'
                      : 'bg-zinc-800 text-zinc-300 ring-zinc-700'
                }`}
              >
                {VERDICT_LABELS[event.verdict] ?? event.verdict}
              </span>
            </div>
            {event.acted_at && (
              <div className="text-xs text-zinc-500">
                Acted by: <span className="text-zinc-300">{event.acted_by}</span> at {formatLocal(event.acted_at)}
              </div>
            )}

            {flash && (
              <div
                data-testid="action-flash"
                className={`rounded-lg px-3 py-2 text-xs ${
                  flash.kind === 'ok'
                    ? 'bg-emerald-500/10 text-emerald-300'
                    : 'bg-red-500/10 text-red-300'
                }`}
              >
                {flash.text}
              </div>
            )}

            {triage ? (
              <div className="space-y-2">
                <button
                  type="button"
                  data-testid="release-btn"
                  disabled={acting !== null || releaseDisabled}
                  onClick={() => act('released')}
                  className="w-full rounded-lg border border-emerald-600/50 px-3 py-2 text-sm text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-40"
                >
                  {acting === 'released' ? 'Releasing…' : 'Release'}
                </button>
                <button
                  type="button"
                  data-testid="block-btn"
                  disabled={acting !== null}
                  onClick={() => act('blocked_permanently')}
                  className="w-full rounded-lg border border-red-600/50 px-3 py-2 text-sm text-red-300 hover:bg-red-500/10 disabled:opacity-40"
                >
                  {acting === 'blocked_permanently' ? 'Blocking…' : 'Block Permanently'}
                </button>
                <button
                  type="button"
                  data-testid="fp-btn"
                  disabled={acting !== null}
                  onClick={() => act('false_positive')}
                  className="w-full rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-40"
                >
                  {acting === 'false_positive' ? 'Marking…' : 'Mark False Positive'}
                </button>
              </div>
            ) : (
              <div className="text-xs text-zinc-500" data-testid="read-only-note">
                Read-only: viewer keys cannot triage events.
              </div>
            )}
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4" data-testid="action-history">
            <div className="text-sm text-zinc-300 mb-2">Action history</div>
            {history.length === 0 ? (
              <div className="text-xs text-zinc-500" data-testid="history-empty">No actions yet</div>
            ) : (
              <ol className="space-y-2 border-l border-zinc-800 pl-3">
                {history.map((h, i) => (
                  <li key={i} className="text-xs text-zinc-400" data-testid="history-entry">
                    <span className="text-zinc-200">{ACTION_LABELS[h.user_action] ?? h.user_action}</span>{' '}
                    — {formatLocal(h.acted_at)} · {h.acted_by}
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
