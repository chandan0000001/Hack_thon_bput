/**
 * ATO-UI-OVERHAUL — Account Takeover detail view (READ-ONLY).
 *
 * Route /org/:orgId/projects/:projectId/analysis/account-takeover/:eventId.
 * Replaces the manual analysis form: the payload is fetched from
 * GET /analysis/account-takeover/events/{eventId} (tenant resolved
 * server-side) and rendered — prominent action banner, baseline display,
 * vertical attack timeline, evidence + recommended actions, and the XAI
 * explanation panel. Zero input elements.
 */

import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Clock, Lock, ShieldCheck, UserCheck } from 'lucide-react';
import { orgApi, type AtoEventDetail } from '../services/orgApi';
import ExplanationPanel from '../components/common/ExplanationPanel';
import {
  ATO_ACTION_KEYS,
  atoActionAfterManual,
  atoActionBadge,
  atoActionButtonClass,
  atoActionLabel,
  atoActionToastText,
  atoActionUiState,
  atoBannerLabel,
  atoBannerTone,
  atoClockLabel,
  atoDotClass,
  atoLevelTone,
  sortAtoTimeline,
  type AtoActionKey,
  type AtoActionLedgerEntry,
} from './orgAtoHelpers';

function BaselineDisplay({ baseline }: { baseline: Record<string, unknown> }) {
  const rows: Array<[string, string]> = [
    ['Account', String(baseline.user ?? '—')],
    ['Role', String(baseline.role ?? '—')],
    ['Usual login window', `${baseline.typical_login_start ?? '?'}–${baseline.typical_login_end ?? '?'} local`],
    ['Home country', String(baseline.home_country ?? '—')],
    ['Known IPs', ((baseline.known_ips as string[]) ?? []).join(', ') || '—'],
    ['Known devices', ((baseline.known_devices as string[]) ?? []).join(', ') || '—'],
  ];
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4" data-testid="ato-baseline-section">
      <div className="text-sm text-zinc-300 mb-3">Normal baseline</div>
      <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-2">
        {rows.map(([label, value]) => (
          <div key={label} className="flex gap-2 text-sm">
            <dt className="w-40 shrink-0 text-zinc-500">{label}</dt>
            <dd className="text-zinc-200 font-mono text-xs leading-5">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export default function OrgAccountTakeoverDetail() {
  const { orgId, eventId } = useParams<{ orgId: string; eventId: string }>();
  const [detail, setDetail] = useState<AtoEventDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ledger, setLedger] = useState<Record<string, AtoActionLedgerEntry>>({});
  const [acting, setActing] = useState<AtoActionKey | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    if (!orgId || !eventId) return;
    let cancelled = false;
    orgApi
      .getAtoEventDetail(orgId, eventId)
      .then((data) => {
        if (!cancelled) {
          setDetail(data);
          setLedger(data.action_ledger ?? {});
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load ATO event.');
      });
    return () => {
      cancelled = true;
    };
  }, [orgId, eventId]);

  async function runManualAction(action: AtoActionKey) {
    if (!orgId || !eventId || !detail) return;
    setActing(action);
    setActionError(null);
    try {
      const result = await orgApi.executeAtoAction(orgId, eventId, action);
      if (result.executed) {
        // Pending -> Done (Manual); button disables itself.
        setLedger((prev) => atoActionAfterManual(prev, action));
        setToast(atoActionToastText(action));
        setTimeout(() => setToast(null), 4000);
      } else {
        // Already executed (auto or a previous manual click) — reflect truth.
        setLedger(result.action_ledger ?? {});
        setToast(null);
      }
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setActing(null);
    }
  }

  if (error) {
    return (
      <div className="p-6" data-testid="org-ato-detail-page">
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300" data-testid="ato-detail-error">
          {error}
        </div>
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="p-6 text-sm text-zinc-500" data-testid="org-ato-detail-page">
        Loading analysis…
      </div>
    );
  }

  const tone = atoLevelTone(detail.risk_level);
  const timeline = sortAtoTimeline(detail.suspicious_events);
  const bannerIcon =
    detail.action_taken === 'ACCOUNT_RESTRICTED' ? (
      <Lock style={{ width: 20, height: 20 }} />
    ) : detail.action_taken === 'USER_NOTIFIED' ? (
      <UserCheck style={{ width: 20, height: 20 }} />
    ) : (
      <ShieldCheck style={{ width: 20, height: 20 }} />
    );

  return (
    <div className="p-6 space-y-5" data-testid="org-ato-detail-page">
      {/* Top banner: the enforced action, prominent */}
      <div
        className={`flex items-center gap-3 rounded-xl border px-4 py-4 ${atoBannerTone(detail.action_taken)}`}
        data-testid="ato-action-banner"
      >
        {bannerIcon}
        <div>
          <div className="text-sm font-bold tracking-wide" data-testid="ato-action-text">
            {atoBannerLabel(detail.action_taken)}
          </div>
          <div className="text-xs opacity-70">
            {detail.account_id ?? 'unknown account'} · enforcement decided by the fused risk score
          </div>
        </div>
        <span
          className={`ml-auto rounded-full px-3 py-1 text-xs font-semibold ring-1 ${tone.ring} ${tone.text}`}
          data-testid="ato-risk-pill"
        >
          {tone.label} · {detail.risk_score}/100
        </span>
      </div>

      <div className="text-xs text-zinc-500">
        analyzed {new Date(detail.created_at).toLocaleString()} · org {detail.organization.name}
        {detail.project ? ` · project ${detail.project.id.slice(0, 8)}…` : ''}
      </div>

      <BaselineDisplay baseline={detail.baseline_profile as Record<string, unknown>} />

      {/* Attack timeline (vertical) */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
        <div className="text-sm text-zinc-300 mb-4">Attack timeline</div>
        <div className="relative ml-3 border-l-2 border-zinc-800 space-y-6" data-testid="ato-timeline">
          {timeline.map((event, idx) => (
            <div key={idx} className="relative pl-6" data-testid="ato-timeline-item">
              <span
                className={`absolute -left-[8px] top-1 h-4 w-4 rounded-full ring-4 ring-zinc-950 ${atoDotClass(event)}`}
              />
              <div className="flex items-center gap-2 text-sm text-zinc-200">
                <Clock className="text-zinc-500" style={{ width: 14, height: 14 }} />
                <span className="font-mono" data-testid="ato-timeline-time">
                  {atoClockLabel(event.timestamp)}
                </span>
                <span className="text-zinc-400">{event.detail || String(event.event_type ?? 'event')}</span>
              </div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {(event.flagged ?? []).map((flag) => (
                  <span
                    key={flag}
                    className="rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-300 ring-1 ring-red-500/30"
                  >
                    {flag.split('_').join(' ')}
                  </span>
                ))}
                {typeof event.event_score === 'number' && event.event_score > 0 && (
                  <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">
                    +{event.event_score} risk
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Evidence + recommended actions */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
          <div className="text-sm text-zinc-300 mb-3">Evidence</div>
          <ul className="space-y-2" data-testid="ato-indicators">
            {detail.indicators.map((indicator, idx) => (
              <li key={idx} className="flex items-start gap-2 text-sm">
                <span
                  className={
                    indicator.severity === 'critical' || indicator.severity === 'high'
                      ? 'text-red-400'
                      : 'text-amber-400'
                  }
                >
                  ✗
                </span>
                <span className="text-zinc-300">{indicator.description}</span>
                <span className="ml-auto text-[10px] uppercase tracking-wider text-zinc-600">
                  {indicator.signal}
                </span>
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4">
          <div className="text-sm font-semibold text-emerald-300 mb-2">Recommended actions</div>
          <ol className="list-decimal space-y-1 pl-5 text-sm text-zinc-300" data-testid="ato-actions">
            {detail.recommended_actions.map((action, idx) => (
              <li key={idx}>{action}</li>
            ))}
          </ol>
        </div>
      </div>

      {/* ATO-HYBRID-ACTIONS: unified action center — shows the STATE of each
          action (Pending / Done (Auto) / Done (Manual)), not just buttons.
          Automatic executions arrive in the ledger as done_auto; manual ones
          go through the same backend executor via PATCH. */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4" data-testid="ato-actions-panel">
        <div className="flex items-center justify-between mb-3">
          <div className="text-sm text-zinc-300">Analyst actions</div>
          <div className="text-[10px] uppercase tracking-wider text-zinc-600">
            same executor as the automatic pipeline
          </div>
        </div>
        <div className="space-y-3">
          {ATO_ACTION_KEYS.map((action) => {
            const state = atoActionUiState(ledger[action]);
            const badge = atoActionBadge(state);
            return (
              <div
                key={action}
                className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-950/60 px-3 py-2.5"
                data-testid={`ato-action-${action}`}
              >
                <span
                  className={`inline-block rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${badge.className}`}
                  data-testid={`ato-action-badge-${action}`}
                >
                  {badge.label}
                </span>
                <span className="text-sm text-zinc-300">{atoActionLabel(action)}</span>
                {typeof ledger[action]?.executed_at === 'string' && (
                  <span className="text-[10px] text-zinc-600">
                    {new String(ledger[action].executed_at).slice(0, 19).replace('T', ' ')}
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => runManualAction(action)}
                  disabled={state !== 'pending' || acting !== null}
                  className={`ml-auto rounded-lg px-3 py-1.5 text-xs font-semibold disabled:cursor-not-allowed disabled:opacity-40 ${atoActionButtonClass(action)}`}
                  data-testid={`ato-action-btn-${action}`}
                >
                  {acting === action ? 'Executing…' : atoActionLabel(action)}
                </button>
              </div>
            );
          })}
        </div>
        {actionError && (
          <div className="mt-3 text-xs text-red-400" data-testid="ato-action-error">
            {actionError}
          </div>
        )}
      </div>

      <ExplanationPanel
        explanation={detail.explanation}
        confidence={detail.risk_score}
        eventId={detail.alert_id ?? undefined}
      />

      {/* Success toast for manual actions */}
      {toast && (
        <div
          className="fixed bottom-6 right-6 z-50 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm font-medium text-emerald-300 shadow-lg"
          data-testid="ato-toast"
          role="status"
        >
          {toast}
        </div>
      )}
    </div>
  );
}
