import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { SEVERITY_STYLES } from './VerboseResultPanel';
import { normalizeScorePct } from '../../utils/score';
import { formatLocal } from '../../utils/datetime';

export interface EngineSummary {
  engine: string;
  score: number; // 0.0-1.0
}

const ACTION_LABELS: Record<string, string> = {
  pass: 'Pass',
  notify: 'Notify',
  quarantine: 'Quarantine',
  block: 'Quarantine + Block sender',
  // Legacy values (rows stored before the 4-tier action matrix):
  flag_for_review: 'Flag for manual review',
  none: 'No action required',
  clean: 'No action required',
};

const PROVIDER_STATUS_LABELS: Record<string, string> = {
  quarantined: 'Quarantined',
  success: 'Action succeeded',
  clean: 'Delivered to inbox',
  notified: 'User notified',
  notify_recommended: 'Notify (advisory)',
  no_action_required: 'No action required',
  skipped_trusted_sender: 'Skipped (trusted sender)',
  review_recommended: 'Review recommended',
  enforcement_error: 'Enforcement error',
  pending: 'Pending',
  completed: 'Completed',
  analysis_only: 'Analysis only',
};

const PROCESSING_STATUS_STYLES: Record<string, string> = {
  completed: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  analyzing: 'bg-blue-500/10 text-blue-400 ring-1 ring-blue-500/30 animate-pulse',
  fetching: 'bg-blue-500/10 text-blue-400 ring-1 ring-blue-500/30 animate-pulse',
};

function scoreTone(pct: number): string {
  return pct >= 70
    ? 'text-red-400'
    : pct >= 40
      ? 'text-amber-400'
      : 'text-zinc-500';
}

/**
 * Shared row card for email analysis previews (live ingestion feed and
 * manual scan results): severity badge, subject/sender, per-engine scores,
 * normalized 0-100 risk score, recommended action, and the honest provider
 * operation status. Both previews must render through this component so
 * their layout, styling, and information hierarchy stay identical.
 */
export default function EmailAnalysisResultCard({
  severity,
  subject,
  sender,
  receivedAt,
  score,
  engines = [],
  recommendedAction,
  providerOperationStatus,
  processingStatus,
  enforcementDetail,
  onClick,
  trailing,
}: {
  severity: string;
  subject: string;
  sender?: string | null;
  receivedAt?: string | null;
  /** Risk score in whatever scale the producer stored — normalized to 0-100. */
  score: number | null | undefined;
  engines?: EngineSummary[];
  recommendedAction?: string | null;
  providerOperationStatus?: string | null;
  /** Pipeline stage badge (live feed only): fetching / analyzing / completed. */
  processingStatus?: string | null;
  /** One-line enforcement explanation (live feed only). */
  enforcementDetail?: string | null;
  onClick?: () => void;
  trailing?: ReactNode;
}) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.safe;
  const scorePct = normalizeScorePct(score);
  const actionLabel = recommendedAction
    ? (ACTION_LABELS[recommendedAction] ?? recommendedAction)
    : null;
  const providerLabel = providerOperationStatus
    ? (PROVIDER_STATUS_LABELS[providerOperationStatus] ?? providerOperationStatus)
    : null;

  const body = (
    <>
      <div className="flex flex-wrap items-center gap-2">
        {processingStatus ? (
          <span
            className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
              PROCESSING_STATUS_STYLES[processingStatus] ?? 'bg-zinc-800 text-zinc-400'
            }`}
          >
            {processingStatus === 'fetching' || processingStatus === 'analyzing' ? (
              <span className="flex items-center gap-1">
                <Loader2 className="h-3 w-3 animate-spin" />
                {processingStatus}
              </span>
            ) : (
              processingStatus
            )}
          </span>
        ) : null}
        <span
          className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${style}`}
        >
          {severity}
        </span>
        {recommendedAction === 'block' && (
          <span
            title="Critical verdict: the sender was added to the org blocklist and a provider filter auto-quarantines future mail from them"
            className="rounded bg-red-500/20 px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-red-300 ring-1 ring-red-500/50"
          >
            Sender blocked
          </span>
        )}
        <span className="min-w-0 flex-1 truncate text-sm text-zinc-200">
          {subject || '(no subject)'}
          {sender ? <span className="ml-2 text-xs text-zinc-500">— {sender}</span> : null}
        </span>
        <span className={`font-mono text-xs ${scoreTone(scorePct)}`}>{scorePct}/100</span>
        {(actionLabel || providerLabel) && (
          <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-600">
            {actionLabel ? `action: ${actionLabel}` : null}
            {actionLabel && providerLabel ? ' · ' : null}
            {providerLabel ? providerLabel : null}
          </span>
        )}
        {trailing}
      </div>
      {(engines.length > 0 || enforcementDetail || receivedAt) && (
        <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px]">
          {engines.map((e) => (
            <span
              key={e.engine}
              className="rounded bg-zinc-800/80 px-1.5 py-0.5 font-mono text-zinc-400"
              title={`${e.engine} engine score`}
            >
              {e.engine}: {normalizeScorePct(e.score)}/100
            </span>
          ))}
          {enforcementDetail && (
            <span className="truncate max-w-2xl text-zinc-400">💡 {enforcementDetail}</span>
          )}
          {receivedAt && (
            <span className="text-zinc-600">· {formatLocal(receivedAt)}</span>
          )}
        </div>
      )}
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className="flex w-full flex-col gap-1 px-5 py-3.5 text-left transition hover:bg-zinc-900"
      >
        {body}
      </button>
    );
  }
  return <div className="flex flex-col gap-1 px-5 py-3.5 text-xs transition hover:bg-zinc-800/30">{body}</div>;
}
