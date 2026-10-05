import { AlertTriangle, CheckCircle2, Hourglass, ShieldCheck } from 'lucide-react';
import type { FeatureAnalysis, ScanResult } from '../../types';
import { normalizeScorePct } from '../../utils/score';
import LoadingSpinner from './LoadingSpinner';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'safe'] as const;

export const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 ring-1 ring-red-500/40',
  high: 'bg-orange-500/10 text-orange-400 ring-1 ring-orange-500/40',
  medium: 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/40',
  low: 'bg-yellow-500/10 text-yellow-500 ring-1 ring-yellow-500/40',
  safe: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
};

const ACTION_LABELS: Record<string, string> = {
  pass: 'Pass',
  notify: 'Notify',
  quarantine: 'Quarantine',
  block: 'Quarantine + Block sender',
  // Legacy values (rows stored before the 4-tier action matrix):
  flag_for_review: 'Flag for manual review',
  none: 'No action required',
};

/**
 * Verbose, structured analysis view (Phase 3): severity badge, risk gauge,
 * per-engine explanations with evidence tables, and the honest provider
 * operation status (analysis results are never presented as actions).
 */
export default function VerboseResultPanel({ scan }: { scan: ScanResult }) {
  const severityStyle = SEVERITY_STYLES[scan.overall_severity] ?? SEVERITY_STYLES.safe;
  const scorePct = normalizeScorePct(scan.overall_score);
  const deferred = scan.provider_operation_status === 'deferred_to_phase_4';

  const sortedAnalyses = [...scan.feature_analyses].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity as (typeof SEVERITY_ORDER)[number]) -
        SEVERITY_ORDER.indexOf(b.severity as (typeof SEVERITY_ORDER)[number]) ||
      b.score - a.score,
  );

  return (
    <div className="space-y-5">
      {/* Header: severity badge + risk gauge */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-zinc-800 bg-zinc-950/60 p-4">
        <div className="flex items-center gap-3">
          <span className={`rounded-md px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-widest ${severityStyle}`}>
            {scan.overall_severity}
          </span>
          <div>
            <p className="text-sm font-semibold text-zinc-100">Risk score {scorePct}/100</p>
            <p className="font-mono text-[11px] text-zinc-500">
              {scan.feature_analyses.length} engine(s) · deterministic heuristics + ML blending
            </p>
          </div>
        </div>
        {/* Score gauge */}
        <div className="flex items-center gap-3">
          <div className="h-2.5 w-40 overflow-hidden rounded-full bg-zinc-800">
            <div
              className={`h-full rounded-full ${scorePct >= 70 ? 'bg-red-500' : scorePct >= 40 ? 'bg-amber-500' : 'bg-emerald-500'}`}
              style={{ width: `${scorePct}%` }}
            />
          </div>
          <span className="font-mono text-lg font-bold text-zinc-100">{scorePct}</span>
        </div>
      </div>

      {/* Overall explanation */}
      <div>
        <h4 className="mb-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-red-400">
          Why this verdict
        </h4>
        {scan.overall_explanation ? (
          <p className="whitespace-pre-line text-sm leading-relaxed text-zinc-300">{scan.overall_explanation}</p>
        ) : (
          <LoadingSpinner text="Generating AI explanation..." />
        )}
      </div>

      {/* Per-engine feature analyses */}
      <div className="space-y-3">
        {sortedAnalyses.map((analysis) => (
          <FeatureBlock key={analysis.engine} analysis={analysis} />
        ))}
      </div>

      {/* Recommended action + honest provider status */}
      <div className="grid gap-3 md:grid-cols-2">
        <div className="flex items-start gap-2.5 rounded-xl border border-zinc-800 bg-zinc-900/90 p-4">
          <ShieldCheck className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" />
          <div>
            <p className="font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">
              Recommended action
            </p>
            <p className="mt-0.5 text-sm font-semibold text-zinc-100">
              {ACTION_LABELS[scan.recommended_action] ?? scan.recommended_action}
            </p>
          </div>
        </div>
        <div
          className={`flex items-start gap-2.5 rounded-xl border p-4 ${
            deferred ? 'border-amber-500/30 bg-amber-500/5' : 'border-zinc-800 bg-zinc-900/90'
          }`}
        >
          {deferred ? (
            <Hourglass className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-400" />
          ) : (
            <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-zinc-500" />
          )}
          <div>
            <p className="font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">
              Provider operation status
            </p>
            <p className="mt-0.5 font-mono text-xs text-zinc-200">{scan.provider_operation_status}</p>
            {scan.provider_operation_detail && (
              <p className="mt-1 text-xs leading-relaxed text-zinc-500">{scan.provider_operation_detail}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function FeatureBlock({ analysis }: { analysis: FeatureAnalysis }) {
  const style = SEVERITY_STYLES[analysis.severity] ?? SEVERITY_STYLES.safe;
  const hasEvidence = analysis.indicators.length > 0;
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs font-bold text-zinc-100">{analysis.engine}</span>
          <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${style}`}>
            {analysis.severity}
          </span>
        </div>
        <span className="font-mono text-xs text-zinc-500">score {normalizeScorePct(analysis.score)}/100</span>
      </div>

      {analysis.explanation ? (
        <p className="mt-2 whitespace-pre-line text-xs leading-relaxed text-zinc-400">{analysis.explanation}</p>
      ) : (
        <LoadingSpinner text="Generating AI explanation..." />
      )}

      {hasEvidence ? (
        <div className="mt-3 overflow-hidden rounded-lg border border-zinc-800">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-zinc-900 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                <th className="px-3 py-2">Indicator</th>
                <th className="px-3 py-2">Evidence / matched value</th>
                <th className="px-3 py-2 text-right">Weight</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/70">
              {analysis.indicators.map((indicator, idx) => (
                <tr key={`${indicator.name}-${idx}`} className="text-zinc-300">
                  <td className="px-3 py-2 font-mono text-[11px] text-zinc-400">{indicator.name}</td>
                  <td className="max-w-md break-words px-3 py-2">{indicator.value}</td>
                  <td className="px-3 py-2 text-right font-mono text-zinc-500">{indicator.weight}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="mt-3 flex items-center gap-1.5 text-[11px] text-zinc-600">
          <AlertTriangle className="h-3 w-3" /> No indicators were raised by this engine.
        </p>
      )}
    </div>
  );
}
