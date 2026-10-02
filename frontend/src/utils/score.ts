/**
 * Normalize a stored risk score to a 0-100 percentage for display.
 *
 * Producers persist scores on the 0.0-1.0 scale (ScanResult.overall_score,
 * FeatureAnalysis.score, ProcessedEmail.risk_score). Legacy rows written
 * before that contract may already hold 0-100 — treat values above 1 as
 * already-percentage and clamp everything to 0-100 so gauges never overflow.
 */
export function normalizeScorePct(score: number | null | undefined): number {
  const raw = Number(score ?? 0);
  const pct = raw <= 1 ? raw * 100 : raw;
  return Math.max(0, Math.min(100, Math.round(pct)));
}
