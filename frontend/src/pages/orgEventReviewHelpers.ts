/**
 * Pure helpers for the ORG-DASHBOARD-P2 event review page, kept .ts-only
 * so the node:test runner (strip-types, no JSX) can import them directly.
 */

import type { OrgBlockedIndicatorRow, OrgEventDetail } from '../services/orgApi';

/** Viewer keys cannot triage (R3: admin/analyst only). */
export function canAct(role: string | undefined): boolean {
  return Boolean(role) && role !== 'viewer';
}

/** Exact-match the event's indicator values against blocked rows (R4). */
export function matchBlockedValues(
  indicatorValues: string[],
  blocked: Array<Pick<OrgBlockedIndicatorRow, 'indicator_value'>>
): string[] {
  const blockedSet = new Set(blocked.map((b) => b.indicator_value.trim().toLowerCase()));
  return indicatorValues.filter((v) => blockedSet.has(v.trim().toLowerCase()));
}

/** Action-history timeline entries from the event (backend stores latest action). */
export function buildActionHistory(event: OrgEventDetail | null): Array<{
  acted_at: string;
  acted_by: string;
  user_action: string;
}> {
  if (!event || !event.acted_at || !event.user_action) return [];
  return [
    { acted_at: event.acted_at, acted_by: event.acted_by ?? 'unknown', user_action: event.user_action },
  ];
}

/** Tiny JSON syntax highlighter for the collapsible raw-data viewer. */
export function highlightJson(value: unknown): string {
  const json = JSON.stringify(value, null, 2);
  return json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"([^"]+)":/g, '<span class="text-zinc-300">"$1"</span>:')
    .replace(/: "(.*?)"/g, ': <span class="text-emerald-300">"$1"</span>')
    .replace(/: (-?\d+\.?\d*)/g, ': <span class="text-amber-300">$1</span>')
    .replace(/: (true|false|null)/g, ': <span class="text-sky-300">$1</span>');
}

export function indicatorValue(ind: Record<string, unknown>): string {
  return String(ind.value ?? ind.indicator_value ?? '');
}

export function indicatorSeverity(ind: Record<string, unknown>): string {
  return String(ind.severity ?? 'low');
}

export function indicatorType(ind: Record<string, unknown>): string {
  return String(ind.type ?? ind.indicator_type ?? 'indicator');
}
