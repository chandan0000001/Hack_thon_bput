/**
 * Pure helpers for the ORG-DASHBOARD-P3 events list page, kept .ts-only
 * for the node:test runner (strip-types cannot import .tsx — and orgApi
 * transitively imports extensionless modules node cannot resolve).
 */

import type { OrgEventRow } from '../services/orgApi';

/** ORG-DASHBOARD-P3: events-list filter set (server contract names). */
export interface EventsListFilters {
  eventType?: string; // network_event | ato_event | log_event
  severity?: string; // critical | high | medium | low
  verdict?: string; // pending_review | released | blocked_permanently | false_positive
  q?: string;
  limit?: number;
  offset?: number;
}

/** Build the query string for the events list endpoint (empty params omitted). */
export function eventsQueryParams(filters: EventsListFilters): string {
  const params = new URLSearchParams();
  if (filters.eventType) params.set('event_type', filters.eventType);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.verdict) params.set('verdict', filters.verdict);
  if (filters.q) params.set('q', filters.q);
  params.set('limit', String(filters.limit ?? 50));
  if (filters.offset) params.set('offset', String(filters.offset));
  const qs = params.toString();
  return qs ? `?${qs}` : '';
}

/** Append a page of events to existing rows, dropping id duplicates. */
export function appendEvents(existing: OrgEventRow[], incoming: OrgEventRow[]): OrgEventRow[] {
  const seen = new Set(existing.map((e) => e.id));
  return [...existing, ...incoming.filter((e) => !seen.has(e.id))];
}

/** Relative time like "4m ago"; falls back to the raw string when unparseable. */
export function relativeTime(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 45) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export const VERDICT_CHIP_CLASSES: Record<string, string> = {
  pending_review: 'bg-amber-500/10 text-amber-300 ring-amber-500/40',
  released: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/40',
  blocked_permanently: 'bg-red-500/10 text-red-300 ring-red-500/40',
  false_positive: 'bg-zinc-800 text-zinc-300 ring-zinc-700',
};

export const VERDICT_LABELS: Record<string, string> = {
  pending_review: 'Pending review',
  released: 'Released',
  blocked_permanently: 'Blocked',
  false_positive: 'False positive',
};

export const EVENT_TYPE_LABELS: Record<string, string> = {
  network_event: 'Network',
  ato_event: 'ATO',
  log_event: 'Log',
};
