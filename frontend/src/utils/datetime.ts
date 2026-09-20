/**
 * Shared timestamp rendering. Backend timestamps are UTC; some legacy fields are
 * serialized without a timezone suffix, so a naive string is treated as UTC
 * before converting to the browser's local time for display.
 */

export function parseBackendDate(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  let s = iso;
  const tzAware = /(?:Z|z|[+-]\d{2}:?\d{2})$/.test(s);
  if (!tzAware) s += 'Z';
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

export function formatLocal(iso: string | null | undefined): string {
  const d = parseBackendDate(iso);
  return d ? d.toLocaleString() : '—';
}

export function formatLocalTime(iso: string | null | undefined): string {
  const d = parseBackendDate(iso);
  return d ? d.toLocaleTimeString() : '—';
}
