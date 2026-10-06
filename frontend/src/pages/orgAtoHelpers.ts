/**
 * SCENARIO-3: pure helpers for the org Account-Takeover timeline UI.
 * Kept framework-free so node:test can exercise them directly.
 */

export interface AtoTimelineEvent {
  timestamp?: string;
  event_type?: string;
  detail?: string;
  flagged?: string[];
  event_score?: number;
  [key: string]: unknown;
}

/** "2026-10-06T03:17:00" -> "03:17 AM" (falls back to the raw value). */
export function atoClockLabel(timestamp?: string): string {
  if (!timestamp) return 'Unknown time';
  const match = /T(\d{2}):(\d{2})/.exec(timestamp);
  if (!match) return timestamp;
  const hour = Number(match[1]);
  const minute = match[2];
  const suffix = hour < 12 ? 'AM' : 'PM';
  const display = hour % 12 || 12;
  return `${String(display).padStart(2, '0')}:${minute} ${suffix}`;
}

/** Timeline dot color: flagged events get the red dot, clean ones emerald. */
export function atoDotClass(event: AtoTimelineEvent): string {
  return event.flagged && event.flagged.length > 0
    ? 'bg-red-500 ring-red-500/30'
    : 'bg-emerald-500 ring-emerald-500/30';
}

/** Verdict tone for the risk-level pill. */
export function atoLevelTone(
  level: string
): { text: string; ring: string; label: string } {
  switch ((level || '').toLowerCase()) {
    case 'critical':
      return { text: 'text-red-300', ring: 'ring-red-500/40 bg-red-500/10', label: 'CRITICAL' };
    case 'high':
      return { text: 'text-red-300', ring: 'ring-red-500/40 bg-red-500/10', label: 'HIGH' };
    case 'medium':
      return { text: 'text-amber-300', ring: 'ring-amber-500/40 bg-amber-500/10', label: 'MEDIUM' };
    default:
      return { text: 'text-emerald-300', ring: 'ring-emerald-500/40 bg-emerald-500/10', label: 'LOW' };
  }
}

/** Stable chronological ordering for the vertical timeline. */
export function sortAtoTimeline<T extends AtoTimelineEvent>(events: T[]): T[] {
  return [...events].sort((a, b) =>
    String(a.timestamp ?? '').localeCompare(String(b.timestamp ?? ''))
  );
}

/** ATO-UI-OVERHAUL: row of GET /analysis/account-takeover/events. */
export interface AtoEventSummary {
  id: string;
  timestamp: string;
  user_email: string;
  risk_score: number;
  action_taken: string;
  tier: string;
  severity?: string;
  account_restricted?: boolean;
}

/** Real-time search filter: case-insensitive substring on event id or
 * account email. Empty/whitespace query returns the list unchanged. */
export function filterAtoEvents<T extends { id: string; user_email: string }>(
  events: T[],
  query: string
): T[] {
  const q = query.trim().toLowerCase();
  if (!q) return events;
  return events.filter(
    (e) => e.id.toLowerCase().includes(q) || e.user_email.toLowerCase().includes(q)
  );
}

/** Status pill for the enforcement action. */
export function atoStatusTone(
  actionTaken?: string
): { label: string; className: string } {
  switch (actionTaken) {
    case 'ACCOUNT_RESTRICTED':
      return {
        label: 'Restricted',
        className: 'bg-red-500/10 text-red-300 ring-1 ring-red-500/40',
      };
    case 'USER_NOTIFIED':
      return {
        label: 'Notified',
        className: 'bg-amber-500/10 text-amber-300 ring-1 ring-amber-500/40',
      };
    default:
      return {
        label: 'Allowed',
        className: 'bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/40',
      };
  }
}

/** Risk-score badge tone following the 3-tier bands. */
export function atoScoreTone(score: number): string {
  if (score < 30) return 'bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/40';
  if (score < 75) return 'bg-amber-500/10 text-amber-300 ring-1 ring-amber-500/40';
  return 'bg-red-500/10 text-red-300 ring-1 ring-red-500/40';
}

/** Detail banner text for the enforced action. */
export function atoBannerLabel(actionTaken?: string): string {
  switch (actionTaken) {
    case 'ACCOUNT_RESTRICTED':
      return 'ACCOUNT RESTRICTED & USER NOTIFIED';
    case 'USER_NOTIFIED':
      return 'USER NOTIFIED';
    default:
      return 'ACTIVITY ALLOWED — NO ACTION REQUIRED';
  }
}

/** Detail banner styling per tier. */
export function atoBannerTone(actionTaken?: string): string {
  switch (actionTaken) {
    case 'ACCOUNT_RESTRICTED':
      return 'border-red-500/50 bg-red-500/10 text-red-200';
    case 'USER_NOTIFIED':
      return 'border-amber-500/50 bg-amber-500/10 text-amber-200';
    default:
      return 'border-emerald-500/50 bg-emerald-500/10 text-emerald-200';
  }
}

/** Demo payload (mirrors scenarios/scenario-3/assets) for one-click runs. */
export const ATO_DEMO_BASELINE = {
  account_id: 'sarah.chen@acme.com',
  baseline_profile: {
    user: 'sarah.chen@acme.com',
    role: 'Finance Director',
    typical_login_start: '09:00',
    typical_login_end: '10:00',
    home_country: 'US',
    known_ips: ['98.42.117.6', '10.0.4.15'],
    known_devices: ['MAC-BOOK-A7F3', 'IPHONE-12-SARAH'],
  },
};

export const ATO_DEMO_TIMELINE = [
  {
    timestamp: '2026-10-06T03:17:00',
    event_type: 'login_success',
    source_ip: '203.0.113.77',
    country: 'RU',
    device_id: 'WIN-XK22B9',
    detail: 'Login from unfamiliar IP (Country mismatch)',
  },
  {
    timestamp: '2026-10-06T03:18:00',
    event_type: 'failed_login',
    failed_attempts: 8,
    source_ip: '203.0.113.77',
    country: 'RU',
    device_id: 'WIN-XK22B9',
    detail: '8 failed login attempts',
  },
  {
    timestamp: '2026-10-06T03:20:00',
    event_type: 'login_success',
    source_ip: '203.0.113.77',
    country: 'RU',
    device_id: 'WIN-XK22B9',
    detail: 'Successful login from new device',
  },
  { timestamp: '2026-10-06T03:22:00', event_type: 'password_change', detail: 'Password changed' },
  {
    timestamp: '2026-10-06T03:25:00',
    event_type: 'file_access',
    files_accessed: 150,
    detail: '150 files accessed/downloaded',
  },
];
