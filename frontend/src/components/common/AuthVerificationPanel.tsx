import { ShieldCheck, ShieldX, ShieldQuestion } from 'lucide-react';
import type { AuthVerification } from '../../types';

/**
 * Compact per-protocol SPF/DKIM/DMARC verification panel for the manual
 * scan path. Rendered above the indicator table whenever the backend's
 * `auth_verification` section is present in the response.
 */

const STATUS_STYLES: Record<string, { chip: string; Icon: typeof ShieldCheck; label: string }> = {
  pass: { chip: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30', Icon: ShieldCheck, label: 'PASS' },
  fail: { chip: 'bg-red-500/15 text-red-400 ring-1 ring-red-500/40', Icon: ShieldX, label: 'FAIL' },
  softfail: { chip: 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/40', Icon: ShieldQuestion, label: 'SOFTFAIL' },
  unavailable: { chip: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700', Icon: ShieldQuestion, label: 'UNAVAILABLE' },
};

const PROTOCOLS: [keyof AuthVerification, string][] = [
  ['spf', 'SPF'],
  ['dkim', 'DKIM'],
  ['dmarc', 'DMARC'],
];

export default function AuthVerificationPanel({
  verification,
}: {
  verification?: AuthVerification | null;
}) {
  if (!verification) return null;
  const independent = verification.source === 'independent';
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">
          Auth Verification
        </h3>
        <span
          className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${
            independent
              ? 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30'
              : 'bg-zinc-800 text-zinc-500 ring-1 ring-zinc-700'
          }`}
          title={
            independent
              ? 'Protocols verified independently from raw message headers'
              : 'Verification degraded — no raw headers were supplied'
          }
        >
          {independent ? 'independent' : verification.source || 'degraded'}
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        {PROTOCOLS.map(([key, label]) => {
          const status = String(verification[key] ?? 'unavailable');
          const style = STATUS_STYLES[status] ?? STATUS_STYLES.unavailable;
          const { Icon } = style;
          return (
            <span
              key={key}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-[11px] font-bold ${style.chip}`}
            >
              <Icon className="h-3.5 w-3.5" />
              {label} {style.label}
            </span>
          );
        })}
      </div>
    </div>
  );
}
