import { AlertTriangle } from 'lucide-react';

/**
 * Amber advisory banner for non-fatal analysis caveats carried by the
 * backend's `warnings` array (e.g. "SPF/DKIM/DMARC cannot be verified
 * without raw headers"). Renders nothing when the list is empty so
 * callers can attach it unconditionally.
 */
export default function WarningsBanner({
  warnings,
  className = '',
}: {
  warnings?: string[] | null;
  className?: string;
}) {
  if (!warnings || warnings.length === 0) return null;
  return (
    <div
      role="alert"
      className={`flex items-start gap-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 ${className}`}
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-400" />
      <div className="space-y-1">
        {warnings.map((w, i) => (
          <p key={i} className="text-xs leading-relaxed text-amber-300">
            ⚠️ {w}
          </p>
        ))}
      </div>
    </div>
  );
}
