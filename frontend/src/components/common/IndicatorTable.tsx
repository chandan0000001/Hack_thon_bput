import type { Indicator, Severity } from '../../types';
import { SEVERITY_STYLES } from './SeverityBadge';

/**
 * Verbose detection log for an analysis result: one table, rows grouped by
 * severity band (first column), with the detection, where it was found and
 * the full human-readable evidence for every signal.
 */

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'safe'];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  safe: 'SAFE',
};

// Human-readable names for the machine detection types.
const TYPE_LABELS: Record<string, string> = {
  lookalike_domain: 'Look-alike domain',
  lookalike_url: 'Look-alike URL',
  sender_domain: 'Sender domain',
  sender_invalid: 'Invalid sender',
  urgency: 'Urgency keyword',
  urgency_language: 'Urgency language',
  urgency_pressure: 'Urgency pressure',
  credential_request: 'Credential request',
  credential_path: 'Credential path',
  ip_url_in_body: 'IP-address link',
  ip_host: 'IP-address host',
  insecure_link: 'Insecure HTTP link',
  suspicious_url: 'Suspicious URL',
  suspicious_tld: 'Suspicious TLD',
  suspicious_tld_url: 'Suspicious TLD URL',
  suspicious_port: 'Suspicious port',
  financial_vocabulary: 'Financial keyword',
  threat_language: 'Threat language',
  ml_model: 'AI model verdict',
  attachment_url_flagged: 'Attachment URL flagged',
  attachment_credential_request: 'Credential phrase in attachment',
  attachment_urgency: 'Urgency phrase in attachment',
  attachment_threat_language: 'Threat language in attachment',
  attachment_financial: 'Financial keyword in attachment',
  mime_mismatch: 'Disguised file type',
  clamav_signature: 'Antivirus signature hit',
  yara_match: 'YARA rule match',
  executable_detected: 'Executable content',
  archive_bomb: 'Archive bomb',
  oversized_file: 'Oversized file',
};

function typeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type.split('_').join(' ');
}

/** Best-effort "where was this found" from the indicator's source and text. */
function foundIn(ind: Indicator, attachmentName: string | null): string {
  if (ind.source === 'attachment') return attachmentName ? `Attachment — ${attachmentName}` : 'Email attachment';
  if (ind.type === 'ml_model') return 'AI model (XGBoost)';
  const d = ind.description.toLowerCase();
  if (d.startsWith('sender') || d.includes('sender domain')) return 'Sender address';
  if (d.includes('in attachment')) return 'Email attachment';
  if (d.includes('email body') || d.includes('link in the email')) return 'Email body';
  if (d.includes('subject')) return 'Email subject';
  return 'Email content';
}

export default function IndicatorTable({
  indicators,
  attachmentName = null,
}: {
  indicators: Indicator[];
  attachmentName?: string | null;
}) {
  const groups = SEVERITY_ORDER.map((sev) => ({
    sev,
    items: indicators.filter((i) => i.severity === sev),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="rounded-xl border border-zinc-700/50 bg-zinc-800/60 backdrop-blur">
      <div className="flex items-center justify-between border-b border-zinc-700/50 px-4 py-3">
        <h3 className="text-sm font-semibold text-zinc-100">Detection Log</h3>
        <span className="text-[11px] uppercase tracking-wider text-zinc-500">
          {indicators.length} signal{indicators.length === 1 ? '' : 's'} · newest analysis
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="text-[10px] uppercase tracking-widest text-zinc-500">
              <th className="px-4 py-2.5 font-semibold">Severity</th>
              <th className="px-3 py-2.5 font-semibold">Detection</th>
              <th className="px-3 py-2.5 font-semibold">Found In</th>
              <th className="px-3 py-2.5 font-semibold">Evidence / Details</th>
            </tr>
          </thead>
          <tbody>
            {groups.length === 0 && (
              <tr className="border-t border-zinc-700/40">
                <td className="px-4 py-3">
                  <span className={`text-[11px] font-bold uppercase tracking-wider ${SEVERITY_STYLES.safe.text}`}>
                    SAFE
                  </span>
                </td>
                <td className="px-3 py-3 text-zinc-300">No threat signals</td>
                <td className="px-3 py-3 text-zinc-500">—</td>
                <td className="px-3 py-3 text-zinc-500">
                  Nothing suspicious was found in this email or its attachment.
                </td>
              </tr>
            )}
            {groups.map(({ sev, items }) =>
              items.map((ind, i) => {
                const style = SEVERITY_STYLES[sev];
                return (
                  <tr key={ind.id} className="border-t border-zinc-700/40 align-top hover:bg-zinc-700/20">
                    {i === 0 && (
                      <td
                        rowSpan={items.length}
                        className={`w-24 px-4 py-3 align-top ${style.text}`}
                      >
                        <div className="flex items-center gap-1.5">
                          <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
                          <span className="text-[11px] font-bold uppercase tracking-wider">
                            {SEVERITY_LABEL[sev]}
                          </span>
                        </div>
                        <div className="mt-0.5 text-[10px] text-zinc-500">{items.length} finding{items.length === 1 ? '' : 's'}</div>
                      </td>
                    )}
                    <td className="px-3 py-3">
                      <div className="font-medium text-zinc-100">{typeLabel(ind.type)}</div>
                      <div className="mt-0.5 font-mono text-[10px] text-zinc-500">{ind.type}</div>
                    </td>
                    <td className="px-3 py-3 text-zinc-300">{foundIn(ind, attachmentName)}</td>
                    <td className="px-3 py-3">
                      {ind.value && (
                        <span className="mb-1 block max-w-72 truncate font-mono text-[11px] text-zinc-200">
                          {ind.value}
                        </span>
                      )}
                      <span className="leading-relaxed text-zinc-400">{ind.description}</span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
