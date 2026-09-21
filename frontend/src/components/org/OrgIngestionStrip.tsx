import { useCallback, useEffect, useState } from 'react';
import * as orgApi from '../../services/orgApi';

function formatAge(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const diffSec = Math.round((Date.now() - t) / 1000);
  if (diffSec < 45) return 'just now';
  if (diffSec < 3600) return `${Math.round(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.round(diffSec / 3600)}h ago`;
  return `${Math.round(diffSec / 86400)}d ago`;
}

/**
 * ORG-LIVE-VIEWS: ingestion health strip — "the system is monitoring".
 * Reads the summary's `ingestion` block (gateway recency + 24h volume,
 * connector fleet status, pipeline sync recency) on mount and every 30 s.
 */
export default function OrgIngestionStrip({
  orgId,
  projectId,
}: {
  orgId: string;
  projectId: string | null;
}) {
  const [ing, setIng] = useState<orgApi.IngestionStatus | null>(null);

  const load = useCallback(async () => {
    try {
      const summary = await orgApi.getDashboardSummary(orgId, projectId);
      setIng(summary.ingestion ?? null);
    } catch {
      // monitoring strip is informational — never surface an error toast
    }
  }, [orgId, projectId]);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const connected = ing?.connectors_connected ?? 0;
  const total = ing?.connectors_total ?? 0;

  return (
    <div
      className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-zinc-800 bg-zinc-900/70 px-3.5 py-2 font-mono text-[11px] text-zinc-400"
      title="Live ingestion health: project gateway, mail connectors, realtime pipeline"
    >
      <span className="flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
        <span className="uppercase tracking-wider text-zinc-500">Monitoring</span>
      </span>
      <span>
        Gateway last event: <span className="text-zinc-200">{formatAge(ing?.gateway_last_event_ts)}</span>
      </span>
      <span>
        Gateway 24h: <span className="text-zinc-200">{ing?.gateway_event_count_24h ?? '—'}</span>
      </span>
      <span>
        Connectors:{' '}
        <span className={total > 0 && connected < total ? 'text-amber-300' : 'text-zinc-200'}>
          {connected}/{total}
        </span>{' '}
        connected
      </span>
      <span>
        Pipeline last sync: <span className="text-zinc-200">{formatAge(ing?.pipeline_last_sync_ts)}</span>
      </span>
    </div>
  );
}
