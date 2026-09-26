/**
 * ORG-DASHBOARD-P1 — live org_events counters.
 *
 * One-time seed fetch (GET .../counters/initial) on mount, then strictly
 * realtime deltas — never polling:
 *   - postgres_changes INSERT/UPDATE on cyberguard.org_events filtered to
 *     the project (production path; enforced by org_events_realtime_select RLS)
 *   - `org_event_changed` broadcast on the same channel — dev-transport
 *     bridge emitted by the gateway (see app/services/org_event_broadcaster)
 *     for stacks where realtime cannot read the app DB directly
 *
 * Both transports carry the same delta shape and are deduped by event id,
 * so stacks where both fire never double-count.
 *
 * Structure mirrors useRealtimeEmails: a plain (non-React) controller that
 * the node:test suite drives with injected mocks, plus a thin React hook.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type { OrgCounters } from '../services/orgApi';

export const BROADCAST_EVENT = 'org_event_changed';

export interface CounterDelta {
  kind: 'insert' | 'update';
  event_id: string;
  event_type: string; // log_event | ato_event | network_event
  severity: string; // critical | high | medium | low
  verdict: string;
  previous_verdict?: string | null;
}

const TYPE_KEYS: Record<string, keyof OrgCounters['by_type']> = {
  log_event: 'log',
  ato_event: 'ato',
  network_event: 'network',
};

const SEVERITY_KEYS: Record<string, keyof OrgCounters['by_severity']> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
};

/** Pure reducer: apply one realtime delta to the seeded counters. */
export function applyCounterDelta(counters: OrgCounters, delta: CounterDelta): OrgCounters {
  const next: OrgCounters = {
    total_24h: counters.total_24h,
    by_severity: { ...counters.by_severity },
    by_type: { ...counters.by_type },
    pending_review: counters.pending_review,
    blocked_indicators_count: counters.blocked_indicators_count,
  };

  if (delta.kind === 'insert') {
    next.total_24h += 1;
    const sev = SEVERITY_KEYS[delta.severity];
    if (sev) next.by_severity[sev] += 1;
    const type = TYPE_KEYS[delta.event_type];
    if (type) next.by_type[type] += 1;
    if (delta.verdict === 'pending_review') next.pending_review += 1;
    return next;
  }

  // update: verdict transitions only affect the pending_review backlog
  const wasPending = delta.previous_verdict === 'pending_review';
  const isPending = delta.verdict === 'pending_review';
  if (wasPending && !isPending && next.pending_review > 0) next.pending_review -= 1;
  if (!wasPending && isPending) next.pending_review += 1;
  return next;
}

/** Dedup key so postgres_changes + broadcast delivery count each change once. */
export function deltaKey(delta: CounterDelta): string {
  if (delta.kind === 'insert') return `i:${delta.event_id}`;
  return `u:${delta.event_id}:${delta.previous_verdict ?? ''}->${delta.verdict}`;
}

export interface OrgLiveCountersController {
  seed: () => Promise<void>;
  resync: () => Promise<void>;
  dispose: () => void;
  getCounters: () => OrgCounters | null;
  isConnected: () => boolean;
  onCounters: (cb: (c: OrgCounters | null) => void) => void;
  onConnection: (cb: (connected: boolean) => void) => void;
}

export interface CreateControllerOptions {
  projectId: string;
  fetchInitial: () => Promise<OrgCounters>;
  supabaseClient?: any; // DI for tests; browser resolves lazily in the hook
}

export function createOrgLiveCountersController(
  options: CreateControllerOptions
): OrgLiveCountersController {
  const { projectId, fetchInitial, supabaseClient } = options;

  let counters: OrgCounters | null = null;
  let connected = false;
  let channel: any = null;
  const seen = new Set<string>(); // capped dedup of applied deltas
  let pending: CounterDelta[] = []; // deltas that arrived before the seed resolved
  const countersCbs = new Set<(c: OrgCounters | null) => void>();
  const connectionCbs = new Set<(ok: boolean) => void>();

  const emitCounters = () => countersCbs.forEach((cb) => cb(counters));
  const emitConnection = () => connectionCbs.forEach((cb) => cb(connected));

  const remember = (key: string) => {
    seen.add(key);
    if (seen.size > 1000) {
      const first = seen.values().next().value;
      if (first !== undefined) seen.delete(first);
    }
  };

  const applyDelta = (delta: CounterDelta) => {
    const key = deltaKey(delta);
    if (seen.has(key)) return;
    remember(key);
    if (counters) {
      counters = applyCounterDelta(counters, delta);
      emitCounters();
    } else if (pending.length < 500) {
      pending.push(delta); // arrived pre-seed; replayed once the seed lands
    }
  };

  const fromPgInsert = (payload: any): CounterDelta => {
    const row = payload?.new ?? {};
    return {
      kind: 'insert',
      event_id: String(row.id ?? ''),
      event_type: String(row.event_type ?? ''),
      severity: String(row.severity ?? ''),
      verdict: String(row.verdict ?? ''),
    };
  };

  const fromPgUpdate = (payload: any): CounterDelta => {
    const row = payload?.new ?? {};
    const old = payload?.old ?? {};
    return {
      kind: 'update',
      event_id: String(row.id ?? ''),
      event_type: String(row.event_type ?? ''),
      severity: String(row.severity ?? ''),
      verdict: String(row.verdict ?? ''),
      previous_verdict: old.verdict != null ? String(old.verdict) : null,
    };
  };

  const fromBroadcast = (payload: any): CounterDelta => ({
    kind: payload?.kind === 'update' ? 'update' : 'insert',
    event_id: String(payload?.event_id ?? ''),
    event_type: String(payload?.event_type ?? ''),
    severity: String(payload?.severity ?? ''),
    verdict: String(payload?.verdict ?? ''),
    previous_verdict: payload?.previous_verdict ?? null,
  });

  const controller: OrgLiveCountersController = {
    async seed() {
      try {
        counters = await fetchInitial();
        const buffered = pending;
        pending = [];
        for (const delta of buffered) {
          counters = applyCounterDelta(counters!, delta);
        }
        emitCounters();
      } catch {
        // seed failure keeps counters null; the UI offers a manual resync
      }
    },
    async resync() {
      await controller.seed();
    },
    dispose() {
      connected = false;
      emitConnection();
      try {
        if (supabaseClient && channel) void supabaseClient.removeChannel(channel);
      } catch {
        // clean unmount
      }
      channel = null;
    },
    getCounters: () => counters,
    isConnected: () => connected,
    onCounters(cb) {
      countersCbs.add(cb);
    },
    onConnection(cb) {
      connectionCbs.add(cb);
    },
  };

  if (supabaseClient) {
    channel = supabaseClient
      .channel(`org-counters-${projectId}`)
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'org_events', filter: `project_id=eq.${projectId}` },
        (payload: any) => applyDelta(fromPgInsert(payload))
      )
      .on(
        'postgres_changes',
        { event: 'UPDATE', schema: 'public', table: 'org_events', filter: `project_id=eq.${projectId}` },
        (payload: any) => applyDelta(fromPgUpdate(payload))
      )
      .on('broadcast', { event: BROADCAST_EVENT }, (msg: any) => applyDelta(fromBroadcast(msg?.payload)))
      .subscribe((status: string) => {
        connected = status === 'SUBSCRIBED';
        emitConnection();
      });
  }

  return controller;
}

export interface UseOrgLiveCountersReturn {
  counters: OrgCounters | null;
  isConnected: boolean;
  resync: () => void;
}

/**
 * React binding. One-time seed fetch on mount + realtime deltas; `resync`
 * is the ONLY re-seed path (user-initiated button — never automatic).
 */
export function useOrgLiveCounters(
  orgId: string | undefined,
  projectId: string | undefined
): UseOrgLiveCountersReturn {
  const [counters, setCounters] = useState<OrgCounters | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const clientRef = useRef<any>(null);
  const [clientReady, setClientReady] = useState(false);

  useEffect(() => {
    // Resolve Supabase lazily so the Node test runner never touches it.
    let cancelled = false;
    import('../lib/supabaseClient')
      .then((mod) => {
        if (cancelled) return;
        try {
          clientRef.current = mod.getSupabase();
        } catch {
          clientRef.current = null;
        }
        setClientReady(true);
      })
      .catch(() => {
        clientRef.current = null;
        setClientReady(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!clientReady || !projectId || !orgId) return;
    let disposed = false;
    let controller: OrgLiveCountersController | null = null;

    (async () => {
      const { orgApi } = await import('../services/orgApi');
      if (disposed) return;
      controller = createOrgLiveCountersController({
        projectId,
        fetchInitial: () => orgApi.getInitialCounters(orgId, projectId),
        supabaseClient: clientRef.current,
      });
      controller.onCounters(setCounters);
      controller.onConnection(setIsConnected);
      await controller.seed();
    })();

    return () => {
      disposed = true;
      controller?.dispose();
    };
  }, [clientReady, orgId, projectId]);

  const resync = useCallback(() => {
    void (async () => {
      if (!orgId || !projectId) return;
      const { orgApi } = await import('../services/orgApi');
      try {
        setCounters(await orgApi.getInitialCounters(orgId, projectId));
      } catch {
        // keep last known counters on resync failure
      }
    })();
  }, [orgId, projectId]);

  return { counters, isConnected, resync };
}
