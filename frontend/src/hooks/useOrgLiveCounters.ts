import { useState, useEffect, useCallback } from 'react';
import type { OrgLiveCountersData } from '../services/orgApi';

export const INITIAL_COUNTERS: OrgLiveCountersData = {
  total_24h: 0,
  by_severity: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  },
  by_type: {
    log: 0,
    ato: 0,
    network: 0,
  },
  pending_review: 0,
  blocked_indicators_count: 0,
};

/**
 * Pure reducer for handling an INSERT event on org_events.
 */
export function applyInsertEvent(
  prev: OrgLiveCountersData,
  newEvent: { severity?: string; event_type?: string; verdict?: string }
): OrgLiveCountersData {
  const sev = (newEvent.severity || '').toLowerCase() as keyof OrgLiveCountersData['by_severity'];
  const typ = (newEvent.event_type || '').toLowerCase() as keyof OrgLiveCountersData['by_type'];
  const isPending = newEvent.verdict === 'pending_review';

  return {
    ...prev,
    total_24h: prev.total_24h + 1,
    by_severity: {
      ...prev.by_severity,
      ...(sev in prev.by_severity ? { [sev]: prev.by_severity[sev] + 1 } : {}),
    },
    by_type: {
      ...prev.by_type,
      ...(typ in prev.by_type ? { [typ]: prev.by_type[typ] + 1 } : {}),
    },
    pending_review: isPending ? prev.pending_review + 1 : prev.pending_review,
  };
}

/**
 * Pure reducer for handling an UPDATE event on org_events.
 */
export function applyUpdateEvent(
  prev: OrgLiveCountersData,
  oldEvent: { verdict?: string } | null | undefined,
  newEvent: { verdict?: string } | null | undefined
): OrgLiveCountersData {
  const wasPending = oldEvent?.verdict === 'pending_review';
  const isPending = newEvent?.verdict === 'pending_review';

  if (wasPending && !isPending) {
    return {
      ...prev,
      pending_review: Math.max(0, prev.pending_review - 1),
    };
  }

  if (!wasPending && isPending) {
    return {
      ...prev,
      pending_review: prev.pending_review + 1,
    };
  }

  return prev;
}

export interface UseOrgLiveCountersResult {
  counters: OrgLiveCountersData;
  isConnected: boolean;
  isLoading: boolean;
  error: string | null;
  resync: () => Promise<void>;
}

/**
 * Live counters hook:
 * 1. Single seed fetch on mount / project change via orgApi.getInitialCounters
 * 2. Supabase Realtime channel subscription to cyberguard.org_events (INSERT & UPDATE)
 * 3. Zero polling (no setInterval)
 */
export function useOrgLiveCounters(
  orgId: string | null,
  projectId: string | null,
  customSupabaseClient?: any,
  seedFetcher?: (orgId: string, projectId: string) => Promise<OrgLiveCountersData>
): UseOrgLiveCountersResult {
  const [counters, setCounters] = useState<OrgLiveCountersData>(INITIAL_COUNTERS);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchSeed = useCallback(async () => {
    if (!orgId || !projectId) {
      setCounters(INITIAL_COUNTERS);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      if (seedFetcher) {
        const data = await seedFetcher(orgId, projectId);
        setCounters(data);
      } else {
        const { orgApi } = await import('../services/orgApi');
        const data = await orgApi.getInitialCounters(orgId, projectId);
        setCounters(data);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch live counters');
    } finally {
      setIsLoading(false);
    }
  }, [orgId, projectId, seedFetcher]);

  // Seed on mount or when orgId/projectId changes
  useEffect(() => {
    void fetchSeed();
  }, [fetchSeed]);

  // Realtime subscription
  useEffect(() => {
    if (!orgId || !projectId) {
      setIsConnected(false);
      return;
    }

    let channel: any = null;
    let activeClient: any = null;
    let cancelled = false;

    async function setupSubscription() {
      try {
        if (customSupabaseClient) {
          activeClient = customSupabaseClient;
        } else {
          const mod = await import('../lib/supabaseClient');
          activeClient = mod.getSupabase();
        }
      } catch {
        if (!cancelled) setIsConnected(false);
        return;
      }

      if (cancelled || !activeClient || typeof activeClient.channel !== 'function') {
        if (!cancelled) setIsConnected(false);
        return;
      }

      const channelName = `org-counters-${projectId}`;
      channel = activeClient
        .channel(channelName)
        .on(
          'postgres_changes',
          {
            event: 'INSERT',
            schema: 'cyberguard',
            table: 'org_events',
            filter: `project_id=eq.${projectId}`,
          },
          (payload: any) => {
            if (payload?.new) {
              setCounters((prev) => applyInsertEvent(prev, payload.new));
            }
          }
        )
        .on(
          'postgres_changes',
          {
            event: 'UPDATE',
            schema: 'cyberguard',
            table: 'org_events',
            filter: `project_id=eq.${projectId}`,
          },
          (payload: any) => {
            setCounters((prev) => applyUpdateEvent(prev, payload?.old, payload?.new));
          }
        )
        .subscribe((status: string) => {
          if (!cancelled) {
            setIsConnected(status === 'SUBSCRIBED');
          }
        });
    }

    void setupSubscription();

    return () => {
      cancelled = true;
      setIsConnected(false);
      if (activeClient && channel && typeof activeClient.removeChannel === 'function') {
        void activeClient.removeChannel(channel);
      }
    };
  }, [orgId, projectId, customSupabaseClient]);

  return {
    counters,
    isConnected,
    isLoading,
    error,
    resync: fetchSeed,
  };
}
