import { useEffect, useRef } from 'react';
import { getSupabase } from '../lib/supabaseClient';

/**
 * Subscribe to Supabase Realtime ``postgres_changes`` for one org-scoped
 * table (migration 0009 publishes cyberguard.org_log_events + cyberguard.alerts;
 * migration 0021 adds cyberguard.events).
 *
 * Calls ``onChange`` whenever an INSERT/UPDATE/DELETE for the organization
 * arrives. When Supabase is not configured (local dev without
 * keys) this is a silent no-op and the caller should fall back to re-fetching
 * on an interval.
 *
 * ``onStatus`` (ORG-LIVE-VIEWS) reports the subscription state so live-view
 * surfaces can render a LIVE vs POLLING pill: true once the channel reports
 * SUBSCRIBED, false on CHANNEL_ERROR/TIMED_OUT/ CLOSED or when realtime is
 * unavailable entirely.
 */
export function useOrgRealtime(
  table: 'alerts' | 'org_log_events',
  orgId: string | undefined,
  onChange: () => void,
  onStatus?: (connected: boolean) => void,
): void {
  const cbRef = useRef(onChange);
  cbRef.current = onChange;
  const statusRef = useRef(onStatus);
  statusRef.current = onStatus;

  useEffect(() => {
    if (!orgId) return;
    let supabase: ReturnType<typeof getSupabase> | null = null;
    try {
      supabase = getSupabase();
    } catch {
      statusRef.current?.(false); // realtime unavailable — polling fallback
      return;
    }

    const channelName = `org-${orgId}-${table}`;
    const channel = supabase
      .channel(channelName)
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'cyberguard',
          table,
          filter: `organization_id=eq.${orgId}`,
        },
        () => cbRef.current(),
      )
      .subscribe((status) => {
        statusRef.current?.(status === 'SUBSCRIBED');
      });

    return () => {
      supabase?.removeChannel(channel);
    };
  }, [table, orgId]);
}
