import { useEffect, useRef, useState } from 'react';
import { create } from 'zustand';

export interface EmailAnalyzedPayload {
  processed_email_id: string;
  risk_score: number;
  classification: string;
  scan_result_id: string | null;
  owner_user_id: string;
  subject?: string;
  sender?: string;
  severity?: string;
  threat_type?: string;
  signals?: Record<string, any>;
  analyzed_at?: string;
}

export function shouldAutoScrollToTop(
  event: { severity?: string; risk_score?: number },
  scrollY: number,
): boolean {
  const isCritical =
    event.severity === 'critical' ||
    (typeof event.risk_score === 'number' && event.risk_score >= 0.85);
  return Boolean(isCritical && scrollY < 120);
}

export function getQuarantineStatusChip(item: {
  scan_result?: any | null;
  severity?: string;
}): {
  isAnalyzing: boolean;
  label: string;
} {
  if (!item.scan_result) {
    return { isAnalyzing: true, label: 'Analyzing...' };
  }
  return { isAnalyzing: false, label: item.severity || 'safe' };
}

interface RealtimeEmailStore {
  liveCount: number;
  lastEvent: EmailAnalyzedPayload | null;
  seenIds: Set<string>;
  recordEvent: (event: EmailAnalyzedPayload) => boolean;
  resetLiveCount: () => void;
  clearHistory: () => void;
}

export const useRealtimeEmailStore = create<RealtimeEmailStore>((set, get) => ({
  liveCount: 0,
  lastEvent: null,
  seenIds: new Set<string>(),

  recordEvent: (event: EmailAnalyzedPayload) => {
    const { seenIds, liveCount } = get();
    if (seenIds.has(event.processed_email_id)) {
      return false; // Deduplicated
    }
    const nextSeen = new Set(seenIds);
    nextSeen.add(event.processed_email_id);
    set({
      seenIds: nextSeen,
      liveCount: liveCount + 1,
      lastEvent: event,
    });
    return true;
  },

  resetLiveCount: () => set({ liveCount: 0 }),

  clearHistory: () => set({ seenIds: new Set(), liveCount: 0, lastEvent: null }),
}));

export interface SubscriptionStatus {
  isConnected: boolean;
  isPolling: boolean;
}

export interface RealtimeSubscriptionOptions {
  userId?: string;
  supabaseClient?: any;
  fallbackTimeoutMs?: number;
  pollingIntervalMs?: number;
  onEvent?: (event: EmailAnalyzedPayload) => void;
  onRefresh?: () => Promise<void> | void;
  onStatusChange?: (status: SubscriptionStatus) => void;
}

export interface RealtimeSubscription {
  channelName: string;
  isConnected: () => boolean;
  isPolling: () => boolean;
  unsubscribe: () => void;
}

/**
 * Encapsulates the Supabase Realtime channel subscription lifecycle,
 * 5-second graceful degradation timeout, and 60-second polling fallback.
 */
export function createEmailRealtimeSubscription(
  options: RealtimeSubscriptionOptions,
): RealtimeSubscription {
  const {
    userId = 'default',
    supabaseClient,
    fallbackTimeoutMs = 5000,
    pollingIntervalMs = 60000,
    onEvent,
    onRefresh,
    onStatusChange,
  } = options;

  let connected = false;
  let polling = false;
  let pollInterval: ReturnType<typeof setInterval> | null = null;
  let timeoutTimer: ReturnType<typeof setTimeout> | null = null;
  let channel: any = null;

  const updateStatus = (newConnected: boolean, newPolling: boolean) => {
    connected = newConnected;
    polling = newPolling;
    onStatusChange?.({ isConnected: connected, isPolling: polling });
  };

  const startPolling = () => {
    updateStatus(false, true);
    if (!pollInterval) {
      pollInterval = setInterval(() => {
        void onRefresh?.();
      }, pollingIntervalMs);
    }
  };

  const stopPolling = () => {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  };

  if (!supabaseClient) {
    // If no client provided, immediately enter polling fallback without error
    startPolling();
    return {
      channelName: `user:${userId}`,
      isConnected: () => connected,
      isPolling: () => polling,
      unsubscribe: () => stopPolling(),
    };
  }

  const channelName = `user:${userId}`;

  // 5-second graceful degradation timer
  timeoutTimer = setTimeout(() => {
    if (!connected) {
      startPolling();
    }
  }, fallbackTimeoutMs);

  try {
    channel = supabaseClient
      .channel(channelName)
      .on('broadcast', { event: 'email_analyzed' }, (msg: any) => {
        const payload = (msg?.payload || msg) as EmailAnalyzedPayload;
        if (payload && payload.processed_email_id) {
          const isNew = useRealtimeEmailStore.getState().recordEvent(payload);
          if (isNew) {
            onEvent?.(payload);
            void onRefresh?.();
          }
        }
      })
      .subscribe((status: string) => {
        if (status === 'SUBSCRIBED') {
          if (timeoutTimer) clearTimeout(timeoutTimer);
          stopPolling();
          updateStatus(true, false);
        } else if (
          status === 'CHANNEL_ERROR' ||
          status === 'TIMED_OUT' ||
          status === 'CLOSED'
        ) {
          startPolling();
        }
      });
  } catch {
    startPolling();
  }

  return {
    channelName,
    isConnected: () => connected,
    isPolling: () => polling,
    unsubscribe: () => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      stopPolling();
      updateStatus(false, false);
      try {
        if (supabaseClient && channel) {
          void supabaseClient.removeChannel(channel);
        }
      } catch {
        // clean unmount
      }
    },
  };
}

export interface UseRealtimeEmailsOptions {
  userId?: string;
  supabaseClient?: any;
  onEvent?: (event: EmailAnalyzedPayload) => void;
  onRefresh?: () => Promise<void> | void;
  enabled?: boolean;
  fallbackTimeoutMs?: number;
  pollingIntervalMs?: number;
}

export interface UseRealtimeEmailsReturn {
  lastEvent: EmailAnalyzedPayload | null;
  liveCount: number;
  isConnected: boolean;
  isPolling: boolean;
  resetLiveCount: () => void;
}

export function useRealtimeEmails(options: UseRealtimeEmailsOptions = {}): UseRealtimeEmailsReturn {
  const {
    userId: propUserId,
    supabaseClient: propClient,
    onEvent,
    onRefresh,
    enabled = true,
    fallbackTimeoutMs = 5000,
    pollingIntervalMs = 60000,
  } = options;

  const [activeClient, setActiveClient] = useState<any>(propClient || null);
  const [activeUserId, setActiveUserId] = useState<string | undefined>(propUserId);

  useEffect(() => {
    if (propClient) {
      setActiveClient(propClient);
      return;
    }
    // Dynamically resolve Supabase in browser runtime without polluting Node test runner
    import('../lib/supabaseClient')
      .then((mod) => {
        try {
          setActiveClient(mod.getSupabase());
        } catch {
          setActiveClient(null);
        }
      })
      .catch(() => {
        setActiveClient(null);
      });
  }, [propClient]);

  useEffect(() => {
    if (propUserId) {
      setActiveUserId(propUserId);
      return;
    }
    import('../store/authStore')
      .then((mod) => {
        setActiveUserId(mod.useAuthStore.getState().user?.id);
      })
      .catch(() => {});
  }, [propUserId]);

  const liveCount = useRealtimeEmailStore((s) => s.liveCount);
  const lastEvent = useRealtimeEmailStore((s) => s.lastEvent);
  const resetLiveCount = useRealtimeEmailStore((s) => s.resetLiveCount);

  const [isConnected, setIsConnected] = useState(false);
  const [isPolling, setIsPolling] = useState(false);

  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  const onRefreshRef = useRef(onRefresh);
  onRefreshRef.current = onRefresh;

  useEffect(() => {
    if (!enabled) {
      setIsConnected(false);
      setIsPolling(false);
      return;
    }

    const sub = createEmailRealtimeSubscription({
      userId: activeUserId,
      supabaseClient: activeClient,
      fallbackTimeoutMs,
      pollingIntervalMs,
      onEvent: (payload) => {
        onEventRef.current?.(payload);
      },
      onRefresh: () => {
        void onRefreshRef.current?.();
      },
      onStatusChange: (status) => {
        setIsConnected(status.isConnected);
        setIsPolling(status.isPolling);
      },
    });

    return () => {
      sub.unsubscribe();
    };
  }, [enabled, activeUserId, activeClient, fallbackTimeoutMs, pollingIntervalMs]);

  return {
    lastEvent,
    liveCount,
    isConnected,
    isPolling,
    resetLiveCount,
  };
}
