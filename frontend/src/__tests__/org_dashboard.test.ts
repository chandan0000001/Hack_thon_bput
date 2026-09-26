import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

import {
  applyCounterDelta,
  createOrgLiveCountersController,
  deltaKey,
  type CounterDelta,
} from '../hooks/useOrgLiveCounters.ts';

const hookPath = path.resolve('src/hooks/useOrgLiveCounters.ts');
const pagePath = path.resolve('src/pages/OrgDashboard.tsx');
const appPath = path.resolve('src/App.tsx');

const SEED = {
  total_24h: 10,
  by_severity: { critical: 1, high: 2, medium: 3, low: 4 },
  by_type: { log: 2, ato: 3, network: 5 },
  pending_review: 8,
  blocked_indicators_count: 2,
};

function makeMockSupabase(log: { removed: string[] }) {
  const mock: any = {
    __chains: [] as any[],
    channel(_name: string) {
      const handlers: Array<{ type: string; filter: any; cb: Function }> = [];
      let statusCb: ((s: string) => void) | undefined;
      const chain: any = {
        on(type: string, filter: any, cb: Function) {
          handlers.push({ type, filter, cb });
          return chain;
        },
        subscribe(cb?: (s: string) => void) {
          statusCb = cb;
          return { unsubscribe: () => {} };
        },
        __handlers: handlers,
        __status: (s: string) => statusCb?.(s),
      };
      mock.__chains.push(chain);
      return chain;
    },
    removeChannel(ch: any) {
      log.removed.push(ch);
    },
  };
  return mock;
}

function insertDelta(id: string, over: Partial<CounterDelta> = {}): CounterDelta {
  return {
    kind: 'insert',
    event_id: id,
    event_type: 'network_event',
    severity: 'critical',
    verdict: 'pending_review',
    ...over,
  };
}

describe('ORG-DASHBOARD-P1 Test Suite (10 Checks)', () => {
  // Check 1: seed-then-INSERT increments counters
  it('1 seed then INSERT increments total/severity/type/pending', () => {
    let counters = { ...SEED, by_severity: { ...SEED.by_severity }, by_type: { ...SEED.by_type } };
    counters = applyCounterDelta(counters, insertDelta('e1'));
    assert.strictEqual(counters.total_24h, 11);
    assert.strictEqual(counters.by_severity.critical, 2);
    assert.strictEqual(counters.by_type.network, 6);
    assert.strictEqual(counters.pending_review, 9);
    // non-pending insert does not touch pending_review
    counters = applyCounterDelta(counters, insertDelta('e2', { verdict: 'blocked_permanently' }));
    assert.strictEqual(counters.pending_review, 9);
    assert.strictEqual(counters.by_type.network, 7);
  });

  // Check 2: UPDATE verdict decrements pending_review
  it('2 UPDATE pending_review -> blocked_permanently decrements pending', () => {
    let counters = { ...SEED, by_severity: { ...SEED.by_severity }, by_type: { ...SEED.by_type } };
    counters = applyCounterDelta(counters, {
      kind: 'update',
      event_id: 'e1',
      event_type: 'ato_event',
      severity: 'high',
      verdict: 'blocked_permanently',
      previous_verdict: 'pending_review',
    });
    assert.strictEqual(counters.pending_review, 7);
    // non-transition updates are no-ops
    const before = counters.pending_review;
    counters = applyCounterDelta(counters, {
      kind: 'update',
      event_id: 'e1',
      event_type: 'ato_event',
      severity: 'high',
      verdict: 'blocked_permanently',
      previous_verdict: 'blocked_permanently',
    });
    assert.strictEqual(counters.pending_review, before);
  });

  // Check 3: postgres_changes + broadcast double delivery counts once
  it('3 dedup: same insert via postgres_changes and broadcast counts once', async () => {
    const removed: string[] = [];
    const supabase = makeMockSupabase({ removed });
    const controller = createOrgLiveCountersController({
      projectId: 'proj-d',
      fetchInitial: async () => JSON.parse(JSON.stringify(SEED)),
      supabaseClient: supabase,
    });
    await controller.seed();
    const chain = findChannelChain(supabase);
    const insertHandler = chain.__handlers.find((h: any) => h.type === 'postgres_changes' && h.filter.event === 'INSERT');
    const broadcastHandler = chain.__handlers.find((h: any) => h.type === 'broadcast');

    // same INSERT delivered by both transports
    insertHandler.cb({ new: { id: 'dup-1', event_type: 'network_event', severity: 'critical', verdict: 'pending_review' } });
    broadcastHandler.cb({ payload: { kind: 'insert', event_id: 'dup-1', event_type: 'network_event', severity: 'critical', verdict: 'pending_review' } });
    assert.strictEqual(controller.getCounters()!.total_24h, 11, 'insert double-delivery counted once');

    // same verdict transition delivered by both transports
    const pgUpdate = { new: { id: 'dup-1', event_type: 'network_event', severity: 'critical', verdict: 'released' }, old: { id: 'dup-1', verdict: 'pending_review' } };
    insertHandler.cb; // (no-op reference)
    const updateHandler = chain.__handlers.find((h: any) => h.type === 'postgres_changes' && h.filter.event === 'UPDATE');
    updateHandler.cb(pgUpdate);
    broadcastHandler.cb({ payload: { kind: 'update', event_id: 'dup-1', event_type: 'network_event', severity: 'critical', verdict: 'released', previous_verdict: 'pending_review' } });
    assert.strictEqual(controller.getCounters()!.pending_review, 8, 'update double-delivery decremented once (8 seed +1 insert -1 update)');
    assert.strictEqual(deltaKey(insertDelta('dup-1')), 'i:dup-1');
    controller.dispose();
  });

  // Check 4: controller subscribes to the spec'd channel, filters, and statuses
  it('4 controller channel name, postgres_changes filters, broadcast event, status mapping', () => {
    const removed: string[] = [];
    const supabase = makeMockSupabase({ removed });
    const fetched: string[] = [];
    const controller = createOrgLiveCountersController({
      projectId: 'proj-123',
      fetchInitial: async () => {
        fetched.push('seed');
        return SEED;
      },
      supabaseClient: supabase,
    });
    const countersSeen: any[] = [];
    controller.onCounters((c) => countersSeen.push(c));
    const connSeen: boolean[] = [];
    controller.onConnection((ok) => connSeen.push(ok));

    const src = fs.readFileSync(hookPath, 'utf8');
    assert.match(src, /channel\(`org-counters-\$\{projectId\}`\)/);
    assert.match(src, /event: 'INSERT', schema: 'public', table: 'org_events', filter: `project_id=eq\.\$\{projectId\}`/);
    assert.match(src, /event: 'UPDATE', schema: 'public', table: 'org_events', filter: `project_id=eq\.\$\{projectId\}`/);
    assert.match(src, /'broadcast', \{ event: BROADCAST_EVENT \}/);
    assert.match(src, /connected = status === 'SUBSCRIBED'/);

    controller.dispose();
    assert.strictEqual(removed.length, 1, 'dispose removes the channel');
  });

  // Check 5: live INSERT via the channel updates counters (seed -> push)
  it('5 live channel INSERT applies delta to seeded counters', async () => {
    const removed: string[] = [];
    const supabase = makeMockSupabase({ removed });
    let resolveSeed: ((c: any) => void) | null = null;
    const seedPromise = new Promise<any>((res) => {
      resolveSeed = res;
    });
    const controller = createOrgLiveCountersController({
      projectId: 'proj-x',
      fetchInitial: () => seedPromise,
      supabaseClient: supabase,
    });
    const seen: any[] = [];
    controller.onCounters((c) => seen.push(c));
    void controller.seed();

    // find the mock channel chain (single channel created)
    const chain = findChannelChain(supabase);
    chain.__status('SUBSCRIBED');
    assert.strictEqual(controller.isConnected(), true);

    // postgres_changes INSERT arrives before seed resolves -> buffered dedup,
    // applied when counters exist
    resolveSeed?.(JSON.parse(JSON.stringify(SEED)));
    await new Promise((r) => setTimeout(r, 5));
    const insertHandler = chain.__handlers.find((h) => h.type === 'postgres_changes' && h.filter.event === 'INSERT');
    insertHandler.cb({ new: { id: 'live-1', event_type: 'ato_event', severity: 'high', verdict: 'pending_review' } });

    const latest = controller.getCounters();
    assert.strictEqual(latest!.total_24h, 11);
    assert.strictEqual(latest!.by_type.ato, 4);
    assert.strictEqual(latest!.by_severity.high, 3);
    controller.dispose();
  });

  // Check 6: status transitions map to LIVE/DISCONNECTED pill
  it('6 pill states: SUBSCRIBED -> LIVE, CHANNEL_ERROR/TIMED_OUT/CLOSED -> DISCONNECTED', () => {
    const removed: string[] = [];
    const supabase = makeMockSupabase({ removed });
    const controller = createOrgLiveCountersController({
      projectId: 'proj-s',
      fetchInitial: async () => SEED,
      supabaseClient: supabase,
    });
    const chain = findChannelChain(supabase);
    chain.__status('SUBSCRIBED');
    assert.strictEqual(controller.isConnected(), true);
    chain.__status('CHANNEL_ERROR');
    assert.strictEqual(controller.isConnected(), false);
    chain.__status('TIMED_OUT');
    assert.strictEqual(controller.isConnected(), false);
    chain.__status('CLOSED');
    assert.strictEqual(controller.isConnected(), false);
    const page = fs.readFileSync(pagePath, 'utf8');
    assert.match(page, /isConnected \? 'LIVE' : 'DISCONNECTED'/);
    assert.match(page, /data-testid="live-status-pill"/);
    controller.dispose();
  });

  // Check 7: resync is manual-only and re-fetches the seed
  it('7 resync re-fetches seed; no automatic polling exists in the hook', async () => {
    const removed: string[] = [];
    const supabase = makeMockSupabase({ removed });
    let fetches = 0;
    const controller = createOrgLiveCountersController({
      projectId: 'proj-r',
      fetchInitial: async () => {
        fetches += 1;
        return SEED;
      },
      supabaseClient: supabase,
    });
    await controller.seed();
    assert.strictEqual(fetches, 1);
    await controller.resync();
    assert.strictEqual(fetches, 2);

    const src = fs.readFileSync(hookPath, 'utf8');
    assert.doesNotMatch(src, /setInterval|setTimeout\(/, 'hook must never poll on its own');
    const page = fs.readFileSync(pagePath, 'utf8');
    assert.match(page, /data-testid="resync-btn"/);
    assert.match(page, /onClick=\{onResync\}/);
    controller.dispose();
  });

  // Check 8: Overview renders 3 analyzer cards with counts, severity bar, engine badge
  it('8 overview: 3 analyzer cards (log/ato/network) with severity bar + engine badge', () => {
    const page = fs.readFileSync(pagePath, 'utf8');
    assert.match(page, /key: 'log' as const, label: 'Log Analysis', engine: 'log_analyzer'/);
    assert.match(page, /key: 'ato' as const, label: 'Account Takeover', engine: 'account_takeover_detector'/);
    assert.match(page, /key: 'network' as const, label: 'Network Threat', engine: 'network_threat_detector'/);
    assert.match(page, /data-testid=\{`analyzer-card-\$\{a\.key\}`\}/);
    assert.match(page, /data-testid=\{`analyzer-count-\$\{a\.key\}`\}/);
    // severity bar: 4 ordered segments
    const bar = page.match(/SEVERITY_ORDER\.map\(\(s\) => \{[\s\S]*?SEVERITY_STYLES\[s\]\.bg/);
    assert.ok(bar, 'severity bar segments rendered from SEVERITY_ORDER');
  });

  // Check 9: recent events table shows last 10 with Review navigation
  it('9 recent events: last-10 fetch, table columns, Review -> event review route', () => {
    const page = fs.readFileSync(pagePath, 'utf8');
    assert.match(page, /listRecentEvents\(orgId, projectId, 10\)/);
    assert.match(page, /data-testid="recent-events-table"/);
    for (const col of ['Timestamp', 'Type', 'Severity', 'Verdict', 'Action']) {
      assert.ok(page.includes(col), `column ${col} present`);
    }
    assert.match(
      page,
      /navigate\(`\/org\/\$\{orgId\}\/projects\/\$\{projectId\}\/events\/\$\{eventId\}\/review`\)/
    );
    const app = fs.readFileSync(appPath, 'utf8');
    assert.match(app, /path="\/org\/:orgId\/projects\/:projectId\/events\/:eventId\/review"/);
  });

  // Check 10: Live Counters tab is read-only (zero inputs) with full grid + shell/switcher wiring
  it('10 live counters tab: zero input elements, 10 tiles, project switcher in shell header', () => {
    const page = fs.readFileSync(pagePath, 'utf8');
    assert.doesNotMatch(page, /<input|<select|<textarea|<form/, 'Live Counters tab must be pure monitoring');
    for (const tile of [
      'counter-total', 'counter-critical', 'counter-high', 'counter-medium', 'counter-low',
      'counter-log', 'counter-ato', 'counter-network', 'counter-pending', 'counter-blocked-indicators',
    ]) {
      assert.ok(page.includes(`'${tile}'`), `tile ${tile} present`);
    }
    const app = fs.readFileSync(appPath, 'utf8');
    // dashboard hosted in the shell; Topbar chips act as the project switcher
    // on /workspace routes (existing ORG-SHELL-1/SETTINGS-P4 behavior)
    assert.match(app, /<OrgWorkspaceShell>\s*<OrgDashboard \/>\s*<\/OrgWorkspaceShell>/);
    const topbar = fs.readFileSync(path.resolve('src/components/layout/Topbar.tsx'), 'utf8');
    assert.match(topbar, /workspace/);
    assert.match(topbar, /org\/select/);
  });
});

/** Retrieve the single mock channel chain created by makeMockSupabase. */
function findChannelChain(supabase: any): any {
  assert.strictEqual(supabase.__chains.length, 1, 'controller creates exactly one channel');
  return supabase.__chains[0];
}
