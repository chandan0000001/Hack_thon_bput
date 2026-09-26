import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

import {
  appendEvents,
  EVENT_TYPE_LABELS,
  eventsQueryParams,
  VERDICT_LABELS,
  relativeTime,
} from '../pages/eventsListHelpers.ts';

const pagePath = path.resolve('src/pages/EventsListPage.tsx');
const shellPath = path.resolve('src/pages/OrgWorkspaceShell.tsx');
const appPath = path.resolve('src/App.tsx');

const page = () => fs.readFileSync(pagePath, 'utf8');

describe('ORG-DASHBOARD-P3 Test Suite (6 Checks)', () => {
  // Check 1: sidebar triad with per-route-family active states
  it('1 shell sidebar triad: Dashboard / Events / Settings, startsWith actives, settings bottom', () => {
    const shell = fs.readFileSync(shellPath, 'utf8');
    // triad order and targets
    const dashIdx = shell.indexOf('data-testid="shell-dashboard-nav"');
    const eventsIdx = shell.indexOf('data-testid="shell-events-nav"');
    const settingsIdx = shell.indexOf('data-testid="shell-settings-nav"');
    assert.ok(dashIdx !== -1 && eventsIdx !== -1 && settingsIdx !== -1, 'all three nav items exist');
    assert.ok(dashIdx < eventsIdx, 'Dashboard before Events');
    // settings stays on the bottom reference rail (after the spacer)
    assert.ok(eventsIdx < shell.indexOf('<div className="flex-1" />'));
    assert.ok(settingsIdx > shell.indexOf('<div className="flex-1" />'));
    // icons from the existing lucide set
    assert.match(shell, /<LayoutDashboard className="h-4 w-4 shrink-0" \/>/);
    assert.match(shell, /<ScrollText className="h-4 w-4 shrink-0" \/>/);
    // per-family startsWith actives; review pages fall into the events family
    assert.match(shell, /location\.pathname\.startsWith\(workspacePath\)/);
    assert.match(shell, /location\.pathname\.startsWith\(eventsPath\)/);
    assert.match(shell, /aria-current=\{dashboardActive \? 'page' : undefined\}/);
    assert.match(shell, /aria-current=\{eventsActive \? 'page' : undefined\}/);
    // routes: /events hosted in the same shell
    const app = fs.readFileSync(appPath, 'utf8');
    const eventsRoute = app.match(/path="\/org\/:orgId\/projects\/:projectId\/events"[\s\S]*?<\/Route>/)?.[0] ?? '';
    assert.match(eventsRoute, /<OrgGuard>/);
    assert.match(eventsRoute, /<EventsListPage \/>/);
  });

  // Check 2: table renders rows with type/severity/verdict badges + risk
  it('2 list renders rows: badges, risk column, relative created with absolute hover', () => {
    const src = page();
    assert.match(src, /data-testid="events-table"/);
    assert.match(src, /<SeverityBadge severity=\{e\.severity as never\} \/>/);
    assert.match(src, /\{VERDICT_CHIP_CLASSES\[e\.verdict\]/);
    assert.match(src, /\{EVENT_TYPE_LABELS\[e\.event_type\] \?\? e\.event_type\}/);
    assert.match(src, /\{e\.analysis_result\?\.risk_score \?\? '—'\}/);
    // relative text + absolute timestamp on hover
    assert.match(src, /title=\{formatLocal\(e\.created_at\)\}/);
    assert.match(src, /\{relativeTime\(e\.created_at\)\}/);
    assert.strictEqual(VERDICT_LABELS.blocked_permanently, 'Blocked');
    assert.strictEqual(EVENT_TYPE_LABELS.network_event, 'Network');
  });

  // Check 3: each filter narrows — exact server param names via query builder
  it('3 filters narrow with exact backend param names', () => {
    assert.strictEqual(eventsQueryParams({}), '?limit=50');
    assert.strictEqual(
      eventsQueryParams({ eventType: 'network_event' }),
      '?event_type=network_event&limit=50'
    );
    assert.strictEqual(
      eventsQueryParams({ severity: 'critical', verdict: 'pending_review' }),
      '?severity=critical&verdict=pending_review&limit=50'
    );
    // URLSearchParams encodes spaces as '+' (server-side equivalent to %20)
    assert.strictEqual(
      eventsQueryParams({ q: 'port 4444', limit: 25, offset: 50 }),
      '?q=port+4444&limit=25&offset=50'
    );
    const src = page();
    // selects drive the filter state with the same names
    assert.match(src, /data-testid="filter-type"/);
    assert.match(src, /data-testid="filter-severity"/);
    assert.match(src, /data-testid="filter-verdict"/);
    const api = fs.readFileSync(path.resolve('src/services/orgApi.ts'), 'utf8');
    assert.match(api, /\/orgs\/\$\{encodeURIComponent\(orgId\)\}\/projects\/\$\{encodeURIComponent\(projectId\)\}\/events\$\{params\}/);
  });

  // Check 4: search input debounced at 300ms
  it('4 search debounce: 300ms timer with cleanup; only debouncedQ reaches the query', () => {
    const src = page();
    assert.match(src, /setTimeout\(\(\) => setDebouncedQ\(filters\.q\.trim\(\)\), 300\)/);
    assert.match(src, /return \(\) => clearTimeout\(t\)/);
    // the fetch uses debouncedQ, not the raw input
    assert.match(src, /q: debouncedQ \|\| undefined/);
    assert.doesNotMatch(src, /q: filters\.q/);
    assert.match(src, /data-testid="events-search"/);
  });

  // Check 5: load-more appends the next offset page without duplicates
  it('5 load more: offset+PAGE_SIZE append, dedupe by id, N-of-M counter', () => {
    const row = (id: string) => ({
      id, event_type: 'network_event', severity: 'high', verdict: 'pending_review',
      source: 'gateway', created_at: '2026-09-26T10:00:00Z', analysis_result: { risk_score: 75 },
    });
    const first = [row('a'), row('b')];
    const nextPage = [row('b'), row('c')]; // server overlap -> no dupe
    const merged = appendEvents(first, nextPage);
    assert.deepStrictEqual(merged.map((r) => r.id), ['a', 'b', 'c']);
    const src = page();
    assert.match(src, /onClick=\{\(\) => void fetchPage\(offset \+ PAGE_SIZE, true\)\}/);
    assert.match(src, /setRows\(\(prev\) => \(append \? appendEvents\(prev, data\.events\) : data\.events\)\)/);
    assert.match(src, /const hasMore = rows\.length < total/);
    assert.match(src, /data-testid="events-count"/);
    assert.match(src, /\{Math\.min\(rows\.length, total\)\} of \{total\}/);
    assert.match(src, /data-testid="load-more"/);
  });

  // Check 6: empty state + clear filters + Review link targets
  it('6 empty state with Clear filters; Review links to the per-event review route', () => {
    const src = page();
    assert.match(src, /No events match filters/);
    assert.match(src, /data-testid="clear-filters"/);
    assert.match(src, /setFilters\(EMPTY_FILTERS\)/);
    assert.match(src, /to=\{`\/org\/\$\{orgId\}\/projects\/\$\{projectId\}\/events\/\$\{e\.id\}\/review`\}/);
    assert.match(src, /data-testid=\{`review-link-\$\{e\.id\}`\}/);
    // refresh button re-queries page 1 (dashboard owns the live feed, not this page)
    assert.match(src, /data-testid="events-refresh"/);
    assert.match(src, /onClick=\{\(\) => void fetchPage\(0, false\)\}/);
    assert.doesNotMatch(src, /postgres_changes|useOrgLiveCounters/);
  });

  // sanity: relativeTime helper
  it('relativeTime buckets', () => {
    const now = Date.now();
    assert.strictEqual(relativeTime(new Date(now - 20_000).toISOString()), 'just now');
    assert.strictEqual(relativeTime(new Date(now - 5 * 60_000).toISOString()), '5m ago');
    assert.strictEqual(relativeTime(new Date(now - 3 * 3600_000).toISOString()), '3h ago');
    assert.strictEqual(relativeTime(new Date(now - 2 * 86_400_000).toISOString()), '2d ago');
  });
});
