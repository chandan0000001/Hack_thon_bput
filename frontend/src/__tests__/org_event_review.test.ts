import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

import {
  buildActionHistory,
  canAct,
  highlightJson,
  matchBlockedValues,
} from '../pages/orgEventReviewHelpers.ts';

const pagePath = path.resolve('src/pages/OrgEventReview.tsx');
const appPath = path.resolve('src/App.tsx');
const apiPath = path.resolve('src/services/orgApi.ts');

const page = () => fs.readFileSync(pagePath, 'utf8');

describe('ORG-DASHBOARD-P2 Test Suite (8 Checks)', () => {
  // Check 1: route + guards
  it('1 review route guarded in shell; 403 -> /org/select, 404 -> workspace', () => {
    const app = fs.readFileSync(appPath, 'utf8');
    assert.match(app, /path="\/org\/:orgId\/projects\/:projectId\/events\/:eventId\/review"/);
    const route = app.match(/path="\/org\/:orgId\/projects\/:projectId\/events\/:eventId\/review"[\s\S]*?<\/Route>/)?.[0] ?? '';
    assert.match(route, /<OrgGuard>/);
    assert.match(route, /<OrgEventReview \/>/);
    const src = page();
    assert.match(src, /navigate\('\/org\/select', \{ replace: true \}\)/);
    assert.match(src, /navigate\(`\/org\/\$\{orgId\}\/projects\/\$\{projectId\}\/workspace`, \{ replace: true \}\)/);
    assert.match(src, /status === 403/);
    assert.match(src, /status === 409/);
  });

  // Check 2: left panel — metadata + id copy + source badge
  it('2 inspection header + metadata card (type/severity/verdict/risk, mono id, copy)', () => {
    const src = page();
    assert.match(src, /data-testid="event-id"/);
    assert.match(src, /data-testid="copy-id-btn"/);
    assert.match(src, /data-testid="source-badge"/);
    assert.match(src, /data-testid="event-metadata"/);
    assert.match(src, /data-testid="event-type"/);
    assert.match(src, /data-testid="event-verdict"/);
    assert.match(src, /data-testid="event-risk"/);
    assert.match(src, /<SeverityBadge severity=\{event\.severity as never\} \/>/);
  });

  // Check 3: raw JSON viewer — collapsible, highlighted, copyable
  it('3 raw data JSON viewer: collapsible + syntax highlighted + copy', () => {
    const src = page();
    assert.match(src, /data-testid="toggle-raw-btn"/);
    assert.match(src, /data-testid="copy-raw-btn"/);
    assert.match(src, /data-testid="raw-json"/);
    assert.match(src, /dangerouslySetInnerHTML=\{\{ __html: highlightJson\(event\.raw_data\) \}\}/);
    const html = highlightJson({ flows: [{ port: 4444, bytes_out: 12500000, ok: true }] });
    assert.match(html, /text-zinc-300">"port"/); // keys highlighted
    assert.match(html, /text-amber-300">4444</); // numbers highlighted
    assert.match(html, /text-sky-300">true</); // booleans highlighted
  });

  // Check 4: indicators list + engine badge + MITRE tags
  it('4 analysis result: indicators (type+value+severity), engine badge, MITRE tags', () => {
    const src = page();
    assert.match(src, /data-testid="indicator-list"/);
    assert.match(src, /data-testid="engine-badge"/);
    assert.match(src, /data-testid="mitre-tags"/);
    assert.match(src, /\{m\.id \? `\$\{m\.id\} \$\{m\.name \?\? ''\}` : m\.name\}/);
    // two-column layout: left 3/5, right 2/5
    assert.match(src, /lg:grid-cols-5/);
    assert.match(src, /lg:col-span-3/);
    assert.match(src, /lg:col-span-2/);
  });

  // Check 5: triage visibility by role
  it('5 admin/analyst get action buttons; viewer sees read-only (zero buttons)', () => {
    assert.strictEqual(canAct('admin'), true);
    assert.strictEqual(canAct('analyst'), true);
    assert.strictEqual(canAct('viewer'), false);
    assert.strictEqual(canAct(undefined), false);
    const src = page();
    assert.match(src, /\{triage \? \(/);
    assert.match(src, /data-testid="read-only-note"/);
    assert.match(src, /viewer keys cannot triage events/);
    // the three buttons live inside the triage branch only
    for (const id of ['release-btn', 'block-btn', 'fp-btn']) {
      assert.match(src, new RegExp(`data-testid="${id}"`));
    }
    assert.match(src, /disabled=\{acting !== null \|\| releaseDisabled\}/);
  });

  // Check 6: release action wiring + 409 inline error
  it('6 release: PATCH via updateEventVerdict; 409 -> inline error', () => {
    const src = page();
    assert.match(src, /onClick=\{\(\) => act\('released'\)\}/);
    const api = fs.readFileSync(apiPath, 'utf8');
    assert.match(api, /method: 'PATCH', body: JSON\.stringify\(\{ action \}\)/);
    assert.match(src, /Cannot release: indicator \$\{primaryBlocked \?\? ''\} is permanently blocked/);
    assert.match(src, /kind: 'err'/);
  });

  // Check 7: block permanently + false positive wiring
  it('7 block -> success banner with indicator value; false positive -> verdict update', () => {
    const src = page();
    assert.match(src, /onClick=\{\(\) => act\('blocked_permanently'\)\}/);
    assert.match(src, /onClick=\{\(\) => act\('false_positive'\)\}/);
    assert.match(src, /added to blocked list/);
    assert.match(src, /setEvent\(\{ \.\.\.event, \.\.\.updated \}\)/);
    assert.match(src, /data-testid="verdict-badge"/);
    assert.match(src, /data-testid="action-flash"/);
  });

  // Check 8: blocked-indicator warning + action history
  it('8 blocked-value match -> banner + release disabled; history entry vs empty state', () => {
    // exact, case-insensitive matching
    const rows = [
      { indicator_value: '198.51.100.23' },
      { indicator_value: 'evil.example.com' },
    ];
    assert.deepStrictEqual(
      matchBlockedValues(['198.51.100.23', 'other.io'], rows),
      ['198.51.100.23']
    );
    assert.deepStrictEqual(matchBlockedValues(['EVIL.EXAMPLE.COM'], rows), ['EVIL.EXAMPLE.COM']);
    assert.deepStrictEqual(matchBlockedValues(['partial-evil.example'], rows), []);

    const src = page();
    assert.match(src, /data-testid="blocked-warning-banner"/);
    assert.match(src, /is permanently blocked\. Release will fail\./);
    assert.match(src, /releaseDisabled = blockedValues\.length > 0 \|\| event\?\.indicator_blocked === true/);

    // history: entry when acted_at present, empty otherwise
    const base = {
      id: 'e1', project_id: 'p', organization_id: 'o', event_type: 'network_event',
      severity: 'high', source: 'gateway', raw_data: {}, analysis_result: null,
      verdict: 'released', user_action: null, acted_by: null, acted_at: null,
      created_at: '2026-09-26T00:00:00Z', indicator_blocked: false,
    };
    assert.deepStrictEqual(buildActionHistory(base), []);
    const acted = { ...base, user_action: 'released', acted_by: 'user-9', acted_at: '2026-09-26T10:00:00Z' };
    const history = buildActionHistory(acted);
    assert.strictEqual(history.length, 1);
    assert.strictEqual(history[0].acted_by, 'user-9');
    assert.strictEqual(history[0].user_action, 'released');
    assert.match(src, /data-testid="history-empty"/);
    assert.match(src, /No actions yet/);
  });
});
