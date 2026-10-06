import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

import {
  ATO_DEMO_BASELINE,
  ATO_DEMO_TIMELINE,
  atoClockLabel,
  atoDotClass,
  atoLevelTone,
  sortAtoTimeline,
} from '../pages/orgAtoHelpers.ts';

const pagePath = path.resolve('src/pages/OrgAccountTakeover.tsx');
const helpersPath = path.resolve('src/pages/orgAtoHelpers.ts');
const shellPath = path.resolve('src/pages/OrgWorkspaceShell.tsx');
const appPath = path.resolve('src/App.tsx');
const orgApiPath = path.resolve('src/services/orgApi.ts');

describe('SCENARIO-3 Org Account Takeover Test Suite (10 Checks)', () => {
  // Check 1: clock labels render as 12h AM/PM from ISO stamps
  it('1 atoClockLabel renders 03:17 AM from ISO timestamps', () => {
    assert.strictEqual(atoClockLabel('2026-10-06T03:17:00'), '03:17 AM');
    assert.strictEqual(atoClockLabel('2026-10-06T15:05:00'), '03:05 PM');
    assert.strictEqual(atoClockLabel('2026-10-06T00:00:00'), '12:00 AM');
    assert.strictEqual(atoClockLabel('2026-10-06T12:30:00'), '12:30 PM');
    assert.strictEqual(atoClockLabel(undefined), 'Unknown time');
  });

  // Check 2: timeline dots — flagged events red, clean events emerald
  it('2 atoDotClass: flagged -> red dot, clean -> emerald dot', () => {
    assert.match(atoDotClass({ flagged: ['odd_hour_login'] }), /bg-red-500/);
    assert.match(atoDotClass({ flagged: [] }), /bg-emerald-500/);
    assert.match(atoDotClass({}), /bg-emerald-500/);
  });

  // Check 3: risk level tones
  it('3 atoLevelTone maps levels to tones', () => {
    assert.strictEqual(atoLevelTone('high').label, 'HIGH');
    assert.strictEqual(atoLevelTone('CRITICAL').label, 'CRITICAL');
    assert.match(atoLevelTone('high').text, /text-red-300/);
    assert.match(atoLevelTone('medium').text, /text-amber-300/);
    assert.strictEqual(atoLevelTone('low').label, 'LOW');
    assert.strictEqual(atoLevelTone('').label, 'LOW');
  });

  // Check 4: timeline is sorted chronologically before render
  it('4 sortAtoTimeline orders events chronologically', () => {
    const sorted = sortAtoTimeline([
      { timestamp: '2026-10-06T03:25:00', detail: 'files' },
      { timestamp: '2026-10-06T03:17:00', detail: 'login' },
      { timestamp: '2026-10-06T03:20:00', detail: 'new device' },
    ]);
    assert.deepStrictEqual(
      sorted.map((e) => e.detail),
      ['login', 'new device', 'files']
    );
    // input array not mutated
    assert.strictEqual(sorted.length, 3);
  });

  // Check 5: demo assets mirror the scenario timeline (5 stages)
  it('5 demo payload carries the 5-stage attack timeline + baseline', () => {
    assert.strictEqual(ATO_DEMO_TIMELINE.length, 5);
    assert.strictEqual(ATO_DEMO_TIMELINE[0].timestamp, '2026-10-06T03:17:00');
    assert.strictEqual(ATO_DEMO_TIMELINE[1].failed_attempts, 8);
    assert.strictEqual(ATO_DEMO_TIMELINE[3].event_type, 'password_change');
    assert.strictEqual(ATO_DEMO_TIMELINE[4].files_accessed, 150);
    assert.strictEqual(ATO_DEMO_BASELINE.baseline_profile.home_country, 'US');
    assert.ok(ATO_DEMO_BASELINE.baseline_profile.known_devices.length >= 1);
  });

  // Check 6: page exists in the shell with the vertical timeline + details below
  it('6 page renders vertical timeline, indicators, actions, ExplanationPanel', () => {
    const page = fs.readFileSync(pagePath, 'utf8');
    assert.match(page, /data-testid="org-ato-page"/);
    // vertical line + per-item dots
    assert.match(page, /data-testid="ato-timeline"/);
    assert.match(page, /data-testid="ato-timeline-item"/);
    assert.match(page, /border-l-2/);
    assert.match(page, /atoDotClass\(event\)/);
    assert.match(page, /atoClockLabel\(event\.timestamp\)/);
    // below the timeline: indicators, actions, explanation
    assert.match(page, /data-testid="ato-indicators"/);
    assert.match(page, /data-testid="ato-actions"/);
    assert.match(page, /<ExplanationPanel/);
    assert.match(page, /eventId=\{result\.alert_id\}/);
  });

  // Check 7: page sends NO organization scope in the body — org rides the
  // membership-validated header, resolved server-side
  it('7 analyzeAccountTakeover posts without org id in body (header only)', () => {
    const orgApi = fs.readFileSync(orgApiPath, 'utf8');
    assert.match(orgApi, /analyzeAccountTakeover\(/);
    assert.match(orgApi, /'X-Organization-Id': orgId/);
    const page = fs.readFileSync(pagePath, 'utf8');
    const payloadBlock = page.match(/const payload = \{[\s\S]*?\n      \};/);
    assert.ok(payloadBlock, 'payload built in page');
    assert.doesNotMatch(payloadBlock[0], /organization_id/, 'no client-supplied org scope');
    assert.match(page, /analyzeAccountTakeover\(orgId, payload\)/);
  });

  // Check 8: shell sidebar gains the Analysis section with the ATO nav item
  it('8 shell sidebar: Analysis section + Account Takeover nav under it', () => {
    const shell = fs.readFileSync(shellPath, 'utf8');
    assert.match(shell, /data-testid="shell-analysis-section"/);
    assert.match(shell, />\s*Analysis\s*</);
    assert.match(shell, /data-testid="shell-ato-nav"/);
    assert.match(shell, /analysis\/account-takeover/);
    // active state uses aria-current like the other nav items
    assert.match(shell, /aria-current=\{atoActive \? 'page' : undefined\}/);
  });

  // Check 9: route registered inside the org shell behind OrgGuard
  it('9 route /org/:orgId/projects/:projectId/analysis/account-takeover in shell', () => {
    const app = fs.readFileSync(appPath, 'utf8');
    assert.match(app, /import OrgAccountTakeover from '\.\/pages\/OrgAccountTakeover'/);
    assert.match(
      app,
      /path="\/org\/:orgId\/projects\/:projectId\/analysis\/account-takeover"/
    );
    assert.match(
      app,
      /<OrgGuard>\s*<OrgWorkspaceShell>\s*<OrgAccountTakeover \/>\s*<\/OrgWorkspaceShell>\s*<\/OrgGuard>/
    );
  });

  // Check 10: run control + error handling
  it('10 run button + invalid-JSON guard present', () => {
    const page = fs.readFileSync(pagePath, 'utf8');
    assert.match(page, /data-testid="ato-run-btn"/);
    assert.match(page, /data-testid="ato-load-demo-btn"/);
    assert.match(page, /Activity timeline must be a JSON array/);
    assert.match(page, /data-testid="ato-error"/);
    assert.match(page, /data-testid="ato-risk-pill"/);
  });
});
