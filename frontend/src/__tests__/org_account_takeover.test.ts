import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

import {
  ATO_ACTION_KEYS,
  ATO_DEMO_BASELINE,
  ATO_DEMO_TIMELINE,
  atoActionAfterManual,
  atoActionBadge,
  atoActionButtonClass,
  atoActionLabel,
  atoActionToastText,
  atoActionUiState,
  atoBannerLabel,
  atoBannerTone,
  atoClockLabel,
  atoDotClass,
  atoLevelTone,
  atoScoreTone,
  atoStatusTone,
  filterAtoEvents,
  sortAtoTimeline,
} from '../pages/orgAtoHelpers.ts';

const listPath = path.resolve('src/pages/OrgAccountTakeoverList.tsx');
const detailPath = path.resolve('src/pages/OrgAccountTakeoverDetail.tsx');
const helpersPath = path.resolve('src/pages/orgAtoHelpers.ts');
const oldPagePath = path.resolve('src/pages/OrgAccountTakeover.tsx');
const shellPath = path.resolve('src/pages/OrgWorkspaceShell.tsx');
const appPath = path.resolve('src/App.tsx');
const orgApiPath = path.resolve('src/services/orgApi.ts');

const ROWS = [
  { id: 'evt-aaa-111', user_email: 'sarah.chen@acme.com', risk_score: 92, action_taken: 'ACCOUNT_RESTRICTED' },
  { id: 'evt-bbb-222', user_email: 'john Doe@acme.com', risk_score: 45, action_taken: 'USER_NOTIFIED' },
  { id: 'evt-ccc-333', user_email: 'bob@acme.com', risk_score: 0, action_taken: 'ALLOWED' },
];

describe('SCENARIO-3 / ATO-UI-OVERHAUL Test Suite (18 Checks)', () => {
  // Check 1: clock labels render as 12h AM/PM from ISO stamps
  it('1 atoClockLabel renders 03:17 AM from ISO timestamps', () => {
    assert.strictEqual(atoClockLabel('2026-10-06T03:17:00'), '03:17 AM');
    assert.strictEqual(atoClockLabel('2026-10-06T15:05:00'), '03:05 PM');
    assert.strictEqual(atoClockLabel('2026-10-06T00:00:00'), '12:00 AM');
    assert.strictEqual(atoClockLabel(undefined), 'Unknown time');
  });

  // Check 2: timeline dots — flagged events red, clean events emerald
  it('2 atoDotClass: flagged -> red dot, clean -> emerald dot', () => {
    assert.match(atoDotClass({ flagged: ['odd_hour_login'] }), /bg-red-500/);
    assert.match(atoDotClass({ flagged: [] }), /bg-emerald-500/);
  });

  // Check 3: risk level tones
  it('3 atoLevelTone maps levels to tones', () => {
    assert.strictEqual(atoLevelTone('high').label, 'HIGH');
    assert.strictEqual(atoLevelTone('CRITICAL').label, 'CRITICAL');
    assert.strictEqual(atoLevelTone('low').label, 'LOW');
  });

  // Check 4: timeline is sorted chronologically before render
  it('4 sortAtoTimeline orders events chronologically', () => {
    const sorted = sortAtoTimeline([
      { timestamp: '2026-10-06T03:25:00', detail: 'files' },
      { timestamp: '2026-10-06T03:17:00', detail: 'login' },
    ]);
    assert.deepStrictEqual(sorted.map((e) => e.detail), ['login', 'files']);
  });

  // Check 5: demo assets mirror the scenario timeline (5 stages)
  it('5 demo payload carries the 5-stage attack timeline + baseline', () => {
    assert.strictEqual(ATO_DEMO_TIMELINE.length, 5);
    assert.strictEqual(ATO_DEMO_TIMELINE[1].failed_attempts, 8);
    assert.strictEqual(ATO_DEMO_TIMELINE[4].files_accessed, 150);
    assert.strictEqual(ATO_DEMO_BASELINE.baseline_profile.home_country, 'US');
  });

  // Check 6: search filters in real-time by event id OR email, case-insensitive
  it('6 filterAtoEvents filters by id or email substring', () => {
    assert.strictEqual(filterAtoEvents(ROWS, '').length, 3);
    assert.strictEqual(filterAtoEvents(ROWS, '   ').length, 3, 'whitespace query = all');
    // by event id (case-insensitive substring)
    assert.deepStrictEqual(
      filterAtoEvents(ROWS, 'BBB').map((r) => r.id),
      ['evt-bbb-222']
    );
    assert.deepStrictEqual(
      filterAtoEvents(ROWS, 'evt-ccc').map((r) => r.id),
      ['evt-ccc-333']
    );
    // by email
    assert.deepStrictEqual(
      filterAtoEvents(ROWS, 'sarah.chen').map((r) => r.id),
      ['evt-aaa-111']
    );
    assert.deepStrictEqual(
      filterAtoEvents(ROWS, 'ACME.COM').length,
      3,
      'email domain matches all, case-insensitive'
    );
    assert.strictEqual(filterAtoEvents(ROWS, 'nope@nowhere.io').length, 0);
  });

  // Check 7: status pills + score badges + banner follow the 3 tiers
  it('7 status tone, score tone and banner label follow the 3-tier bands', () => {
    assert.strictEqual(atoStatusTone('ALLOWED').label, 'Allowed');
    assert.match(atoStatusTone('ALLOWED').className, /emerald/);
    assert.strictEqual(atoStatusTone('USER_NOTIFIED').label, 'Notified');
    assert.match(atoStatusTone('USER_NOTIFIED').className, /amber/);
    assert.strictEqual(atoStatusTone('ACCOUNT_RESTRICTED').label, 'Restricted');
    assert.match(atoStatusTone('ACCOUNT_RESTRICTED').className, /red/);

    assert.match(atoScoreTone(0), /emerald/);
    assert.match(atoScoreTone(29), /emerald/);
    assert.match(atoScoreTone(30), /amber/);
    assert.match(atoScoreTone(74), /amber/);
    assert.match(atoScoreTone(75), /red/);
    assert.match(atoScoreTone(92), /red/);

    assert.strictEqual(atoBannerLabel('ACCOUNT_RESTRICTED'), 'ACCOUNT RESTRICTED & USER NOTIFIED');
    assert.strictEqual(atoBannerLabel('USER_NOTIFIED'), 'USER NOTIFIED');
    assert.match(atoBannerLabel('ALLOWED'), /ALLOWED/);
    assert.match(atoBannerTone('ACCOUNT_RESTRICTED'), /red/);
    assert.match(atoBannerTone('USER_NOTIFIED'), /amber/);
  });

  // Check 8: list page — search box, table columns, real-time filter wiring
  it('8 list page: search input filters in real-time over the server-scoped list', () => {
    const page = fs.readFileSync(listPath, 'utf8');
    assert.match(page, /data-testid="org-ato-list-page"/);
    assert.match(page, /data-testid="ato-search-input"/);
    assert.match(page, /onChange=\{\(e\) => setQuery\(e\.target\.value\)\}/);
    assert.match(page, /filterAtoEvents\(events \?\? \[\], query\)/);
    assert.match(page, /orgApi\s*\.\s*listAtoEvents\(orgId\)/);
    for (const col of ['Timestamp', 'Account', 'Risk Score', 'Status']) {
      assert.ok(page.includes(col), `column ${col} present`);
    }
    assert.match(page, /data-testid="ato-score-badge"/);
    assert.match(page, /data-testid="ato-status-badge"/);
    assert.match(page, /atoScoreTone\(event\.risk_score\)/);
    assert.match(page, /atoStatusTone\(event\.action_taken\)/);
    assert.match(page, /data-testid="ato-list-row"/);
    assert.match(page, /data-testid="ato-list-empty"/);
  });

  // Check 9: row click navigates to the detail route
  it('9 list row click navigates to /analysis/account-takeover/:eventId', () => {
    const page = fs.readFileSync(listPath, 'utf8');
    assert.match(
      page,
      /navigate\(\s*`\/org\/\$\{orgId\}\/projects\/\$\{projectId\}\/analysis\/account-takeover\/\$\{event\.id\}`\s*\)/
    );
    const app = fs.readFileSync(appPath, 'utf8');
    assert.match(app, /path="\/org\/:orgId\/projects\/:projectId\/analysis\/account-takeover\/:eventId"/);
  });

  // Check 10: detail page is READ-ONLY (zero input elements)
  it('10 detail page is read-only: no inputs, forms or textareas', () => {
    const page = fs.readFileSync(detailPath, 'utf8');
    assert.doesNotMatch(page, /<input|<textarea|<select|<form/, 'detail page must have zero inputs');
    assert.match(page, /data-testid="org-ato-detail-page"/);
    assert.match(page, /orgApi\s*\.\s*getAtoEventDetail\(orgId, eventId\)/);
  });

  // Check 11: detail banner is prominent and shows the enforced action
  it('11 detail page: action banner + baseline/timeline/evidence/actions/explanation sections', () => {
    const page = fs.readFileSync(detailPath, 'utf8');
    assert.match(page, /data-testid="ato-action-banner"/);
    assert.match(page, /atoBannerLabel\(detail\.action_taken\)/);
    assert.match(page, /atoBannerTone\(detail\.action_taken\)/);
    // section 1: baseline display (definition list, not a form)
    assert.match(page, /data-testid="ato-baseline-section"/);
    // section 2: vertical timeline
    assert.match(page, /data-testid="ato-timeline"/);
    assert.match(page, /data-testid="ato-timeline-item"/);
    assert.match(page, /border-l-2/);
    assert.match(page, /atoDotClass\(event\)/);
    // section 3: evidence + recommended actions
    assert.match(page, /data-testid="ato-indicators"/);
    assert.match(page, /data-testid="ato-actions"/);
    // section 4: explanation panel
    assert.match(page, /<ExplanationPanel/);
    assert.match(page, /eventId=\{detail\.alert_id \?\? undefined\}/);
  });

  // Check 12: routes — list is the sidebar default, detail nested; old form page gone
  it('12 routes: list default + detail nested behind OrgGuard in shell; old form removed', () => {
    const app = fs.readFileSync(appPath, 'utf8');
    assert.match(app, /import OrgAccountTakeoverList from '\.\/pages\/OrgAccountTakeoverList'/);
    assert.match(app, /import OrgAccountTakeoverDetail from '\.\/pages\/OrgAccountTakeoverDetail'/);
    assert.match(
      app,
      /<OrgGuard>\s*<OrgWorkspaceShell>\s*<OrgAccountTakeoverList \/>\s*<\/OrgWorkspaceShell>\s*<\/OrgGuard>/
    );
    assert.match(
      app,
      /<OrgGuard>\s*<OrgWorkspaceShell>\s*<OrgAccountTakeoverDetail \/>\s*<\/OrgWorkspaceShell>\s*<\/OrgGuard>/
    );
    assert.strictEqual(fs.existsSync(oldPagePath), false, 'manual form page must be deleted');
    // shell sidebar still points at the list route (Analysis section)
    const shell = fs.readFileSync(shellPath, 'utf8');
    assert.match(shell, /data-testid="shell-ato-nav"/);
    assert.match(shell, /analysis\/account-takeover/);
  });

  // Check 13: org scope never rides the URL/query — header only
  it('13 list/detail requests carry X-Organization-Id, no org id in query', () => {
    const orgApi = fs.readFileSync(orgApiPath, 'utf8');
    assert.match(orgApi, /listAtoEvents\(/);
    assert.match(orgApi, /getAtoEventDetail\(/);
    const listBlock = orgApi.match(/async listAtoEvents\([\s\S]*?\n  \},/);
    const detailBlock = orgApi.match(/async getAtoEventDetail\([\s\S]*?\n  \},/);
    assert.ok(listBlock && detailBlock);
    assert.match(listBlock[0], /'X-Organization-Id': orgId/);
    assert.match(detailBlock[0], /'X-Organization-Id': orgId/);
    assert.doesNotMatch(listBlock[0], /organization_id=/, 'no org id as query param');
  });

  // Check 14: helpers file stays framework-free (node:test importable)
  it('14 helpers remain framework-free pure functions', () => {
    const helpers = fs.readFileSync(helpersPath, 'utf8');
    assert.doesNotMatch(helpers, /import\s+.*react|useState|useEffect/i);
  });

  // Check 15: action UI state derivation from the ledger (hybrid actions)
  it('15 atoActionUiState: pending / done_auto / done_manual from ledger', () => {
    assert.strictEqual(atoActionUiState(undefined), 'pending');
    assert.strictEqual(atoActionUiState({}), 'pending');
    assert.strictEqual(atoActionUiState({ status: 'pending' }), 'pending');
    assert.strictEqual(atoActionUiState({ status: 'done_auto', via: 'auto' }), 'done_auto');
    assert.strictEqual(atoActionUiState({ status: 'done_manual', via: 'manual' }), 'done_manual');
  });

  // Check 16: badges, labels, buttons and the manual transition
  it('16 action badges Pending/Done(Auto)/Done(Manual), pure manual transition, toast text', () => {
    assert.deepStrictEqual(ATO_ACTION_KEYS, ['notify_user', 'restrict_account', 'force_password_reset']);
    assert.strictEqual(atoActionBadge('pending').label, 'Pending');
    assert.match(atoActionBadge('pending').className, /zinc/);
    assert.strictEqual(atoActionBadge('done_auto').label, 'Done (Auto)');
    assert.match(atoActionBadge('done_auto').className, /blue/);
    assert.strictEqual(atoActionBadge('done_manual').label, 'Done (Manual)');
    assert.match(atoActionBadge('done_manual').className, /emerald/);

    assert.strictEqual(atoActionLabel('notify_user'), 'Notify User');
    assert.strictEqual(atoActionLabel('restrict_account'), 'Restrict Account');
    assert.strictEqual(atoActionLabel('force_password_reset'), 'Force Password Reset');
    // pending Notify User button is [YELLOW]
    assert.match(atoActionButtonClass('notify_user'), /amber/);

    // transition: pending -> Done (Manual), immutably, other entries kept
    const before = {
      notify_user: { status: 'done_auto', via: 'auto' },
      restrict_account: { status: 'pending' },
    };
    const after = atoActionAfterManual(before as never, 'restrict_account');
    assert.strictEqual(after.restrict_account.status, 'done_manual');
    assert.strictEqual(after.restrict_account.via, 'manual');
    assert.strictEqual(after.notify_user.status, 'done_auto', 'auto entry untouched');
    assert.strictEqual(before.restrict_account.status, 'pending', 'original ledger not mutated');
    // executing an auto-done action manually would still be pending-gated in UI
    assert.strictEqual(atoActionUiState(before.notify_user), 'done_auto');

    assert.strictEqual(atoActionToastText('notify_user'), 'Action executed manually: User Notified');
    assert.strictEqual(atoActionToastText('restrict_account'), 'Action executed manually: Account Restricted');
  });

  // Check 17: detail page renders the unified action center
  it('17 detail page: action center shows state badges, disables non-pending, PATCH wiring, toast', () => {
    const page = fs.readFileSync(detailPath, 'utf8');
    assert.match(page, /data-testid="ato-actions-panel"/);
    assert.match(page, /data-testid=\{`ato-action-\$\{action\}`\}/);
    assert.match(page, /data-testid=\{`ato-action-badge-\$\{action\}`\}/);
    assert.match(page, /data-testid=\{`ato-action-btn-\$\{action\}`\}/);
    // state drives the button: disabled unless pending
    assert.match(page, /disabled=\{state !== 'pending' \|\| acting !== null\}/);
    // PATCH through the unified endpoint, then optimistic ledger update
    assert.match(page, /orgApi\.executeAtoAction\(orgId, eventId, action\)/);
    assert.match(page, /atoActionAfterManual\(prev, action\)/);
    assert.match(page, /atoActionUiState\(ledger\[action\]\)/);
    // success toast
    assert.match(page, /data-testid="ato-toast"/);
    assert.match(page, /atoActionToastText\(action\)/);
    // auto-execution state comes from the fetched ledger
    assert.match(page, /setLedger\(data\.action_ledger \?\? \{\}\)/);
    // detail page remains read-only except for the action buttons (no inputs)
    assert.doesNotMatch(page, /<input|<textarea|<select|<form/);
  });

  // Check 18: PATCH request carries only the action — org scope header-only
  it('18 executeAtoAction uses PATCH with X-Organization-Id header, no org in body', () => {
    const orgApi = fs.readFileSync(orgApiPath, 'utf8');
    const block = orgApi.match(/async executeAtoAction\([\s\S]*?\n  \},/);
    assert.ok(block, 'executeAtoAction defined');
    assert.match(block[0], /method: 'PATCH'/);
    assert.match(block[0], /'X-Organization-Id': orgId/);
    assert.match(block[0], /JSON\.stringify\(\{ action \}\)/);
  });
});
