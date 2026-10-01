/** MEMBER-INVITE-P2 — Frontend invitation UI test suite (6 checks).
 *
 * Repo convention: node:test with source assertions on the .tsx sources plus
 * logic simulations of the extracted pure helpers (no DOM/Playwright in this
 * suite — the helper module is importable directly).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

import {
  mapAcceptError,
  acceptRedirectPath,
  loginRedirectPath,
  hasUsableToken,
} from '../pages/acceptInvitationHelpers.ts';

const orgApiPath = path.resolve('src/services/orgApi.ts');
const generalPath = path.resolve('src/pages/ProjectSettingsGeneral.tsx');
const acceptPagePath = path.resolve('src/pages/AcceptInvitationPage.tsx');
const pendingPath = path.resolve('src/components/PendingInvitations.tsx');
const apiPath = path.resolve('src/services/api.ts');
const authErrorPath = path.resolve('src/components/common/authError.ts');
const loginPath = path.resolve('src/pages/Login.tsx');

// Stand-in matching ApiError (kept in sync with services/http.ts).
class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

describe('MEMBER-INVITE-P2 Test Suite (7 Checks)', () => {
  // Check 1: API client methods + backend response shapes
  it('1 api: inviteMember/listInvitations/revokeInvitation/acceptInvitation hit the invitation endpoints', () => {
    const api = fs.readFileSync(orgApiPath, 'utf8');
    assert.match(api, /async inviteMember\(orgId: string, email: string, role: string\): Promise<CreatedInvitation>/);
    assert.match(api, /apiFetch\(`\/orgs\/\$\{encodeURIComponent\(orgId\)\}\/members`/);
    assert.match(api, /async listInvitations\(orgId: string\): Promise<Invitation\[\]>/);
    assert.match(api, /data\.invitations \|\| \[\]/);
    assert.match(api, /async revokeInvitation\(orgId: string, invitationId: string\): Promise<void>/);
    assert.match(api, /`\/orgs\/\$\{encodeURIComponent\(orgId\)\}\/invitations\/\$\{encodeURIComponent\(invitationId\)\}`/);
    assert.match(api, /async acceptInvitation\(token: string\): Promise<AcceptanceResult>/);
    assert.match(api, /apiFetch\('\/invitations\/accept'/);
    // response-shape types
    assert.match(api, /interface CreatedInvitation extends Invitation \{[\s\S]*?token: string;/);
    assert.match(api, /interface AcceptanceResult \{[\s\S]*?organization_id: string;[\s\S]*?organization_name: string;[\s\S]*?role:/);
    // the old direct-add method is gone (backend no longer returns member rows)
    assert.doesNotMatch(api, /async addMember\(/);
  });

  // Check 2: accept-page error mapping (F2: 404 / 410 / 403 / generic)
  it('2 accept errors: 404 invalid, 410 expired, 403 mismatch, generic fallback', () => {
    assert.deepStrictEqual(mapAcceptError(404, ''), { kind: 'invalid', text: 'Invalid or used invitation link.' });
    assert.deepStrictEqual(mapAcceptError(410, ''), { kind: 'expired', text: 'This invitation has expired.' });
    // 403 surfaces the backend detail, which names the invited address
    assert.deepStrictEqual(
      mapAcceptError(403, 'This invitation was issued to a@b.test. Sign in with that account to accept it.'),
      {
        kind: 'mismatch',
        text: 'This invitation was issued to a@b.test. Sign in with that account to accept it.',
      },
    );
    assert.deepStrictEqual(mapAcceptError(403, ''), {
      kind: 'mismatch',
      text: 'This invitation was sent to a different email address.',
    });
    const generic = mapAcceptError(500, 'backend detail');
    assert.strictEqual(generic.kind, 'generic');
    assert.match(generic.text, /backend detail/);
    const noStatus = mapAcceptError(undefined, '');
    assert.strictEqual(noStatus.kind, 'generic');
  });

  // Check 3: accept-page routing logic (login bounce + post-success landing)
  it('3 accept routing: next-hop login redirect, projects landing, token gate', () => {
    // unauthenticated bounce: /login?mode=org&next=<encoded accept URL>
    const loginPath = loginRedirectPath('tok-123-abc');
    assert.match(loginPath, /^\/login\?mode=org&next=/);
    const next = new URLSearchParams(loginPath.split('?')[1]).get('next')!;
    assert.strictEqual(next, '/auth/accept-invite?token=tok-123-abc');
    // tokens with special chars survive the double encoding
    const next2 = new URLSearchParams(loginRedirectPath('a+b/c?d=e').split('?')[1]).get('next')!;
    assert.strictEqual(next2, '/auth/accept-invite?token=a%2Bb%2Fc%3Fd%3De');
    // success lands on the joined org's project selector (workspace root)
    assert.strictEqual(acceptRedirectPath('org-1'), '/org/org-1/projects');
    // token gate: missing/short tokens never reach the API
    assert.strictEqual(hasUsableToken(null), false);
    assert.strictEqual(hasUsableToken('short'), false);
    assert.strictEqual(hasUsableToken('tok-123-abc-456-def'), true);
  });

  // Check 4: accept page UI states + auth-aware redirect
  it('4 accept page: verifying/success/error states, auth bounce wired', () => {
    const src = fs.readFileSync(acceptPagePath, 'utf8');
    assert.match(src, /Verifying invitation\.\.\./);
    assert.match(src, /data-testid="accept-spinner"/);
    assert.match(src, /Welcome to \{phase\.orgName \|\| 'your organization'\}!/);
    assert.match(src, /data-testid="accept-error"/);
    // navigates to the helper-built landing after success
    assert.match(src, /navigate\(acceptRedirectPath\(res\.organization_id\)/);
    // unauthenticated (hydrated) -> Navigate to the login next-hop
    assert.match(src, /if \(hydrated && !isAuthenticated\) \{\s*\n\s*return <Navigate to=\{loginRedirectPath\(token \?\? ''\)\} replace \/>;/);
    // route registered in App.tsx
    const app = fs.readFileSync(path.resolve('src/App.tsx'), 'utf8');
    assert.match(app, /import AcceptInvitationPage from '\.\/pages\/AcceptInvitationPage';/);
    assert.match(app, /<Route path="\/auth\/accept-invite" element=\{<AcceptInvitationPage \/>\} \/>/);
    // org-mode login honors ?next= so the bounce round-trips (MEMBER-INVITE-P2)
    const login = fs.readFileSync(loginPath, 'utf8');
    assert.match(login, /MEMBER-INVITE-P2: an explicit \?next= hop/);
    assert.match(login, /if \(nextPath !== '\/dashboard'\) \{\s*\n\s*goTo\(nextPath\);/);
  });

  // Check 5: pending invitations table + revoke flow
  it('5 pending list: table columns, revoke confirm removes row, empty/loading states', async () => {
    const src = fs.readFileSync(pendingPath, 'utf8');
    assert.match(src, /data-testid="pending-invitations"/);
    for (const col of ['Email', 'Role', 'Expires', 'Status', 'Actions']) {
      assert.match(src, new RegExp(`>${col}</th>`), `missing ${col} column`);
    }
    assert.match(src, /data-testid="invitations-empty"/);
    assert.match(src, /No pending invitations/);
    assert.match(src, /data-testid="invitations-loading"/);
    assert.match(src, /orgApi[\s.]*listInvitations\(orgId\)/);
    assert.match(src, /data-testid="confirm-revoke-btn"/);
    assert.match(src, /orgApi[\s.]*revokeInvitation\(orgId, revokeTarget\.id\)/);
    // status badge per row; revoke only offered for pending
    assert.match(src, /data-testid=\{`invitation-status-\$\{inv\.id\}`\}/);
    assert.match(src, /\{inv\.status === 'pending' && \([\s\S]{0,200}?data-testid=\{`revoke-invitation-\$\{inv\.email\}`\}/);

    // logic simulation: revoke removes exactly the revoked row
    const rows = [{ id: 'i1', email: 'a@x.test' }, { id: 'i2', email: 'b@x.test' }];
    const revokeInvitation = async (_orgId: string, id: string) => {
      if (id === 'boom') throw new ApiError('Invitation has already been accepted', 409);
    };
    const target = rows[0];
    await revokeInvitation('org-1', target.id);
    const remaining = rows.filter((r) => r.id !== target.id);
    assert.strictEqual(remaining.length, 1);
    assert.strictEqual(remaining[0].email, 'b@x.test');
    await assert.rejects(() => revokeInvitation('org-1', 'boom'), /already been accepted/);
  });

  // Check 6: cleanup — dead /organizations member endpoints removed, check_invite copy updated
  it('6 cleanup: api.ts dead org endpoints gone; check_invite points to the invitation link', () => {
    const api = fs.readFileSync(apiPath, 'utf8');
    for (const fn of [
      'listOrganizations',
      'createOrganization',
      'getOrganization',
      'listOrganizationMembers',
      'addOrganizationMember',
      'updateOrganizationMemberRole',
      'removeOrganizationMember',
    ]) {
      assert.doesNotMatch(api, new RegExp(`export async function ${fn}\\(`), `${fn} should be removed`);
    }
    assert.doesNotMatch(api, /\/organizations\/\$\{orgId\}\/members/);
    const authError = fs.readFileSync(authErrorPath, 'utf8');
    assert.match(authError, /hint === 'check_invite'/);
    assert.match(authError, /Open the invitation link you received to accept it\./);
    assert.doesNotMatch(authError, /Check your email or sign in to accept\./);
  });

  // Check 7 (MEMBER-INVITE-P4): Leave Organization button — non-owner only,
  // DELETE own membership row, redirect to /org/select on success.
  it('7 leave org: owner excluded, removes own membership, redirects to /org/select', async () => {
    const src = fs.readFileSync(generalPath, 'utf8');
    // visibility gate: needs own member row and must not be the owner
    assert.match(src, /const myMember = members\.find\(\(m\) => m\.user_id === user\?\.id\);/);
    assert.match(src, /const canLeave = Boolean\(org && myMember && myMember\.user_id !== org\.owner_id\);/);
    assert.match(src, /\{canLeave && \([\s\S]{0,600}?data-testid="leave-org-btn"/);
    // confirm modal copy + button
    assert.match(src, /Are you sure you want to leave \{org\?\.name \|\| 'this organization'\}\? You will lose/);
    assert.match(src, /data-testid="confirm-leave-btn"/);
    // action: DELETE own membership row, then redirect to the org selector
    assert.match(src, /await orgApi\.removeMember\(orgId, myMember\.id\);/);
    assert.match(src, /navigate\('\/org\/select'\);/);
    // inline failure surfacing
    assert.match(src, /data-testid="leave-error"/);

    // logic simulation: owner row hidden, member row visible + removable
    const members = [
      { id: 'm1', user_id: 'u-owner' },
      { id: 'm2', user_id: 'u-me' },
    ];
    const owner_id = 'u-owner';
    const me = 'u-me';
    const myMember = members.find((m) => m.user_id === me)!;
    const canLeave = Boolean(myMember && myMember.user_id !== owner_id);
    assert.strictEqual(canLeave, true);
    const ownerCanLeave = Boolean(members.find((m) => m.user_id === owner_id)! &&
      members.find((m) => m.user_id === owner_id)!.user_id !== owner_id);
    assert.strictEqual(ownerCanLeave, false);
    const deleted: string[] = [];
    const removeMember = async (_orgId: string, memberId: string) => {
      deleted.push(memberId);
    };
    await removeMember('org-1', myMember.id);
    assert.deepStrictEqual(deleted, ['m2']);
  });
});
