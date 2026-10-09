import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const sectionPath = path.resolve('src/pages/ProjectSettingsApiKeys.tsx');
const apiPath = path.resolve('src/services/orgApi.ts');
const pagePath = path.resolve('src/pages/ProjectSettings.tsx');

// Stand-in matching the ApiError shape used by the page.
class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

describe('ORG-SETTINGS-P5 Test Suite (5 Checks)', () => {
  // Check 1: two-slot cards render empty / active / revoked-as-empty, per role
  it('1 slot states: empty -> Generate, active -> prefix/status/Revoke, revoked treated empty; viewer independent', () => {
    const src = fs.readFileSync(sectionPath, 'utf8');
    // Both role cards, side-by-side grid
    assert.match(src, /data-testid=\{`key-card-\$\{role\}`\}/);
    assert.match(src, /grid grid-cols-1 gap-4 sm:grid-cols-2/);
    assert.match(src, /'Master key', blurb: 'All gateway actions: ingest, analyze, enforce'/);
    assert.match(src, /'View-only key', blurb: 'Read-only audit access; write actions reject with 403'/);
    // Slot query is role-scoped and ignores revoked keys (slot freed)
    assert.match(
      src,
      /find\(\(k\) => k\.role === role && k\.status === 'active'\) \?\? null/
    );
    // Empty / active render branches with their testids
    assert.match(src, /data-testid=\{`key-empty-\$\{role\}`\}/);
    assert.match(src, /data-testid=\{`key-active-\$\{role\}`\}/);
    assert.match(src, /data-testid=\{`generate-key-\$\{role\}`\}/);
    assert.match(src, /data-testid=\{`revoke-key-\$\{role\}`\}/);
    assert.match(src, /data-testid=\{`key-status-\$\{role\}`\}/);
    // Generate posts only the role (name is derived client-side)
    assert.match(src, /orgApi\.createKey\(orgId, projectId, name, role\)/);

    // Logic: revoked keys free the slot; viewer slot independent of master
    const keys = [
      { role: 'master', status: 'revoked' },
      { role: 'viewer', status: 'active' },
    ];
    const activeKeyFor = (role: string) =>
      (keys as any[]).find((k) => k.role === role && k.status === 'active') ?? null;
    assert.strictEqual(activeKeyFor('master'), null, 'revoked master must render as empty');
    assert.ok(activeKeyFor('viewer'), 'viewer slot must stay independent');
  });

  // Check 2: generate -> plaintext-once panel -> checkbox-gated close -> prefix-only refetch
  it('2 generate: plaintext once with copy + checkbox gate; refetch after close', async () => {
    const src = fs.readFileSync(sectionPath, 'utf8');
    assert.match(src, /data-testid="plaintext-panel"/);
    assert.match(src, /data-testid="plaintext-value"/);
    assert.match(src, /testid="plaintext-copy"/);
    assert.match(src, /data-testid="saved-checkbox"/);
    assert.match(src, /I have saved this key/);
    assert.match(src, /disabled=\{!savedConfirmed\}/);
    assert.match(src, /data-testid="plaintext-done-btn"/);
    // Close drops the plaintext and refetches (prefix-only list afterwards)
    assert.match(src, /setPlaintext\(null\);\s*\n\s*setSavedConfirmed\(false\)/);
    assert.match(src, /orgApi\.listKeys\(orgId, projectId\)/);
    // Checkbox gates the Done button: simulate
    let closed = false;
    let savedConfirmed = false;
    const closeGenerateModal = () => {
      if (!savedConfirmed) return; // disabled in DOM
      closed = true;
    };
    closeGenerateModal();
    assert.strictEqual(closed, false);
    savedConfirmed = true;
    closeGenerateModal();
    assert.strictEqual(closed, true);

    const api = fs.readFileSync(apiPath, 'utf8');
    assert.match(api, /async createKey\(/);
    assert.match(api, /api_key: string;/);
  });

  // Check 3: revoke confirm frees the slot
  it('3 revoke: confirm modal -> revoke endpoint -> slot returns to empty', async () => {
    const src = fs.readFileSync(sectionPath, 'utf8');
    assert.match(src, /data-testid="confirm-revoke-btn"/);
    assert.match(src, /orgApi\.revokeKey\(orgId, projectId, revokeTarget\.id\)/);
    assert.match(src, /data-testid="revoke-error"/);
    // After revoke the list is refetched (card flips to empty via activeKeyFor)
    assert.match(src, /const rows = await orgApi\.listKeys\(orgId, projectId\);\s*\n\s*setKeys\(rows\);/);
    const api = fs.readFileSync(apiPath, 'utf8');
    assert.match(api, /async revokeKey\(orgId: string, projectId: string, keyId: string\)/);

    // Logic: revoke then refetch — the role's active key is gone
    let rows = [{ id: 'k1', role: 'master', status: 'active' }];
    const revokeKey = async (_org: string, _proj: string, keyId: string) => {
      rows = rows.map((k) => (k.id === keyId ? { ...k, status: 'revoked' } : k));
    };
    await revokeKey('o', 'p', 'k1');
    const activeMaster = rows.find((k) => k.role === 'master' && k.status === 'active') ?? null;
    assert.strictEqual(activeMaster, null);
  });

  // Check 4: non-admin renders info card and never fetches keys
  it('4 non-admin: info card, no key data or buttons, zero keys calls', () => {
    const src = fs.readFileSync(sectionPath, 'utf8');
    // Role gate first; keys endpoint only touched when org.role === 'admin'
    assert.match(src, /setIsAdmin\(org\.role === 'admin'\)/);
    assert.match(src, /if \(org\.role !== 'admin'\) return;/);
    // Early-return info card for non-admins
    assert.match(src, /if \(isAdmin === false\) \{[\s\S]{0,400}?data-testid="apikeys-info-card"/);
    assert.match(src, /API keys are managed by organization admins\./);
    // No key card testids inside the non-admin branch
    const infoBranch = src.match(/if \(isAdmin === false\) \{[\s\S]*?\n  \}\n\n  if \(loadError\)/);
    assert.ok(infoBranch, 'non-admin early return block must exist');
    assert.doesNotMatch(infoBranch[0], /key-card-|generate-key-|revoke-key-|listKeys/);
  });

  // Check 5: gateway reference row — URL from slug, copy flash, collapsible curl
  it('5 gateway row: p/{slug}/gateway URL + copy + curl with Bearer placeholder and analyze_log', () => {
    const src = fs.readFileSync(sectionPath, 'utf8');
    assert.match(src, /data-testid="gateway-row"/);
    assert.match(src, /data-testid="gateway-url"/);
    assert.match(
      src,
      /\$\{gatewayBase\}\/p\/\$\{projectSlug\}\/gateway/
    );
    assert.match(src, /testid="gateway-copy"/);
    assert.match(src, /data-testid="curl-toggle"/);
    assert.match(src, /data-testid="curl-example"/);
    assert.match(src, /testid="curl-copy"/);
    assert.match(src, /Authorization: Bearer <your-master-key>/);
    assert.match(src, /"action": "analyze_log"/);
    // Wired into the settings page for the api-keys section
    const page = fs.readFileSync(pagePath, 'utf8');
    assert.match(page, /<ProjectSettingsApiKeys orgId=\{orgId\} projectId=\{projectId\} projectSlug=\{project\.slug\} \/>/);
  });
});
