import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const generalPath = path.resolve('src/pages/ProjectSettingsGeneral.tsx');
const apiPath = path.resolve('src/services/orgApi.ts');

// Stand-in matching the ApiError shape used by the page (importing the real
// module would drag the whole supabase/authStore chain into the node runner).
class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

describe('ORG-SETTINGS-P3 Test Suite (6 Checks)', () => {
  // Check 1: name save disabled until dirty -> PATCH -> refetch
  it('1 save persists: PATCH name on dirty, refetch via onProjectRefresh', async () => {
    const src = fs.readFileSync(generalPath, 'utf8');
    assert.match(src, /data-testid="project-name-input"/);
    assert.match(src, /disabled=\{!nameDirty \|\| savingName\}/);
    assert.match(src, /orgApi\.updateProject\(orgId, project\.id, \{ name: nameDraft\.trim\(\) \}\)/);
    assert.match(src, /await onProjectRefresh\(\)/);
    // inline success flash, no toast usage
    assert.match(src, /data-testid="name-flash"/);
    assert.doesNotMatch(src, /addToast/);

    // logic simulation: dirty gate + refresh called after PATCH
    let patched: string | null = null;
    let refreshed = 0;
    const project = { name: 'Old Name' };
    const nameDraft = 'New Name';
    const nameDirty = nameDraft.trim() !== project.name && nameDraft.trim().length >= 2;
    assert.ok(nameDirty);
    const saveName = async () => {
      if (!nameDirty) return;
      patched = nameDraft.trim();
      await onProjectRefresh();
    };
    const onProjectRefresh = async () => {
      refreshed += 1;
    };
    await saveName();
    assert.strictEqual(patched, 'New Name');
    assert.strictEqual(refreshed, 1);
  });

  // Check 2: copy buttons flash "Copied"
  it('2 copy: clipboard write + Copied flash for project id and slug', async () => {
    const src = fs.readFileSync(generalPath, 'utf8');
    assert.match(src, /copy\('id', project\.id\)/);
    assert.match(src, /copy\('slug', project\.slug\)/);
    assert.match(src, /navigator\.clipboard\.writeText\(text\)/);
    assert.match(src, /\{copied \? 'Copied' : 'Copy'\}/);

    // logic simulation: flash key set then cleared by timer
    let copiedKey: string | null = null;
    const copy = (key: string) => {
      copiedKey = key;
    };
    copy('id');
    assert.strictEqual(copiedKey, 'id');
    copiedKey = null; // timer expiry
    assert.strictEqual(copiedKey, null);
  });

  // Check 3: YOU badge, owner-locked role, non-admin renders zero controls
  it('3 roles: YOU badge + owner locked; non-admin view has no edit/invite/delete controls', () => {
    const src = fs.readFileSync(generalPath, 'utf8');
    // YOU badge on current user's row
    assert.match(src, /const isYou = m\.user_id === user\?\.id;/);
    assert.match(src, /data-testid="you-badge"/);
    // owner row locked (plain role text, no select/remove)
    assert.match(src, /const ownerLocked = org \? m\.user_id === org\.owner_id : false;/);
    assert.match(src, /\{isAdmin && !ownerLocked \? \(/);
    // role change + remove are admin-only, owner excluded
    assert.match(src, /data-testid=\{`role-select-\$\{m\.user_id\}`\}/);
    assert.match(src, /data-testid=\{`remove-member-\$\{m\.user_id\}`\}/);
    // Manage members + invite modal admin-only
    assert.match(src, /\{isAdmin && \(\s*<button[\s\S]{0,220}?data-testid="manage-members-btn"/);
    // Delete card hidden for non-admins
    assert.match(src, /\{isAdmin && \(\s*<section[\s\S]{0,160}?data-testid="general-delete-card"/);
    // Non-admin name is plain text (no input), zero save button for them
    assert.match(src, /data-testid="project-name-plain"/);
    // Save/name input live inside the isAdmin branch only
    const adminBranch = src.match(/\{isAdmin \? \(\s*<div className="flex flex-wrap items-center gap-2">[\s\S]*?\) : \(/);
    assert.ok(adminBranch, 'name input must be inside the isAdmin branch');
    assert.match(adminBranch[0], /data-testid="project-name-input"/);
  });

  // Check 4: invite modal adds row; duplicate (409) shows inline error
  it('4 invite: POST members appends row; 409 error renders inline in modal', async () => {
    const src = fs.readFileSync(generalPath, 'utf8');
    assert.match(src, /data-testid="invite-email-input"/);
    assert.match(src, /data-testid="invite-role-select"/);
    assert.match(src, /orgApi\.addMember\(orgId, inviteEmail\.trim\(\), inviteRole\)/);
    assert.match(src, /setMembers\(\(rows\) => \[\.\.\.rows, added\]\)/);
    assert.match(src, /data-testid="invite-error"/);
    // api method hits the members endpoint
    const api = fs.readFileSync(apiPath, 'utf8');
    assert.match(api, /async addMember\(orgId: string, email: string, role: string\)/);

    // logic simulation: first invite succeeds, duplicate 409 surfaces inline
    const rows: { user_id: string }[] = [{ user_id: 'u1' }];
    const addMember = async (email: string) => {
      if (email === 'dup@x.test') throw new ApiError('User is already a member of this organization', 409);
      const added = { user_id: 'u2' };
      rows.push(added);
      return added;
    };
    let modalError: string | null = null;
    await addMember('new@x.test').then((added) => rows.push(added)).catch((e) => { modalError = e.message; });
    assert.strictEqual(rows.length, 3);
    try {
      await addMember('dup@x.test');
    } catch (e: any) {
      modalError = (e as ApiError).message;
    }
    assert.match(modalError!, /already a member/);
  });

  // Check 5: remove member drops the row after confirm
  it('5 remove: confirm modal -> DELETE -> row removed', async () => {
    const src = fs.readFileSync(generalPath, 'utf8');
    assert.match(src, /data-testid="confirm-remove-btn"/);
    assert.match(src, /orgApi\.removeMember\(orgId, removeTarget\.id\)/);
    assert.match(src, /setMembers\(\(rows\) => rows\.filter\(\(r\) => r\.id !== removeTarget\.id\)\)/);
    const api = fs.readFileSync(apiPath, 'utf8');
    assert.match(api, /async removeMember\(orgId: string, memberId: string\)/);

    // logic simulation
    let deletedId: string | null = null;
    let rows = [{ id: 'm1' }, { id: 'm2' }];
    const removeTarget = rows[0];
    const removeMember = async (id: string) => {
      deletedId = id;
    };
    await removeMember(removeTarget.id);
    rows = rows.filter((r) => r.id !== removeTarget.id);
    assert.strictEqual(deletedId, 'm1');
    assert.strictEqual(rows.length, 1);
  });

  // Check 6: delete project — wrong name disabled/409 inline, correct name navigates
  it('6 delete: exact-name gate, 409 inline error, success navigates to projects', async () => {
    const src = fs.readFileSync(generalPath, 'utf8');
    // Danger banner copy
    assert.match(src, /Deleting this project permanently removes its events, API keys, and project\s+settings\. The organization and its members are not affected\./);
    assert.match(src, /data-testid="delete-confirm-input"/);
    assert.match(src, /disabled=\{deleting \|\| deleteConfirm !== project\.name\}/);
    assert.match(src, /orgApi\.deleteProject\(orgId, project\.id, deleteConfirm\)/);
    assert.match(src, /data-testid="delete-error"/);
    assert.match(src, /navigate\(`\/org\/\$\{orgId\}\/projects`\)/);
    const api = fs.readFileSync(apiPath, 'utf8');
    assert.match(api, /async deleteProject\(orgId: string, projectId: string, confirmName: string\)/);

    // logic simulation: wrong name -> backend 409 -> inline; correct -> navigate
    const project = { id: 'p1', name: 'Scratch' };
    let navigated: string | null = null;
    let lastError: string | null = null;
    const deleteProject = async (_org: string, id: string, confirmName: string) => {
      if (confirmName !== project.name) throw new ApiError('confirm_name does not match the project name', 409);
      if (id !== project.id) throw new Error('not found');
    };
    const confirmDelete = async (typed: string) => {
      lastError = null;
      try {
        await deleteProject('org1', project.id, typed);
        navigated = '/org/org1/projects';
      } catch (e: any) {
        lastError = (e as ApiError).message;
      }
    };
    await confirmDelete('Wrong');
    assert.match(lastError!, /does not match/);
    assert.strictEqual(navigated, null);
    await confirmDelete('Scratch');
    assert.strictEqual(navigated, '/org/org1/projects');
    assert.strictEqual(lastError, null);
  });
});
