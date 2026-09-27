/*
 * EXT-P1 Check 6 — popup state machine (pure reducer transitions).
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'auth.js'), 'utf8'), { filename: 'lib/auth.js' });
const { nextPopupState } = globalThis.CyberGuardExt;

test('6.1 boot path: BOOT -> loading', () => {
  assert.equal(nextPopupState('signed-out', 'BOOT'), 'loading');
});

test('6.2 signed-out paths: no tokens or dead refresh token', () => {
  assert.equal(nextPopupState('loading', 'NO_TOKENS'), 'signed-out');
  assert.equal(nextPopupState('loading', 'REFRESH_FAIL'), 'signed-out');
  assert.equal(nextPopupState('refreshing', 'REFRESH_FAIL'), 'signed-out');
  assert.equal(nextPopupState('authenticated', 'SIGNOUT'), 'signed-out');
});

test('6.3 authenticated paths: live token or successful refresh', () => {
  assert.equal(nextPopupState('loading', 'TOKENS_VALID'), 'authenticated');
  assert.equal(nextPopupState('refreshing', 'REFRESH_OK'), 'authenticated');
  assert.equal(nextPopupState('authenticated', 'REFRESH_OK'), 'authenticated');
});

test('6.4 fatal -> error', () => {
  assert.equal(nextPopupState('loading', 'FATAL'), 'error');
  assert.equal(nextPopupState('authenticated', 'FATAL'), 'error');
});

test('6.5 unknown events are no-ops (state preserved)', () => {
  assert.equal(nextPopupState('authenticated', 'SOMETHING_ELSE'), 'authenticated');
  assert.equal(nextPopupState('signed-out', undefined), 'signed-out');
});

test('6.6 full happy-path walkthrough', () => {
  let s = 'signed-out';
  s = nextPopupState(s, 'BOOT');
  assert.equal(s, 'loading');
  s = nextPopupState(s, 'TOKENS_VALID');
  assert.equal(s, 'authenticated');
  s = nextPopupState(s, 'SIGNOUT');
  assert.equal(s, 'signed-out');
});

test('6.7 full recovery-path walkthrough: expired token -> refresh fails -> sign-in', () => {
  let s = 'signed-out';
  s = nextPopupState(s, 'BOOT');
  s = nextPopupState(s, 'REFRESH_FAIL');
  assert.equal(s, 'signed-out', 'dead refresh token lands back on sign-in');
});
