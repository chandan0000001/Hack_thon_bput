/*
 * EXT-P1 Check 2 — fragment parse: valid / mismatch / missing.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'auth.js'), 'utf8'), { filename: 'lib/auth.js' });
const { parseFragment, stateMatches } = globalThis.CyberGuardExt;

const VALID = '#access_token=abc&refresh_token=def&expires_at=4102444800&state=nonce-123';

test('2.1 valid fragment parses into the auth handoff shape', () => {
  const res = parseFragment(VALID);
  assert.equal(res.ok, true);
  assert.deepEqual(res.value, {
    access_token: 'abc',
    refresh_token: 'def',
    expires_at: 4102444800,
    state: 'nonce-123',
  });
});

test('2.2 valid fragment without leading hash also parses', () => {
  const res = parseFragment(VALID.slice(1));
  assert.equal(res.ok, true);
  assert.equal(res.value.access_token, 'abc');
});

test('2.3 missing fragments rejected', () => {
  for (const hash of ['', '#', undefined, null]) {
    const res = parseFragment(hash);
    assert.equal(res.ok, false, `missing: ${JSON.stringify(hash)}`);
    assert.equal(res.reason, 'missing');
  }
});

test('2.4 invalid fragments rejected (bad token / bad expiry / missing state)', () => {
  const cases = [
    '#access_token=&refresh_token=def&expires_at=100&state=s', // empty access token
    '#access_token=abc&expires_at=100&state=s', // missing refresh token
    '#access_token=abc&refresh_token=def&expires_at=NaN&state=s', // bad expiry
    '#access_token=abc&refresh_token=def&expires_at=0&state=s', // zero expiry
    '#access_token=abc&refresh_token=def&expires_at=100', // missing state
    '#garbage-nothing-here',
  ];
  for (const hash of cases) {
    const res = parseFragment(hash);
    assert.equal(res.ok, false, `invalid: ${hash}`);
    assert.equal(res.reason, 'invalid');
  }
});

test('2.5 state matching: non-empty strings, exact equality', () => {
  assert.equal(stateMatches('nonce-123', 'nonce-123'), true);
  assert.equal(stateMatches('', ''), false, 'empty expected state never matches');
  assert.equal(stateMatches(undefined, 'nonce-123'), false);
  assert.equal(stateMatches('nonce-123', 'nonce-124'), false);
  assert.equal(stateMatches('nonce-123 ', 'nonce-123'), false, 'no implicit trimming');
});
