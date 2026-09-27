/*
 * EXT-P1 Check 4 — refresh scheduling on a fake clock + refresh token
 * exchange against a stubbed Supabase endpoint.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'auth.js'), 'utf8'), { filename: 'lib/auth.js' });
const { refreshDelayMs, isExpired, refreshTokens, isRefreshTerminal, AUTH_EXPIRY_MARGIN_S } = globalThis.CyberGuardExt;

test('4.1 refresh fires exactly expires_at - 60s on a fake clock', () => {
  const nowMs = 1_700_000_000_000;
  const nowSec = Math.floor(nowMs / 1000);
  const auth = { expires_at: nowSec + 3600 };
  assert.equal(refreshDelayMs(auth, nowMs), (3600 - AUTH_EXPIRY_MARGIN_S) * 1000);
});

test('4.2 inside the margin / past expiry schedules immediately (never negative)', () => {
  const nowMs = 1_700_000_000_000;
  const nowSec = Math.floor(nowMs / 1000);
  assert.equal(refreshDelayMs({ expires_at: nowSec + 30 }, nowMs), 0, '30s left < 60s margin');
  assert.equal(refreshDelayMs({ expires_at: nowSec - 500 }, nowMs), 0, 'already expired');
  assert.equal(refreshDelayMs({ expires_at: nowSec + AUTH_EXPIRY_MARGIN_S + 1 }, nowMs), 1000);
  assert.equal(refreshDelayMs(null, nowMs), 0);
});

test('4.3 isExpired honours the 60s pre-expiry margin', () => {
  const nowSec = 1_700_000_000;
  assert.equal(isExpired({ expires_at: nowSec + 3600 }, nowSec), false);
  assert.equal(isExpired({ expires_at: nowSec + 60 }, nowSec), true, 'boundary is inside margin');
  assert.equal(isExpired({ expires_at: nowSec + 61 }, nowSec), false);
  assert.equal(isExpired(null, nowSec), true);
});

test('4.4 refreshTokens exchanges the refresh token via the Supabase endpoint', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      json: async () => ({
        access_token: 'new-at',
        refresh_token: 'new-rt',
        expires_at: 4102444800,
      }),
    };
  };
  const next = await refreshTokens({
    refreshToken: 'old-rt',
    supabaseUrl: 'https://sb.example.com',
    anonKey: 'anon',
    email: 'u@x.io',
    fetchImpl,
  });
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /^https:\/\/sb\.example\.com\/auth\/v1\/token\?grant_type=refresh_token$/);
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(JSON.parse(calls[0].init.body).refresh_token, 'old-rt');
  assert.equal(calls[0].init.headers.apikey, 'anon');
  assert.deepEqual(next, {
    access_token: 'new-at',
    refresh_token: 'new-rt',
    expires_at: 4102444800,
    email: 'u@x.io',
  });
});

test('4.5 terminal refresh failures (400/401/403) vs transient (5xx/network)', async () => {
  const fail = (status) => async () => ({ ok: false, status, json: async () => ({}) });
  for (const status of [400, 401, 403]) {
    await assert.rejects(
      refreshTokens({ refreshToken: 'rt', supabaseUrl: 'https://sb', anonKey: 'k', fetchImpl: fail(status) }),
      (err) => err.status === status
    );
    assert.equal(isRefreshTerminal(status), true, `${status} is terminal`);
  }
  assert.equal(isRefreshTerminal(500), false);
  assert.equal(isRefreshTerminal(503), false);
  await assert.rejects(
    refreshTokens({ refreshToken: null, supabaseUrl: 'https://sb', anonKey: 'k' }),
    /missing refreshToken/
  );
});
