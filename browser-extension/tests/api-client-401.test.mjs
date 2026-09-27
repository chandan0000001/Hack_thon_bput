/*
 * EXT-P2 Check 9 — API client 401 handling: refresh once and retry; if the
 * refresh fails, clear the session (sign-out) and throw AuthLostError.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'api-client.js'), 'utf8'), { filename: 'api-client.js' });
const { apiClient } = globalThis.CyberGuardExt;

const jsonRes = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});

test('9 401 -> refresh + retry; failed refresh -> sign-out + AuthLostError', async () => {
  // Phase 1: 401 then success after refresh — retry carries the fresh token.
  const calls = [];
  let signOuts = 0;
  apiClient.configure({
    getAuth: async () => ({ access_token: 'stale', refresh_token: 'rt' }),
    refresh: async () => ({ access_token: 'fresh', refresh_token: 'rt2' }),
    signOut: async () => { signOuts += 1; },
    fetchImpl: async (url, init) => {
      calls.push(init.headers.Authorization);
      return jsonRes({ ok: true }, calls.length === 1 ? 401 : 200);
    },
  });
  const res = await apiClient.analyzeUrl('http://api', 'https://x.example');
  assert.equal(res.ok, true);
  assert.deepEqual(calls, ['Bearer stale', 'Bearer fresh'], 'retry uses the refreshed token');
  assert.equal(signOuts, 0, 'session survives a successful refresh');

  // Phase 2: refresh fails -> sign-out called, AuthLostError, no infinite loop.
  apiClient.configure({
    getAuth: async () => ({ access_token: 'stale', refresh_token: 'dead' }),
    refresh: async () => null,
    signOut: async () => { signOuts += 1; },
    fetchImpl: async () => jsonRes({}, 401),
  });
  await assert.rejects(
    apiClient.analyzeEmail('http://api', 'hello'),
    (err) => err.authLost === true && /refresh failed/.test(err.message)
  );
  assert.equal(signOuts, 1);

  // Phase 3: non-401 errors do NOT touch the session.
  apiClient.configure({
    getAuth: async () => ({ access_token: 'tok' }),
    refresh: async () => null,
    signOut: async () => { signOuts += 1; },
    fetchImpl: async () => jsonRes({ detail: 'boom' }, 500),
  });
  await assert.rejects(apiClient.analyzeUrl('http://api', 'https://x'), (e) => e.status === 500 && !e.authLost);
  assert.equal(signOuts, 1, 'sign-out count unchanged');
});
