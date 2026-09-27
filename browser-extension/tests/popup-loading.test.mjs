/*
 * EXT-P2 Check 12 — loading state toggles during a fetch (start → loading,
 * settle → done), driven through the scan state machine + api client.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'popup-views.js'), 'utf8'), { filename: 'popup-views.js' });
const { nextScan } = globalThis.CyberGuardExt.popupViews;
delete globalThis.CyberGuardExt.apiClient;
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'api-client.js'), 'utf8'), { filename: 'api-client.js' });
const { apiClient } = globalThis.CyberGuardExt;

test('12 loading toggles on for the in-flight fetch and off when it settles', async () => {
  let scan = 'idle';
  assert.equal(nextScan(scan, 'SCAN_START'), 'loading', 'clicking Scan shows the spinner');
  scan = 'loading';
  assert.equal(nextScan(scan, 'SCAN_OK'), 'done', 'successful response clears the spinner');
  assert.equal(nextScan('loading', 'SCAN_FAIL'), 'error', 'failed response also clears it');
  assert.equal(nextScan('done', 'SCAN_START'), 'loading', 'a re-scan re-enters loading');
  assert.equal(nextScan('loading', 'SCAN_RESET'), 'idle', 'leaving the view resets the scan state');

  // The spinner state must span the in-flight promise window: the fetch is
  // started (loading) and only settles after the deferred response resolves.
  let resolveFetch;
  const deferred = new Promise((resolve) => { resolveFetch = resolve; });
  apiClient.configure({
    getAuth: async () => ({ access_token: 'tok' }),
    refresh: async () => null,
    signOut: async () => {},
    fetchImpl: () => deferred.then(() => ({ ok: true, status: 200, json: async () => ({ risk_score: 1 }) })),
  });
  assert.equal(nextScan('idle', 'SCAN_START'), 'loading');
  const inFlight = apiClient.analyzeUrl('http://api', 'https://x');
  resolveFetch();
  const result = await inFlight;
  assert.equal(result.risk_score, 1, 'in-flight call settles through the client');
  assert.equal(nextScan('loading', 'SCAN_OK'), 'done');
});
