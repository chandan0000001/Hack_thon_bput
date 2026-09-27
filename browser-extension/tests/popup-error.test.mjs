/*
 * EXT-P2 Check 13 — error banner renders on a mock 500: the scan machine
 * lands on 'error' and the failure message carries the HTTP status.
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

test('13 mock 500 -> error scan state with a banner message (no auth loss)', async () => {
  apiClient.configure({
    getAuth: async () => ({ access_token: 'tok' }),
    refresh: async () => null,
    signOut: async () => {
      throw new Error('sign-out must NOT run on a 500');
    },
    fetchImpl: async () => ({ ok: false, status: 500, json: async () => ({ detail: 'boom' }) }),
  });

  let bannerMessage = '';
  let scan = 'idle';
  try {
    scan = nextScan(scan, 'SCAN_START');
    await apiClient.analyzeUrl('http://api', 'https://x.example');
    assert.fail('500 must reject');
  } catch (err) {
    scan = nextScan(scan, 'SCAN_FAIL');
    bannerMessage = err.message; // popup.js puts this into #url-error
  }

  assert.equal(scan, 'error', 'scan state is error -> banner visible');
  assert.match(bannerMessage, /HTTP 500/, 'banner carries the HTTP status');
});
