/*
 * EXT-P1 Check 5 — callback content-script path gate: EXACT /ext/callback
 * only. /ext/callback2, sub-paths, and any other path must be rejected; the
 * bridge forwards the raw hash exactly once the fragment appears.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

// Path gate for 5.1 (loaded standalone, no browser globals needed).
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'path-gate.js'), 'utf8'), { filename: 'path-gate.js' });

function loadWithEnv({ pathname, hash = '' }) {
  const sent = [];
  delete globalThis.chrome;
  delete globalThis.browser;
  globalThis.CyberGuardExt = undefined;
  vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'path-gate.js'), 'utf8'), { filename: 'path-gate.js' });
  globalThis.location = { pathname, hash };
  globalThis.window = { close: () => {} };
  globalThis.chrome = {
    runtime: {
      lastError: null,
      sendMessage: (msg, cb) => {
        sent.push(msg);
        cb && cb({ ok: true });
      },
      onMessage: { addListener: () => {} },
    },
  };
  vm.runInThisContext(readFileSync(join(ROOT, 'content', 'callback-bridge.js'), 'utf8'), {
    filename: 'callback-bridge.js',
  });
  return { sent, location: globalThis.location };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The bridge polls on a 100ms interval (10s deadline); tests stop the poll
// explicitly so the node process does not linger.
function stopPoll() {
  if (globalThis.__cgCallbackPollTimer) clearInterval(globalThis.__cgCallbackPollTimer);
}

test('5.1 gate regex: exact path accepted, lookalikes rejected', () => {
  const { isCallbackPath } = globalThis.CyberGuardExt;
  assert.equal(isCallbackPath('/ext/callback'), true);
  for (const bad of ['/ext/callback2', '/ext/callback/extra', '/ext/callbackX', '/EXT/callback', '//evil/ext/callback', '', '/']) {
    assert.equal(isCallbackPath(bad), false, `rejected: ${JSON.stringify(bad)}`);
  }
});

test('5.2 bridge is inert on /ext/callback2 (no message ever sent)', async () => {
  const { sent } = loadWithEnv({ pathname: '/ext/callback2', hash: '#access_token=evil' });
  await sleep(250);
  assert.equal(sent.length, 0, 'no EXT_AUTH message from a lookalike path');
  stopPoll();
});

test('5.3 bridge forwards the raw fragment on the exact path once it appears', async () => {
  const { sent, location } = loadWithEnv({ pathname: '/ext/callback', hash: '' });
  await sleep(250);
  assert.equal(sent.length, 0, 'nothing forwarded before the page writes the fragment');
  location.hash = '#access_token=at&refresh_token=rt&expires_at=4102444800&state=n1';
  await sleep(250);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, 'EXT_AUTH');
  assert.equal(sent[0].hash.startsWith('#access_token=at&'), true);
  stopPoll();
});

test('5.4 SPA transition: document opens on /ext/auth, client-side route to /ext/callback forwards', async () => {
  // The website is an SPA: no new document load on route change, so the
  // bridge must track pathname transitions (while gated to the exact path).
  const { sent, location } = loadWithEnv({ pathname: '/ext/auth', hash: '' });
  await sleep(200);
  assert.equal(sent.length, 0, 'inert on /ext/auth');
  // SPA route change: same document, new pathname + hash handoff
  location.pathname = '/ext/callback';
  location.hash = '#access_token=spa-at&refresh_token=rt&expires_at=4102444800&state=n2';
  await sleep(250);
  assert.equal(sent.length, 1, 'forwards after the SPA transition');
  assert.equal(sent[0].hash.startsWith('#access_token=spa-at&'), true);
  stopPoll();
});
