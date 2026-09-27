/*
 * EXT-P1 Check 1 — nonce single-use (background auth handoff).
 *
 * Loads background.js in a fresh Node VM context per scenario (with a
 * chrome-API stub and an importScripts shim) and drives the real
 * EXT_AUTH_START / EXT_AUTH handlers: a nonce must authenticate exactly one
 * fragment handoff — replays and state mismatches are rejected.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

function makeStorageArea() {
  const map = new Map();
  // Callback-style, like the real chrome.* APIs the adapter wraps.
  return {
    get: (keys, cb) => {
      const out = {};
      for (const k of [].concat(keys)) if (map.has(k)) out[k] = map.get(k);
      cb(out);
    },
    set: (items, cb) => {
      for (const [k, v] of Object.entries(items)) map.set(k, v);
      cb && cb();
    },
    remove: (keys, cb) => {
      for (const k of [].concat(keys)) map.delete(k);
      cb && cb();
    },
  };
}

function loadBackground(cfg) {
  // Fresh vm context per scenario: background.js has top-level consts, so
  // reloading it in the shared global lexical scope would collide.
  const created = [];
  const removed = [];
  const alarms = [];
  const storageLocal = makeStorageArea();
  const storageSession = makeStorageArea();
  const chromeStub = {
    __created: created,
    __removed: removed,
    __alarms: alarms,
    __storageLocal: storageLocal,
    __storageSession: storageSession,
    runtime: {
      lastError: null,
      sendMessage: (msg, cb) => cb && cb({ ok: true }),
      onMessage: { addListener: () => {} },
    },
    storage: { local: storageLocal, session: storageSession },
    tabs: {
      create: (opts, cb) => {
        created.push(opts);
        cb({ id: created.length });
      },
      remove: (id, cb) => {
        removed.push(id);
        cb && cb();
      },
    },
    alarms: {
      create: (name, info) => alarms.push({ name, info }),
      clear: () => true,
      onAlarm: { addListener: () => {} },
    },
  };
  const sandbox = {
    URLSearchParams,
    URL,
    crypto: globalThis.crypto,
    setTimeout,
    console,
    globalThis: null, // wired below
    EXT_CONFIG: cfg,
    chrome: chromeStub,
    browser: undefined,
    importScripts: (...files) => {
      for (const file of files) {
        if (file === 'config.js') continue; // generated at build time; EXT_CONFIG injected above
        vm.runInContext(readFileSync(join(ROOT, file), 'utf8'), ctx, { filename: file });
      }
    },
  };
  sandbox.globalThis = sandbox;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(readFileSync(join(ROOT, 'background.js'), 'utf8'), ctx, { filename: 'background.js' });
  return { bg: sandbox.CyberGuardBackground, chrome: chromeStub };
}

const storageGet = (area, key) => new Promise((resolve) => area.get(key, resolve));

function fragmentFor(state) {
  const params = new URLSearchParams({
    access_token: 'at-' + state.slice(0, 8),
    refresh_token: 'rt-' + state.slice(0, 8),
    expires_at: String(Math.floor(Date.now() / 1000) + 3600),
    state,
  });
  return { hash: '#' + params.toString(), state };
}

const CFG = { WEB_ORIGIN: 'http://localhost:5173', API_BASE_URL: 'http://localhost:8000/api/v1' };

test('1.1 EXT_AUTH_START mints a nonce and the matching handoff authenticates', async () => {
  const { bg, chrome } = loadBackground(CFG);
  const start = await bg.startAuth();
  assert.ok(start.ok && start.nonce.length >= 16, 'startAuth returns a nonce');
  const frag = fragmentFor(start.nonce);
  const res = await bg.handleExtAuth({ type: 'EXT_AUTH', hash: frag.hash }, { tab: { id: 42 } });
  assert.equal(res.ok, true, 'matching state authenticates');
  const stored = await storageGet(chrome.__storageLocal, 'extAuth');
  assert.ok(stored.extAuth, 'auth object persisted to storage.local');
  assert.ok(stored.extAuth.access_token.startsWith('at-'), 'access token persisted');
  assert.ok(stored.extAuth.refresh_token.startsWith('rt-'), 'refresh token persisted');
  assert.ok(chrome.__removed.includes(42), 'callback tab is closed');
  assert.ok(chrome.__alarms.some((a) => a.name === 'extAuthRefresh'), 'refresh alarm armed');
});

test('1.2 nonce is single-use: replay of the SAME valid fragment is rejected', async () => {
  const { bg, chrome } = loadBackground(CFG);
  const { nonce } = await bg.startAuth();
  const frag = fragmentFor(nonce);
  const first = await bg.handleExtAuth({ hash: frag.hash }, { tab: { id: 1 } });
  assert.equal(first.ok, true);
  const replay = await bg.handleExtAuth({ hash: frag.hash }, { tab: { id: 2 } });
  assert.equal(replay.ok, false);
  assert.equal(replay.error, 'no_pending_auth', 'nonce consumed before validation');
  assert.ok(!chrome.__removed.includes(2), 'replay tab not closed');
});

test('1.3 fragment state not matching the pending nonce is rejected', async () => {
  const { bg } = loadBackground(CFG);
  await bg.startAuth();
  const evil = fragmentFor('00000000-0000-0000-0000-000000000000');
  const res = await bg.handleExtAuth({ hash: evil.hash }, { tab: { id: 3 } });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'state_mismatch');
});

test('1.4 handoff without a pending pre-flight is rejected', async () => {
  const { bg } = loadBackground(CFG);
  const frag = fragmentFor('no-preflight-nonce');
  const res = await bg.handleExtAuth({ hash: frag.hash }, { tab: { id: 4 } });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'no_pending_auth');
});

test('1.5 malformed fragments are rejected with a reason', async () => {
  for (const hash of ['', '#', '#access_token=only']) {
    const { bg } = loadBackground(CFG);
    await bg.startAuth(); // fresh nonce per case: the nonce is single-use even on failure
    const res = await bg.handleExtAuth({ hash }, { tab: { id: 5 } });
    assert.equal(res.ok, false, `rejected: ${JSON.stringify(hash)}`);
    assert.match(res.error, /^bad_fragment:(missing|invalid)$/);
  }
});
