/*
 * EXT-P3 Check 21 — messaging round-trip: content ANALYZE_BATCH ->
 * background api-client calls -> BATCH_RESULTS payload.
 *
 * Loads the real background.js in a VM (chrome stub + importScripts shim)
 * and drives the registered onMessage listener end-to-end.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

const ALERT = (score, sev) => ({ risk_score: score, severity: sev, indicators: [] });

function loadBackground() {
  const messageListeners = [];
  const storageLocal = makeStorage();
  const storageSession = makeStorage();
  const tabsCreated = [];
  const openPopupCalls = [];
  const chromeStub = {
    runtime: {
      lastError: null,
      onMessage: { addListener: (fn) => messageListeners.push(fn) },
      getURL: (path) => `chrome-extension://testid/${path}`,
    },
    storage: { local: storageLocal, session: storageSession },
    tabs: { create: (opts, cb) => { tabsCreated.push(opts); cb && cb({ id: 1 }); } },
    alarms: { create: () => {}, clear: () => true, onAlarm: { addListener: () => {} } },
    action: { openPopup: async () => { openPopupCalls.push(1); return; } },
  };
  const sandbox = {
    URLSearchParams, URL, crypto: globalThis.crypto, setTimeout, console,
    fetch: globalThis.fetch, FormData: class { constructor() { this.entries = []; } append(k, v) { this.entries.push([k, v]); } get(k) { const e = this.entries.find(([key]) => key === k); return e && e[1]; } },
    Blob: globalThis.Blob, atob: globalThis.atob,
    globalThis: null,
    EXT_CONFIG: { WEB_ORIGIN: 'http://localhost:5173', API_BASE_URL: 'http://api', SUPABASE_URL: '', SUPABASE_ANON_KEY: '' },
    chrome: chromeStub,
    browser: undefined,
    importScripts: (...files) => {
      for (const f of files) {
        if (f === 'config.js') continue;
        vm.runInContext(readFileSync(join(ROOT, f), 'utf8'), ctx, { filename: f });
      }
    },
  };
  sandbox.globalThis = sandbox;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(readFileSync(join(ROOT, 'background.js'), 'utf8'), ctx, { filename: 'background.js' });

  // Stub the API surface the batch handler calls (mimics backend responses).
  const calls = [];
  sandbox.CyberGuardExt.apiClient.configure({
    getAuth: async () => ({ access_token: 'tok', refresh_token: 'rt' }),
    refresh: async () => null,
    signOut: async () => {},
    fetchImpl: async (url) => {
      calls.push(url);
      const body = url.endsWith('/analysis/url')
        ? { risk_score: 88, severity: 'high' }
        : url.endsWith('/analysis/email')
          ? { risk_score: 61, severity: 'medium' }
          : { manipulation_probability: 0.9, severity: 'critical', method: 'cnn' };
      return { ok: true, status: 200, json: async () => body };
    },
  });

  return { listeners: messageListeners, tabsCreated, openPopupCalls, calls, chromeStub };
}

function makeStorage() {
  const map = new Map();
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

function send(listeners, msg, sender = {}) {
  return new Promise((resolve) => {
    for (const fn of listeners) fn(msg, sender, resolve);
  });
}

test('21 ANALYZE_BATCH round-trip: content -> background -> aggregated BATCH_RESULTS', async () => {
  const bg = loadBackground();
  assert.equal(bg.listeners.length, 1, 'background registered its message listener');

  const res = await send(bg.listeners, {
    type: 'ANALYZE_BATCH',
    urls: ['https://a.example/1', 'https://b.example/2'],
    emails: ['From: x@evil.example\n\nphishing body'],
    images: [{ src: 'https://site.example/pic.jpg', dataUrl: null }], // not fetchable -> error card
  });

  assert.equal(res.ok, true);
  assert.equal(res.results.length, 4, '2 urls + 1 email + 1 image');
  const urls = res.results.filter((r) => r.kind === 'url');
  assert.ok(urls.every((r) => r.ok && r.data.risk_score === 88), 'URL results carry AlertResponse data');
  assert.ok(bg.calls.every((u) => u.startsWith('http://api/analysis/')), 'api client hit the analyzer endpoints');
  const email = res.results.find((r) => r.kind === 'email');
  assert.equal(email.ok, true);
  assert.equal(email.data.severity, 'medium');
  const image = res.results.find((r) => r.kind === 'image');
  assert.equal(image.ok, false, 'image without dataUrl degrades to an error card');
  assert.match(image.error, /not fetchable/);

  // OPEN_URL_VIEW opens the popup page in a tab with the URL pre-filled.
  const viaTab = await send(bg.listeners, { type: 'OPEN_URL_VIEW', url: 'https://evil.example/login' });
  assert.equal(viaTab.ok, true);
  assert.equal(viaTab.via, 'tab');
  const tab = bg.tabsCreated[0];
  assert.match(tab.url, /^chrome-extension:\/\/testid\/popup\/popup\.html\?view=url&url=https%3A%2F%2Fevil\.example%2Flogin$/);

  // Non-http payloads are refused.
  const bad = await send(bg.listeners, { type: 'OPEN_URL_VIEW', url: 'javascript:alert(1)' });
  assert.equal(bad.ok, false);
});
