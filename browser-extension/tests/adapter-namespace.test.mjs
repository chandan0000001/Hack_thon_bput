/*
 * EXT-P1 Check 3 — adapter namespace fallback: chrome-only and browser-only
 * globals must both yield a working promise-based adapter.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ADAPTER = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'lib', 'browser-adapter.js');

function loadAdapterFresh() {
  delete globalThis.CyberGuardExt;
  vm.runInThisContext(readFileSync(ADAPTER, 'utf8'), { filename: 'browser-adapter.js' });
  return globalThis.CyberGuardExt.api;
}

function chromeStub() {
  const store = new Map();
  return {
    runtime: {
      lastError: null,
      sendMessage: (msg, cb) => cb({ ok: true, echo: msg }),
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: {
        get: (keys, cb) => cb(Object.fromEntries([].concat(keys).flatMap((k) => (store.has(k) ? [[k, store.get(k)]] : [])))),
        set: (items, cb) => {
          for (const [k, v] of Object.entries(items)) store.set(k, v);
          cb && cb();
        },
        remove: (keys, cb) => {
          for (const k of [].concat(keys)) store.delete(k);
          cb && cb();
        },
      },
    },
    tabs: { create: (opts, cb) => cb({ id: 7, ...opts }) },
  };
}

test('3.1 chrome-only global: adapter resolves chrome, promises wrap callbacks', async () => {
  delete globalThis.browser;
  globalThis.chrome = chromeStub();
  const api = loadAdapterFresh();
  assert.equal(api.namespace, 'chrome');
  await api.storage.local.set({ k: 'v' });
  const got = await api.storage.local.get('k');
  assert.deepEqual(got, { k: 'v' });
  await api.storage.local.remove('k');
  assert.deepEqual(await api.storage.local.get('k'), {});
  const tab = await api.tabs.create({ url: 'http://x' });
  assert.equal(tab.id, 7);
  const res = await api.runtime.sendMessage({ type: 'PING' });
  assert.equal(res.echo.type, 'PING');
});

test('3.2 browser-only global (Firefox): adapter resolves browser', async () => {
  delete globalThis.chrome;
  // Firefox supports the callback form too, which is what the adapter uses.
  globalThis.browser = {
    runtime: {
      sendMessage: (msg, cb) => {
        if (typeof cb === 'function') cb({ ok: true, echo: msg });
        return Promise.resolve({ ok: true, echo: msg });
      },
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: {
        get: (keys, cb) => {
          const out = Object.fromEntries([].concat(keys).map((k) => [k, 'v']));
          cb && cb(out);
          return Promise.resolve(out);
        },
        set: (items, cb) => {
          cb && cb();
          return Promise.resolve();
        },
        remove: (keys, cb) => {
          cb && cb();
          return Promise.resolve();
        },
      },
    },
    tabs: {
      create: (opts, cb) => {
        const tab = { id: 9, ...opts };
        cb && cb(tab);
        return Promise.resolve(tab);
      },
    },
  };
  const api = loadAdapterFresh();
  assert.equal(api.namespace, 'browser');
  const got = await api.storage.local.get('k');
  assert.deepEqual(got, { k: 'v' });
  const tab = await api.tabs.create({ url: 'http://y' });
  assert.equal(tab.id, 9);
  const res = await api.runtime.sendMessage({ type: 'PING' });
  assert.equal(res.echo.type, 'PING');
});

test('3.3 neither namespace: adapter construction fails loudly', () => {
  delete globalThis.chrome;
  delete globalThis.browser;
  assert.throws(() => loadAdapterFresh(), /no usable extension API namespace/);
});
