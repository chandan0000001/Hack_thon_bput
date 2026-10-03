/*
 * CyberGuard extension — browser namespace adapter.
 *
 * One source must run on both Chromium (globalThis.chrome, callback-style)
 * and Firefox (globalThis.browser, promise-style). This module resolves the
 * namespace once and exposes a uniform promise-based surface. Callback-style
 * APIs are wrapped; promise-style APIs still accept callbacks, so the same
 * wrapper works for both (webextension-polyfill semantics).
 */
(function (global) {
  'use strict';

  function callbackToPromise(fn, args) {
    return new Promise((resolve, reject) => {
      let done = false;
      try {
        fn(...args, (result) => {
          if (done) return;
          done = true;
          const lastError = (global.chrome && global.chrome.runtime && global.chrome.runtime.lastError) ||
            (global.browser && global.browser.runtime && global.browser.runtime.lastError);
          if (lastError) reject(new Error(lastError.message));
          else resolve(result);
        });
      } catch (err) {
        if (!done) {
          done = true;
          reject(err);
        }
      }
    });
  }

  function storageArea(raw, area) {
    const impl = raw.storage[area];
    return {
      get: (keys) => callbackToPromise(impl.get.bind(impl), [keys]),
      set: (items) => callbackToPromise(impl.set.bind(impl), [items]),
      remove: (keys) => callbackToPromise(impl.remove.bind(impl), [keys]),
    };
  }

  function createAdapter(raw) {
    if (!raw || !raw.runtime || !raw.storage) {
      throw new Error('CyberGuard extension: no usable extension API namespace (browser/chrome)');
    }
    return {
      raw,
      namespace: global.browser ? 'browser' : 'chrome',
      storage: {
        local: storageArea(raw, 'local'),
        session: storageArea(raw, 'session'),
      },
      tabs: {
        create: (options) => callbackToPromise(raw.tabs.create.bind(raw.tabs), [options]),
        remove: (tabId) => callbackToPromise(raw.tabs.remove.bind(raw.tabs), [tabId]),
        get: (tabId) => callbackToPromise(raw.tabs.get.bind(raw.tabs), [tabId]),
        // MV3 service worker: register the listener directly (like onMessage) —
        // wrapping onUpdated in a promise makes no sense for an event stream.
        onUpdated: raw.tabs && raw.tabs.onUpdated ? raw.tabs.onUpdated : null,
        onRemoved: raw.tabs && raw.tabs.onRemoved ? raw.tabs.onRemoved : null,
      },
      action: (raw.action || raw.browserAction)
        ? {
            setBadgeText: (details) => callbackToPromise((raw.action || raw.browserAction).setBadgeText.bind(raw.action || raw.browserAction), [details]),
            setBadgeBackgroundColor: (details) => callbackToPromise((raw.action || raw.browserAction).setBadgeBackgroundColor.bind(raw.action || raw.browserAction), [details]),
            setTitle: (details) => callbackToPromise((raw.action || raw.browserAction).setTitle.bind(raw.action || raw.browserAction), [details]),
          }
        : null,
      runtime: {
        sendMessage: (message) => callbackToPromise(raw.runtime.sendMessage.bind(raw.runtime), [message]),
        onMessage: raw.runtime.onMessage,
      },
      alarms: raw.alarms
        ? {
            create: (name, info) => raw.alarms.create(name, info),
            clear: (name) => raw.alarms.clear(name),
            onAlarm: raw.alarms.onAlarm,
          }
        : null,
    };
  }

  const api = createAdapter(global.browser ?? global.chrome);

  global.CyberGuardExt = global.CyberGuardExt || {};
  global.CyberGuardExt.api = api;
  global.CyberGuardExt.createAdapter = createAdapter;
})(globalThis);
