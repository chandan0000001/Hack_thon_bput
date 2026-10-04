/*
 * EXT-SCANNER-V2 S7 Tests:
 * 1. Guard: mock onBeforeNavigate -> malicious verdict -> tabs.update to blocked.html (assert URL params)
 * 2. Guard: safe verdict -> no redirect
 * 3. Guard: allowlisted -> skipped
 * 4. Guard: redirect chain second hop also checked
 * 5. Interstitial: renders reason/indicators
 * 6. Interstitial: Continue anyway -> allowlist set + navigate; Go back
 * 7. State machine: mutation during analyzing does NOT reset (requestId preserved, +n badge after)
 * 8. Dedup: same image twice -> one backend call
 * 9. Lock: locked -> observer callback no-op; unlock -> resumes
 * 10. Pill v2: expand shows rows with checkboxes; analyze selected sends only checked
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { JSDOM } from 'jsdom';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

function makeStorage(initial = {}) {
  const store = { ...initial };
  return {
    get: (keys, cb) => {
      if (typeof keys === 'string') {
        const res = { [keys]: store[keys] };
        return cb ? cb(res) : Promise.resolve(res);
      }
      if (Array.isArray(keys)) {
        const res = {};
        for (const k of keys) res[k] = store[k];
        return cb ? cb(res) : Promise.resolve(res);
      }
      if (typeof keys === 'object' && keys !== null) {
        const res = { ...keys };
        for (const k of Object.keys(keys)) {
          if (store[k] !== undefined) res[k] = store[k];
        }
        return cb ? cb(res) : Promise.resolve(res);
      }
      const res = { ...store };
      return cb ? cb(res) : Promise.resolve(res);
    },
    set: (items, cb) => {
      Object.assign(store, items);
      return cb ? cb() : Promise.resolve();
    },
    remove: (keys, cb) => {
      const arr = Array.isArray(keys) ? keys : [keys];
      for (const k of arr) delete store[k];
      return cb ? cb() : Promise.resolve();
    },
    _raw: store,
  };
}

function createBackgroundContext(apiClientMocks = {}) {
  const tabsUpdated = [];
  const tabsCreated = [];
  const storageLocal = makeStorage();
  const storageSession = makeStorage();

  const chromeStub = {
    runtime: {
      lastError: null,
      onMessage: { addListener: () => {} },
      getURL: (path) => `chrome-extension://testid/${path}`,
      sendMessage: () => {},
    },
    storage: { local: storageLocal, session: storageSession },
    tabs: {
      update: (tabId, opts, cb) => {
        tabsUpdated.push({ tabId, opts });
        if (cb) cb({ id: tabId, ...opts });
        return Promise.resolve({ id: tabId, ...opts });
      },
      create: (opts, cb) => {
        tabsCreated.push(opts);
        if (cb) cb({ id: 99 });
        return Promise.resolve({ id: 99 });
      },
      get: (tabId, cb) => {
        const res = { id: tabId };
        if (cb) cb(res);
        return Promise.resolve(res);
      },
      onUpdated: { addListener: () => {} },
      onRemoved: { addListener: () => {} },
    },
    action: {
      setBadgeText: () => Promise.resolve(),
      setBadgeBackgroundColor: () => Promise.resolve(),
      setTitle: () => Promise.resolve(),
    },
    alarms: { create: () => {}, clear: () => true, onAlarm: { addListener: () => {} } },
    webNavigation: {
      onBeforeNavigate: { addListener: () => {} },
      onCompleted: { addListener: () => {} },
    },
  };

  const sandbox = {
    URLSearchParams, URL, crypto: globalThis.crypto, setTimeout, clearTimeout, console,
    fetch: globalThis.fetch,
    FormData: class { constructor() {} append() {} },
    Blob: globalThis.Blob,
    globalThis: null,
    EXT_CONFIG: {
      WEB_ORIGIN: 'http://localhost:5173',
      API_BASE_URL: 'http://api',
      SUPABASE_URL: '',
      SUPABASE_ANON_KEY: '',
    },
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

  // Prevent background refresh timers from keeping node test runner open
  sandbox.CyberGuardBackground.scheduleRefresh = () => {};
  storageLocal.set({
    extAuth: { access_token: 'valid-token', refresh_token: 'rt' },
    autoBlockNavigation: true,
  });

  // Mock apiClient
  sandbox.CyberGuardExt.apiClient.configure({
    getAuth: async () => ({ access_token: 'valid-token', refresh_token: 'rt' }),
    refresh: async () => null,
    signOut: async () => {},
  });

  if (apiClientMocks.analyzeUrl) {
    sandbox.CyberGuardExt.apiClient.analyzeUrl = apiClientMocks.analyzeUrl;
  }

  return { ctx, sandbox, chromeStub, tabsUpdated };
}

// -----------------------------------------------------------------------------
// S1 Navigation Guard Tests
// -----------------------------------------------------------------------------

test('22.1 guard: mock onBeforeNavigate -> malicious verdict -> tabs.update to blocked.html (assert URL params)', async () => {
  const { sandbox, tabsUpdated } = createBackgroundContext({
    analyzeUrl: async (baseUrl, url) => ({
      risk_score: 94,
      severity: 'critical',
      recommended_action: 'block',
      explanation: 'Known phishing threat.',
      indicators: [{ description: 'Credential harvester target', type: 'credential_harvesting' }],
    }),
  });

  const { handleBeforeNavigate } = sandbox.CyberGuardBackground;
  await handleBeforeNavigate({ tabId: 10, url: 'https://evil.phish.test/login', frameId: 0 });

  assert.equal(tabsUpdated.length, 1, 'tabs.update must be called once');
  assert.equal(tabsUpdated[0].tabId, 10);
  const target = tabsUpdated[0].opts.url;
  assert.ok(target.includes('blocked.html'), 'url points to blocked.html');

  const u = new URL(target, 'chrome-extension://testid');
  assert.equal(u.searchParams.get('url'), 'https://evil.phish.test/login');
  assert.equal(u.searchParams.get('reason'), 'Credential harvester target');
  assert.equal(u.searchParams.get('score'), '94');
  assert.equal(u.searchParams.get('severity'), 'critical');
  const inds = JSON.parse(u.searchParams.get('indicators'));
  assert.equal(inds.length, 1);
  assert.equal(inds[0].description, 'Credential harvester target');
});

test('22.2 guard: safe verdict -> no redirect', async () => {
  const { sandbox, tabsUpdated } = createBackgroundContext({
    analyzeUrl: async () => ({
      risk_score: 15,
      severity: 'low',
      recommended_action: 'pass',
      indicators: [],
    }),
  });

  const { handleBeforeNavigate } = sandbox.CyberGuardBackground;
  await handleBeforeNavigate({ tabId: 11, url: 'https://safe.example/docs', frameId: 0 });

  assert.equal(tabsUpdated.length, 0, 'safe navigation must not redirect');
});

test('22.3 guard: allowlisted -> skipped without analysis', async () => {
  let apiCalled = false;
  const { sandbox, tabsUpdated } = createBackgroundContext({
    analyzeUrl: async () => {
      apiCalled = true;
      return { risk_score: 99, severity: 'critical', recommended_action: 'block' };
    },
  });

  const { handleBeforeNavigate, setNavAllowlist } = sandbox.CyberGuardBackground;
  setNavAllowlist('https://allowlisted.example/page');

  await handleBeforeNavigate({ tabId: 12, url: 'https://allowlisted.example/page', frameId: 0 });

  assert.equal(apiCalled, false, 'allowlisted URL should not call backend');
  assert.equal(tabsUpdated.length, 0, 'allowlisted URL should not redirect');
});

test('22.4 guard: redirect chain second hop also checked', async () => {
  const verdicts = {
    'https://short.example/hop1': { risk_score: 10, severity: 'low', recommended_action: 'pass', indicators: [] },
    'https://phish.example/final': { risk_score: 89, severity: 'high', recommended_action: 'quarantine', indicators: [{ description: 'Open redirect landing' }] },
  };

  const { sandbox, tabsUpdated } = createBackgroundContext({
    analyzeUrl: async (baseUrl, url) => verdicts[url] || { risk_score: 0, recommended_action: 'pass' },
  });

  const { handleBeforeNavigate } = sandbox.CyberGuardBackground;

  // Hop 1 (direct nav to shortener): safe
  await handleBeforeNavigate({ tabId: 15, url: 'https://short.example/hop1', frameId: 0 });
  assert.equal(tabsUpdated.length, 0, 'hop 1 should pass');

  // Hop 2 (redirect to malicious target): blocked
  await handleBeforeNavigate({ tabId: 15, url: 'https://phish.example/final', frameId: 0 });
  assert.equal(tabsUpdated.length, 1, 'hop 2 must be blocked');
  assert.equal(tabsUpdated[0].tabId, 15);
  assert.ok(tabsUpdated[0].opts.url.includes('url=https%3A%2F%2Fphish.example%2Ffinal'));
});

// -----------------------------------------------------------------------------
// S2 Interstitial Page Tests
// -----------------------------------------------------------------------------

test('22.5 interstitial: renders reason, indicators, score, and target URL', () => {
  const html = readFileSync(join(ROOT, 'blocked.html'), 'utf8');
  const dom = new JSDOM(html, {
    url: 'chrome-extension://testid/blocked.html?url=https%3A%2F%2Fbad.example%2Fphish&reason=Phishing+kit+detected&score=85&severity=critical&indicators=%5B%7B%22description%22%3A%22Fake+SSO%22%7D%2C%7B%22description%22%3A%22Homoglyph+domain%22%7D%5D',
  });

  new Function('global', readFileSync(join(ROOT, 'blocked.js'), 'utf8'))(dom.window);
  dom.window.CyberGuardBlocked.init(dom.window.document);

  const doc = dom.window.document;
  assert.equal(doc.getElementById('cg-target-url').textContent, 'https://bad.example/phish');
  assert.equal(doc.getElementById('cg-reason').textContent, 'Phishing kit detected');
  assert.equal(doc.getElementById('cg-score').textContent, '85');
  assert.equal(doc.getElementById('cg-severity').textContent, 'CRITICAL');

  const indItems = doc.querySelectorAll('#cg-indicators li');
  assert.equal(indItems.length, 2);
  assert.equal(indItems[0].textContent, 'Fake SSO');
  assert.equal(indItems[1].textContent, 'Homoglyph domain');
});

test('22.6 interstitial: Continue anyway -> allowlist set + navigate; Go back', async () => {
  const html = readFileSync(join(ROOT, 'blocked.html'), 'utf8');
  const dom = new JSDOM(html, {
    url: 'chrome-extension://testid/blocked.html?url=https%3A%2F%2Fbad.example%2Flogin',
  });

  const sessionStore = {};
  let replacedWith = null;
  let backCalls = [];
  let wentTo = null;

  const mockWin = {
    document: dom.window.document,
    history: {
      length: 3,
      back: () => { backCalls.push('back'); },
      go: (delta) => { backCalls.push(`go:${delta}`); },
    },
    location: {
      search: '?url=https%3A%2F%2Fbad.example%2Flogin',
      replace: (url) => { replacedWith = url; },
      href: '',
    },
    chrome: {
      storage: {
        session: {
          get: (keys, cb) => cb({ navAllowlist: sessionStore }),
          set: (items, cb) => { Object.assign(sessionStore, items.navAllowlist || {}); cb && cb(); },
        },
      },
      runtime: { sendMessage: () => {} },
    },
  };

  new Function('global', readFileSync(join(ROOT, 'blocked.js'), 'utf8'))(mockWin);
  const { continueAnyway, goBack } = mockWin.CyberGuardBlocked;

  // Continue anyway
  await continueAnyway('https://bad.example/login', mockWin);
  assert.ok(sessionStore['https://bad.example/login'] > Date.now(), 'session allowlist must have URL');
  assert.equal(replacedWith, 'https://bad.example/login', 'must navigate to original URL');

  // Go back must SKIP the blocked target entry (session history is
  // […, target, blockedPage]; a single back() re-lands on the target and
  // the guard re-blocks it — infinite loop).
  goBack(mockWin);
  assert.deepEqual(backCalls, ['go:-2'], 'must history.go(-2) past the blocked target');

  // Blocked target was the first entry in the tab -> leave history entirely
  const shallowWin = { ...mockWin, history: { length: 2, back: () => {}, go: () => {} } };
  new Function('global', readFileSync(join(ROOT, 'blocked.js'), 'utf8'))(shallowWin);
  replacedWith = null;
  shallowWin.CyberGuardBlocked.goBack(shallowWin);
  assert.equal(replacedWith, 'about:blank', 'must leave history when target was the first entry');
});

// -----------------------------------------------------------------------------
// S5 State Machine & In-Flight Persistence Tests
// -----------------------------------------------------------------------------

test('22.7 state machine: mutation during analyzing does NOT reset (requestId preserved, +n badge after)', async () => {
  const dom = new JSDOM(`<!doctype html><html><body>
    <img src="https://example.com/img1.png" width="300" height="300">
  </body></html>`, { url: 'https://example.com/page' });

  dom.window.fetch = async () => { throw new Error('offline'); };
  new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
  dom.window.CyberGuardExt = { detect: globalThis.CyberGuardExt.detect };
  new Function('global', readFileSync(join(ROOT, 'content', 'pill.js'), 'utf8'))(dom.window);

  let batchResolve;
  const batchPromise = new Promise((resolve) => { batchResolve = resolve; });

  dom.window.chrome = {
    runtime: {
      sendMessage: (msg, cb) => {
        batchPromise.then((res) => cb(res));
      },
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: { get: (k, cb) => cb({}), set: (k, cb) => cb && cb() },
      onChanged: { addListener: () => {} },
    },
  };

  new Function('global', readFileSync(join(ROOT, 'content', 'scanner.js'), 'utf8'))(dom.window);
  const { CyberGuardScanner } = dom.window;

  // Initial scan sets awaiting
  CyberGuardScanner.scan();
  assert.equal(CyberGuardScanner.getState(), 'awaiting');

  // Trigger analysis
  const analyzeJob = CyberGuardScanner.handleAnalyze();
  assert.equal(CyberGuardScanner.getState(), 'analyzing');
  const reqId = CyberGuardScanner.getCurrentRequestId();
  assert.ok(reqId && reqId.startsWith('req_'));

  // Mutation while analyzing: append another image
  const img2 = dom.window.document.createElement('img');
  img2.src = 'https://example.com/img2.png';
  img2.width = 300;
  img2.height = 300;
  dom.window.document.body.appendChild(img2);

  // Trigger observer callback
  CyberGuardScanner.scheduleScan();

  // State must NOT reset to idle, requestId preserved
  assert.equal(CyberGuardScanner.getState(), 'analyzing');
  assert.equal(CyberGuardScanner.getCurrentRequestId(), reqId);
  assert.equal(CyberGuardScanner.getQueuedNewDetections().length, 1);

  // Finish analysis
  batchResolve({
    ok: true,
    results: [{ kind: 'image', ok: true, data: { manipulation_probability: 0.1, severity: 'low' } }],
  });
  await analyzeJob;

  assert.equal(CyberGuardScanner.getState(), 'results');
  const badge = dom.window.document.querySelector('#cgext-pill .cgext-pill__badge');
  assert.ok(badge && !badge.hidden, 'badge must be visible');
  assert.equal(badge.textContent, '+1 new');
  CyberGuardScanner.cancelBatcher();
});

// -----------------------------------------------------------------------------
// S5 Dedup Cache Test
// -----------------------------------------------------------------------------

test('22.8 dedup: same image twice -> one backend call', async () => {
  const dom = new JSDOM(`<!doctype html><html><body>
    <img src="https://example.com/photo.png" width="300" height="300">
  </body></html>`, { url: 'https://example.com/page' });

  dom.window.fetch = async () => { throw new Error('offline'); };
  new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
  dom.window.CyberGuardExt = { detect: globalThis.CyberGuardExt.detect };
  new Function('global', readFileSync(join(ROOT, 'content', 'pill.js'), 'utf8'))(dom.window);

  let backendCalls = 0;
  dom.window.chrome = {
    runtime: {
      sendMessage: (msg, cb) => {
        if (msg.type === 'ANALYZE_BATCH') backendCalls++;
        cb({ ok: true, results: [{ kind: 'image', ok: true, data: { risk_score: 80, severity: 'high' } }] });
      },
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: { get: (k, cb) => cb({}) },
      onChanged: { addListener: () => {} },
    },
  };

  new Function('global', readFileSync(join(ROOT, 'content', 'scanner.js'), 'utf8'))(dom.window);
  const { CyberGuardScanner } = dom.window;

  // First analysis
  const item = CyberGuardScanner.scanDetections()[0];
  const res1 = await CyberGuardScanner.handleAnalyze([item]);
  assert.equal(backendCalls, 1, 'first call hits backend');
  assert.equal(res1.results.length, 1);

  // Second analysis of same item
  const res2 = await CyberGuardScanner.handleAnalyze([item]);
  assert.equal(backendCalls, 1, 'second call must hit dedup cache (0 extra backend calls)');
  assert.equal(res2.results.length, 1);
  CyberGuardScanner.cancelBatcher();
});

// -----------------------------------------------------------------------------
// S6 Lock Control Test
// -----------------------------------------------------------------------------

test('22.9 lock: locked -> observer callback no-op; unlock -> resumes', () => {
  const dom = new JSDOM(`<!doctype html><html><body>
    <img src="https://example.com/first.png" width="250" height="250">
  </body></html>`, { url: 'https://example.com/lock-test' });

  new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
  dom.window.CyberGuardExt = { detect: globalThis.CyberGuardExt.detect };
  new Function('global', readFileSync(join(ROOT, 'content', 'pill.js'), 'utf8'))(dom.window);
  dom.window.chrome = {
    runtime: { onMessage: { addListener: () => {} } },
    storage: { local: { get: (k, cb) => cb({}) }, onChanged: { addListener: () => {} } },
  };

  new Function('global', readFileSync(join(ROOT, 'content', 'scanner.js'), 'utf8'))(dom.window);
  const { CyberGuardScanner } = dom.window;

  CyberGuardScanner.scan();
  const initialItems = CyberGuardScanner.scanDetections();
  assert.equal(initialItems.length, 1);

  // Lock
  CyberGuardScanner.setLocked(true);
  assert.equal(CyberGuardScanner.isLocked(), true);
  const pill = dom.window.document.getElementById('cgext-pill');
  assert.ok(pill.classList.contains('cgext-pill--locked'));

  // Mutate DOM
  const img2 = dom.window.document.createElement('img');
  img2.src = 'https://example.com/locked-out.png';
  img2.width = 300;
  img2.height = 300;
  dom.window.document.body.appendChild(img2);

  // When locked, scheduleScan is no-op
  CyberGuardScanner.scheduleScan();
  // Pill counts unchanged
  const pillText = dom.window.document.querySelector('#cgext-pill .cgext-pill__text').textContent;
  assert.match(pillText, /1 image/);

  // Unlock
  CyberGuardScanner.setLocked(false);
  assert.equal(CyberGuardScanner.isLocked(), false);
  assert.ok(!pill.classList.contains('cgext-pill--locked'));

  // Schedule scan now runs
  CyberGuardScanner.scan();
  const updatedText = dom.window.document.querySelector('#cgext-pill .cgext-pill__text').textContent;
  assert.match(updatedText, /2 images/);
  CyberGuardScanner.setLocked(true);
  CyberGuardScanner.cancelBatcher();
});

// -----------------------------------------------------------------------------
// S4 Pill V2 Clarity + Control Test
// -----------------------------------------------------------------------------

test('22.10 pill v2: expand shows rows with checkboxes; analyze selected sends only checked', async () => {
  const dom = new JSDOM(`<!doctype html><html><body></body></html>`, { url: 'https://example.com/' });
  dom.window.CyberGuardExt = {};
  new Function('global', readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))(dom.window);
  new Function('global', readFileSync(join(ROOT, 'content', 'pill.js'), 'utf8'))(dom.window);

  const { pillUi } = dom.window.CyberGuardExt;
  let sentItems = null;
  pillUi.init({
    onAnalyze: async (selected) => {
      sentItems = selected;
      return { ok: true, results: [] };
    },
  });

  pillUi.setItems([
    { id: 'item-1', kind: 'image', value: 'https://cdn.example/banner.png', locationHint: 'Hero banner', checked: true },
    { id: 'item-2', kind: 'email', value: 'Hello, please verify your credentials at http://phish', locationHint: 'Email body', checked: true },
  ]);

  // Expand panel
  pillUi.expand();
  const pill = dom.window.document.getElementById('cgext-pill');
  assert.ok(pill.classList.contains('cgext-pill--expanded'));

  const rows = pill.querySelectorAll('.cgext-pill__row');
  assert.equal(rows.length, 2, 'two rows rendered');

  // Uncheck item-2
  const check2 = rows[1].querySelector('.cgext-pill__checkbox');
  check2.checked = false;
  check2.dispatchEvent(new dom.window.Event('change'));

  // Check footer button text
  const btnSel = pill.querySelector('.cgext-pill__btn-analyze-selected');
  assert.equal(btnSel.textContent, 'Analyze selected (1)');

  // Click analyze selected
  btnSel.dispatchEvent(new dom.window.Event('click'));
  assert.ok(sentItems, 'onAnalyze was invoked');
  assert.equal(sentItems.length, 1, 'only 1 item sent');
  assert.equal(sentItems[0].id, 'item-1', 'only checked item was analyzed');
});

// -----------------------------------------------------------------------------
// Navigation Guard: search-engine results pages are exempt
// -----------------------------------------------------------------------------

test('22.11 guard: google/bing/ddg SERP URLs are never auto-blocked (query words are not destinations)', async () => {
  let analyzed = 0;
  const { sandbox, tabsUpdated } = createBackgroundContext({
    analyzeUrl: async () => {
      analyzed++;
      return { risk_score: 99, severity: 'critical', recommended_action: 'block', indicators: [] };
    },
  });
  const { handleBeforeNavigate, isSearchResultsPageExempt } = sandbox.CyberGuardBackground;
  assert.equal(typeof isSearchResultsPageExempt, 'function', 'background exports SERP exemption helper');

  const serps = [
    'https://www.google.com/search?q=googke&oq=googke+&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTITCAEQABiDARixAxiABBiKBT&sourceid=chrome&ie=UTF-8',
    'https://www.google.co.in/search?q=cheap+meds',
    'https://www.bing.com/search?q=googke&form=QBLH',
    'https://duckduckgo.com/?q=googke',
    'https://search.yahoo.com/search?p=googke',
    'https://search.brave.com/search?q=googke',
  ];
  for (const url of serps) {
    await handleBeforeNavigate({ tabId: 1, url, frameId: 0 });
    assert.ok(isSearchResultsPageExempt(url), `exempt: ${url}`);
  }
  assert.equal(analyzed, 0, 'no SERP URL may hit the analyzer');
  assert.equal(tabsUpdated.length, 0, 'no SERP URL may be blocked');

  // A look-alike destination is still guarded
  await handleBeforeNavigate({ tabId: 1, url: 'https://goggle.com/search?q=x', frameId: 0 });
  assert.equal(analyzed, 1, 'non-exempt URL still analyzed');
});

test('22.12 detect.isSearchResultsPage: engines, paths, and non-engine hosts', async () => {
  const { isSearchResultsPage } = globalThis.CyberGuardExt.detect;
  assert.equal(isSearchResultsPage('https://www.google.com/search?q=x'), true);
  assert.equal(isSearchResultsPage('https://google.co.uk/search?q=x'), true);
  assert.equal(isSearchResultsPage('https://www.bing.com/search?q=x'), true);
  assert.equal(isSearchResultsPage('https://duckduckgo.com/?q=x'), true);
  assert.equal(isSearchResultsPage('https://lite.duckduckgo.com/lite?q=x'), true);
  assert.equal(isSearchResultsPage('https://www.baidu.com/s?wd=x'), true);
  assert.equal(isSearchResultsPage('https://www.ecosia.org/search?q=x'), true);
  assert.equal(isSearchResultsPage('https://www.startpage.com/sp/search?query=x'), true);
  // Not SERPs
  assert.equal(isSearchResultsPage('https://goggle.com/search?q=x'), false, 'look-alike host is guarded');
  assert.equal(isSearchResultsPage('https://evil.test/search?q=x'), false, 'unknown host is guarded');
  assert.equal(isSearchResultsPage('https://www.google.com/mail/u/0'), false, 'non-search path is guarded');
  assert.equal(isSearchResultsPage('https://www.google.com/'), false, 'google homepage is guarded');
  assert.equal(isSearchResultsPage('not a url'), false);
});
