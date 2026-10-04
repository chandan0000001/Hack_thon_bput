/*
 * CyberGuard extension — background (MV3 service worker on Chromium,
 * event page on Firefox — same classic script for both).
 *
 * Owns the universal auth flow:
 *   EXT_AUTH_START  — popup asks for a fresh single-use nonce (storage.session)
 *   EXT_AUTH        — /ext/callback content bridge hands over the fragment;
 *                     nonce verified single-use, tokens persisted to
 *                     storage.local, tab closed
 *   refresh         — alarm scheduled at expires_at - 60s via lib/auth.js
 *   EXT_AUTH_GET / EXT_AUTH_REFRESH / EXT_AUTH_SIGNOUT — popup helpers
 *
 * EXT-P3 batch analysis (content scanner):
 *   ANALYZE_BATCH   — content pill clicked; runs the three analyzers via
 *                     lib/api-client.js against the stored session and
 *                     returns {ok, results[]}
 *   OPEN_URL_VIEW   — overlay "Open in popup": action.openPopup() when the
 *                     browser allows it, else popup.html in a new tab with
 *                     ?view=url&url=… pre-fill
 *
 * Current-tab URL guard (Stage-1 fast path):
 *   tabs.onUpdated  — classifies the navigated URL automatically (http/https
 *                     only, browser-internal pages excluded). Results are
 *                     cached per URL (10-min TTL), deduplicated while in
 *                     flight, surfaced as a per-tab badge and stored in
 *                     storage.session. Opt-out: storage.local
 *                     { auto_scan_tab: false }.
 *   GET_TAB_SCAN_VERDICT — popup fetches the stored verdict for a tab
 *   SCAN_TAB_URL    — explicit on-demand scan of a given tab URL
 *
 * Tokens live only in storage.local (fragment handoff only, never query
 * strings, never server logs).
 */
/* global importScripts, crypto, FormData, Blob */
importScripts('config.js', 'lib/browser-adapter.js', 'lib/auth.js', 'lib/api-client.js', 'lib/detect.js');

const api = CyberGuardExt.api;
const CFG = globalThis.EXT_CONFIG;

const NONCE_KEY = 'extAuthNonce';
const AUTH_KEY = 'extAuth';
const REFRESH_ALARM = 'extAuthRefresh';

function randomNonce() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  (globalThis.crypto || {}).getRandomValues
    ? globalThis.crypto.getRandomValues(bytes)
    : bytes.forEach((_, i) => { bytes[i] = Math.floor(Math.random() * 256); });
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Popup clicked "Sign In": mint a single-use nonce for this pre-flight. */
async function startAuth() {
  const nonce = randomNonce();
  await api.storage.session.set({ [NONCE_KEY]: nonce });
  return { ok: true, nonce, webOrigin: CFG.WEB_ORIGIN, v: 1 };
}

/**
 * Content bridge handoff. msg = { type, hash } where hash is the raw
 * location.hash of ${WEB}/ext/callback.
 */
async function handleExtAuth(msg, sender) {
  const stored = await api.storage.session.get(NONCE_KEY);
  const expected = stored[NONCE_KEY];
  // Single-use: consume the nonce before validating so a replay — even of a
  // valid fragment — finds nothing to match.
  await api.storage.session.remove(NONCE_KEY);
  if (typeof expected !== 'string' || expected.length === 0) {
    return { ok: false, error: 'no_pending_auth' };
  }
  const parsed = CyberGuardExt.parseFragment(msg && msg.hash);
  if (!parsed.ok) {
    return { ok: false, error: `bad_fragment:${parsed.reason}` };
  }
  const frag = parsed.value;
  if (!CyberGuardExt.stateMatches(expected, frag.state)) {
    return { ok: false, error: 'state_mismatch' };
  }
  const auth = {
    access_token: frag.access_token,
    refresh_token: frag.refresh_token,
    expires_at: frag.expires_at,
    email: (msg && msg.email) || null,
  };
  await api.storage.local.set({ [AUTH_KEY]: auth });
  scheduleRefresh(auth);
  if (sender && sender.tab && sender.tab.id != null) {
    try { await api.tabs.remove(sender.tab.id); } catch (e) { /* tab may be gone */ }
  }
  return { ok: true };
}

async function getAuth() {
  const stored = await api.storage.local.get(AUTH_KEY);
  return stored[AUTH_KEY] || null;
}

async function signOut() {
  await api.storage.local.remove(AUTH_KEY);
  await api.storage.session.remove(NONCE_KEY);
  if (api.alarms) api.alarms.clear(REFRESH_ALARM);
  return { ok: true };
}

function scheduleRefresh(auth, minDelayMs = 0) {
  const delayMs = Math.max(minDelayMs, CyberGuardExt.refreshDelayMs(auth, Date.now()));
  if (api.alarms) {
    // Absolute `when` is the only alarm form accepted uniformly: some
    // Chromium builds throw on any delayMinutes value (schema invocation
    // error), while `when` works across Chromium and Firefox.
    api.alarms.create(REFRESH_ALARM, { when: Date.now() + Math.max(30000, delayMs) });
  } else {
    setTimeout(() => { doRefresh().catch(() => {}); }, delayMs);
  }
}

async function doRefresh() {
  const auth = await getAuth();
  if (!auth || !auth.refresh_token) return { ok: false, error: 'no_auth' };
  try {
    const next = await CyberGuardExt.refreshTokens({
      refreshToken: auth.refresh_token,
      supabaseUrl: CFG.SUPABASE_URL,
      anonKey: CFG.SUPABASE_ANON_KEY,
      email: auth.email,
    });
    await api.storage.local.set({ [AUTH_KEY]: next });
    scheduleRefresh(next);
    return { ok: true, auth: next };
  } catch (err) {
    if (CyberGuardExt.isRefreshTerminal(err.status)) {
      // Refresh token revoked/expired — drop the session (signed-out).
      await signOut();
      return { ok: false, error: 'session_expired' };
    }
    // Transient (network/5xx): retry later with the same token.
    scheduleRefresh(auth, CyberGuardExt.REFRESH_RETRY_MS);
    return { ok: false, error: 'retry_scheduled' };
  }
}

// --- EXT-P3: batch analysis --------------------------------------------------

// The api client in the worker context reads the session straight from
// storage.local and reuses the same refresh/sign-out flow as the popup.
CyberGuardExt.apiClient.configure({
  getAuth: async () => getAuth(),
  refresh: async () => {
    const res = await doRefresh();
    return res && res.ok ? res.auth : null;
  },
  signOut: async () => signOut(),
});

function dataUrlToBlob(dataUrl) {
  const [head, b64] = String(dataUrl).split(',');
  const mime = /:(.*?);/.exec(head);
  const bytes = atob(b64);
  const arr = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) arr[i] = bytes.charCodeAt(i);
  return new Blob([arr], { type: (mime && mime[1]) || 'application/octet-stream' });
}

async function analyzeBatch(msg) {
  const results = [];
  const jobs = [];
  for (const url of [].concat((msg && msg.urls) || [])) {
    jobs.push(
      CyberGuardExt.apiClient
        .analyzeUrl(CFG.API_BASE_URL, url)
        .then((data) => results.push({ kind: 'url', input: url, ok: true, data }))
        .catch((err) => results.push({ kind: 'url', input: url, ok: false, error: String((err && err.message) || err) }))
    );
  }
  for (const email of [].concat((msg && msg.emails) || [])) {
    jobs.push(
      CyberGuardExt.apiClient
        .analyzeEmail(CFG.API_BASE_URL, email)
        .then((data) => results.push({ kind: 'email', input: `${String(email).slice(0, 80)}…`, ok: true, data }))
        .catch((err) => results.push({ kind: 'email', input: `${String(email).slice(0, 80)}…`, ok: false, error: String((err && err.message) || err) }))
    );
  }
  for (const image of [].concat((msg && msg.images) || [])) {
    const input = (image && image.src) || 'image';
    jobs.push(
      (async () => {
        if (!image || !image.dataUrl) throw new Error('image not fetchable from page');
        const form = new FormData();
        form.append('file', dataUrlToBlob(image.dataUrl), 'detected-image');
        const data = await CyberGuardExt.apiClient.analyzeDeepfakeForm(CFG.API_BASE_URL, form);
        return results.push({ kind: 'image', input, ok: true, data });
      })().catch((err) => results.push({ kind: 'image', input, ok: false, error: String((err && err.message) || err) }))
    );
  }
  await Promise.all(jobs);
  return { ok: true, results };
}

// --- Current-tab URL guard (Stage-1 fast path) ------------------------------
//
// Automatically classifies the URL of the tab being navigated (independent of
// the page-content scanner, which still requires an explicit Analyze click).
// Design constraints:
//   * browser-internal pages (chrome://, about:, file://, extension stores,
//     non-http(s) schemes) are never analyzed — lib/detect.js isInternalUrl
//   * Stage-1 only: one POST /analysis/url per URL, no screenshots here
//   * results are cached per URL with a TTL and deduplicated while in flight,
//     so SPA hash-pushes and back/forward navigations do not spam the API
//   * a per-tab verdict is stored in storage.session for the popup; the badge
//     is set per tab (cleared on SAFE so normal browsing stays quiet)
//   * the whole path is opt-out via storage.local { auto_scan_tab: false }

const TAB_SCAN_KEY = 'tabScanVerdicts';
const TAB_URL_TTL_MS = 10 * 60 * 1000;
const BADGE_COLORS = {
  low: '#f59e0b',
  medium: '#f59e0b',
  high: '#dc2626',
  critical: '#dc2626',
};

const urlVerdictCache = new Map(); // url -> { at, verdict }
const inFlightScans = new Map();   // url -> Promise<verdict>

function normalizeCacheKey(url) {
  try {
    const u = new URL(url);
    u.hash = '';
    return u.href;
  } catch (e) {
    return String(url || '');
  }
}

async function autoScanEnabled() {
  try {
    const stored = await api.storage.local.get({ auto_scan_tab: true });
    return stored.auto_scan_tab !== false;
  } catch (e) {
    return true;
  }
}

async function setTabBadge(tabId, verdict) {
  if (!api.action) return;
  try {
    const sev = String((verdict && verdict.severity) || '').toLowerCase();
    if (!sev || sev === 'safe') {
      await api.action.setBadgeText({ text: '', tabId });
      return;
    }
    await api.action.setBadgeText({ text: '!', tabId });
    await api.action.setBadgeBackgroundColor({ color: BADGE_COLORS[sev] || '#f59e0b', tabId });
    await api.action.setTitle({ title: `CyberGuard: ${sev} risk on this page`, tabId });
  } catch (e) { /* tab may be gone; badge is best-effort */ }
}

async function storeTabVerdict(tabId, verdict) {
  try {
    const stored = await api.storage.session.get(TAB_SCAN_KEY);
    const all = stored[TAB_SCAN_KEY] || {};
    all[tabId] = { ...verdict, at: Date.now() };
    await api.storage.session.set({ [TAB_SCAN_KEY]: all });
  } catch (e) { /* storage.session unavailable (Firefox pre-128): badge only */ }
}

async function cachedVerdict(url) {
  const key = normalizeCacheKey(url);
  const hit = urlVerdictCache.get(key);
  if (hit && Date.now() - hit.at < TAB_URL_TTL_MS) return hit.verdict;
  return null;
}

async function analyzeCurrentTabUrl(tabId, url) {
  const key = normalizeCacheKey(url);
  const cached = await cachedVerdict(key);
  if (cached) {
    await setTabBadge(tabId, cached);
    await storeTabVerdict(tabId, { url: key, ...cached, cached: true });
    return cached;
  }
  if (inFlightScans.has(key)) {
    const verdict = await inFlightScans.get(key);
    await setTabBadge(tabId, verdict);
    return verdict;
  }
  const job = CyberGuardExt.apiClient
    .analyzeUrl(CFG.API_BASE_URL, url)
    .then((data) => {
      const verdict = {
        severity: (data && data.severity) || null,
        risk_score: (data && typeof data.risk_score === 'number') ? data.risk_score : null,
        ml_artifact: (data && data.ml_artifact) || null,
      };
      urlVerdictCache.set(key, { at: Date.now(), verdict });
      return verdict;
    })
    .catch((err) => ({
      severity: null,
      risk_score: null,
      error: String((err && err.message) || err),
    }))
    .finally(() => inFlightScans.delete(key));
  inFlightScans.set(key, job);
  const verdict = await job;
  await setTabBadge(tabId, verdict);
  await storeTabVerdict(tabId, { url: key, ...verdict });
  return verdict;
}

function clearTabScan(tabId) {
  if (api.action) {
    api.action.setBadgeText({ text: '', tabId }).catch(() => {});
  }
  api.storage.session.get(TAB_SCAN_KEY)
    .then((stored) => {
      const all = stored[TAB_SCAN_KEY] || {};
      if (all[tabId]) {
        delete all[tabId];
        return api.storage.session.set({ [TAB_SCAN_KEY]: all });
      }
      return undefined;
    })
    .catch(() => {});
}

// Stage-2 trigger: only for high/critical Stage-1 verdicts (the cascade
// contract — SAFE URLs never get screenshots taken). One attempt per tab+URL.
const stageTwoInFlight = new Set(); // `${tabId}:${url}`

async function captureVisible(tabId) {
  const tabs = api.raw && api.raw.tabs;
  if (!tabs || typeof tabs.captureVisibleTab !== 'function') return null;
  return new Promise((resolve) => {
    try {
      tabs.captureVisibleTab(tabId, { format: 'jpeg', quality: 70 }, (dataUrl) => {
        resolve((globalThis.chrome && globalThis.chrome.runtime.lastError) ? null : dataUrl);
      });
    } catch (e) {
      resolve(null);
    }
  });
}

// Block page: opened ONLY when the user opts in via
// { block_critical: true } (default false — fail-open by design; CyberGuard
// being wrong or offline must not brick browsing) AND the fused Stage-2
// verdict is BLOCK. See blocked/blocked.html for the evidence shown.
async function blockCriticalVerdictEnabled() {
  try {
    const stored = await api.storage.local.get({ block_critical: false });
    return stored.block_critical === true;
  } catch (e) {
    return false;
  }
}

async function maybeRunStageTwo(tabId, url, verdict) {
  const sev = String((verdict && verdict.severity) || '').toLowerCase();
  if (sev !== 'high' && sev !== 'critical') return;
  const key = `${tabId}:${normalizeCacheKey(url)}`;
  if (stageTwoInFlight.has(key)) return;
  stageTwoInFlight.add(key);
  try {
    const dataUrl = await captureVisible(tabId);
    if (!dataUrl) return; // capture blocked (permission/gesture) — Stage 1 stands
    const stage2 = await CyberGuardExt.apiClient.analyzeUrlVisual(CFG.API_BASE_URL, url, dataUrl);
    let fused = stage2;
    if (stage2 && stage2.job_id) {
      // Bounded polling: give the worker up to ~8s, then leave the job id.
      for (let i = 0; i < 4; i += 1) {
        await new Promise((r) => setTimeout(r, 2000));
        const poll = await CyberGuardExt.apiClient.getVisualResult(CFG.API_BASE_URL, stage2.job_id);
        if (poll && poll.status === 'done') { fused = poll.result; break; }
      }
    }
    if (fused && fused.fusion) {
      const fusedDecision = fused.fusion.decision;
      await storeTabVerdict(tabId, {
        url: normalizeCacheKey(url),
        severity: fusedDecision === 'block' ? 'critical' : verdict.severity,
        risk_score: fused.fusion.risk_score ?? verdict.risk_score,
        stage2: {
          decision: fusedDecision,
          brand: (fused.stage2 && fused.stage2.brand_detected) || null,
          reasons: (fused.fusion && fused.fusion.reasons) || [],
        },
      });
      if (fusedDecision === 'block') {
        await setTabBadge(tabId, { severity: 'critical' });
        if (await blockCriticalVerdictEnabled()) {
          const reasons = (fused.fusion.reasons || []).map(String);
          const getURL = api.raw.runtime && api.raw.runtime.getURL
            ? api.raw.runtime.getURL('blocked/blocked.html') : 'blocked/blocked.html';
          const blockedPage = `${getURL}?url=${encodeURIComponent(url)}`
            + `&score=${encodeURIComponent(fused.fusion.risk_score ?? '')}`
            + `&severity=${encodeURIComponent('critical')}`
            + `&reasons=${encodeURIComponent(JSON.stringify(reasons))}`
            + `&apiBase=${encodeURIComponent(CFG.API_BASE_URL)}`;
          try { await api.tabs.update(tabId, { url: blockedPage }); } catch (e) { /* tab gone */ }
        }
      }
    }
  } catch (e) {
    // Stage 2 is additive evidence; failures never break browsing.
  } finally {
    stageTwoInFlight.delete(key);
  }
}

// --- S1 Navigation Guard (chrome.webNavigation.onBeforeNavigate) ---
const navSessionAllowlist = new Map(); // url -> expiresAt
const inFlightNavigations = new Map(); // tabId -> navId

async function isAutoBlockNavigationEnabled() {
  try {
    const stored = await api.storage.local.get({ autoBlockNavigation: true });
    return stored.autoBlockNavigation !== false;
  } catch (e) {
    return true;
  }
}

async function isNavAllowlisted(url) {
  const now = Date.now();
  if (!url) return false;
  if (navSessionAllowlist.has(url) && navSessionAllowlist.get(url) > now) return true;
  try {
    const u = new URL(url);
    u.hash = '';
    if (navSessionAllowlist.has(u.href) && navSessionAllowlist.get(u.href) > now) return true;
  } catch (e) {}

  try {
    const stored = await api.storage.session.get({ navAllowlist: {} });
    const list = (stored && stored.navAllowlist) || {};
    if (list[url] && list[url] > now) {
      navSessionAllowlist.set(url, list[url]);
      return true;
    }
    const u = new URL(url);
    u.hash = '';
    if (list[u.href] && list[u.href] > now) {
      navSessionAllowlist.set(u.href, list[u.href]);
      return true;
    }
  } catch (e) {}

  return false;
}

function setNavAllowlist(url, ttlMs = 10 * 60 * 1000) {
  const expiresAt = Date.now() + ttlMs;
  navSessionAllowlist.set(url, expiresAt);
  try {
    const u = new URL(url);
    u.hash = '';
    navSessionAllowlist.set(u.href, expiresAt);
  } catch (e) {}
  api.storage.session.get({ navAllowlist: {} }).then((stored) => {
    const list = (stored && stored.navAllowlist) || {};
    list[url] = expiresAt;
    try {
      const u = new URL(url);
      u.hash = '';
      list[u.href] = expiresAt;
    } catch (e) {}
    return api.storage.session.set({ navAllowlist: list });
  }).catch(() => {});
}

function isWebOrigin(url) {
  try {
    const u = new URL(url);
    const orig = new URL(CFG.WEB_ORIGIN);
    return u.origin === orig.origin;
  } catch {
    return false;
  }
}

function isExtensionPage(url) {
  if (!url) return true;
  const s = String(url).toLowerCase();
  if (s.startsWith('chrome-extension://') || s.startsWith('moz-extension://') || s.startsWith('about:') || s.startsWith('chrome://') || s.startsWith('edge://')) {
    return true;
  }
  if (s.includes('blocked.html')) return true;
  return CyberGuardExt.detect ? CyberGuardExt.detect.isInternalUrl(url) : false;
}

async function handleBeforeNavigate(details) {
  if (!details || !details.url || (details.frameId != null && details.frameId !== 0)) return;
  const url = details.url;
  const tabId = details.tabId;

  // For each navigation in http/https tabs: skip if URL is in session allowlist, the web origin, or extension pages.
  if (!/^https?:\/\//i.test(url)) return;
  if (isExtensionPage(url)) return;
  if (isWebOrigin(url)) return;
  if (await isNavAllowlisted(url)) return;
  if (!(await isAutoBlockNavigationEnabled())) return;

  const auth = await getAuth();
  if (!auth || !auth.access_token) return; // fail-open

  const navId = (inFlightNavigations.get(tabId) || 0) + 1;
  inFlightNavigations.set(tabId, navId);

  try {
    const data = await CyberGuardExt.apiClient.analyzeUrl(CFG.API_BASE_URL, url);
    if (inFlightNavigations.get(tabId) !== navId) return;

    const riskScore = typeof data?.risk_score === 'number' ? data.risk_score : (typeof data?.score === 'number' ? data.score : null);
    const scoreFraction = riskScore != null ? (riskScore > 1 ? riskScore / 100 : riskScore) : 0;
    const recAction = String(data?.recommended_action || (
      scoreFraction >= 0.85 ? 'block' : scoreFraction >= 0.60 ? 'quarantine' : scoreFraction >= 0.30 ? 'notify' : 'pass'
    )).toLowerCase();

    // 4-tier matrix: if recommended_action is 'quarantine' or 'block' (score >= 0.60) -> AUTO-BLOCK
    if (recAction === 'quarantine' || recAction === 'block' || scoreFraction >= 0.60) {
      const reason = (data?.indicators && data.indicators[0] && (data.indicators[0].description || data.indicators[0].value))
        || data?.explanation
        || `High-risk URL detected (${recAction.toUpperCase()})`;
      const top3 = (data?.indicators || []).slice(0, 3);
      const enc = encodeURIComponent;
      const getURL = (api.raw && api.raw.runtime && api.raw.runtime.getURL)
        ? api.raw.runtime.getURL('blocked.html') : 'blocked.html';
      const blockedPage = `${getURL}?url=${enc(url)}`
        + `&reason=${enc(reason)}`
        + `&score=${enc(riskScore != null ? (riskScore <= 1 && riskScore > 0 ? Math.round(riskScore * 100) : Math.round(riskScore)) : Math.round(scoreFraction * 100))}`
        + `&severity=${enc(data?.severity || (scoreFraction >= 0.85 ? 'critical' : 'high'))}`
        + `&indicators=${enc(JSON.stringify(top3))}`;

      await api.tabs.update(tabId, { url: blockedPage });
    }
  } catch (err) {
    // Fail-open
  }
}

function handleNavCompleted(details) {
  if (details && (details.frameId == null || details.frameId === 0) && details.tabId != null) {
    inFlightNavigations.delete(details.tabId);
  }
}

function armNavigationGuard() {
  const wn = api.webNavigation || (api.raw && api.raw.webNavigation);
  if (!wn) return;
  if (wn.onBeforeNavigate && typeof wn.onBeforeNavigate.addListener === 'function') {
    wn.onBeforeNavigate.addListener((details) => {
      handleBeforeNavigate(details).catch(() => {});
    });
  }
  if (wn.onCompleted && typeof wn.onCompleted.addListener === 'function') {
    wn.onCompleted.addListener((details) => {
      handleNavCompleted(details);
    });
  }
}

armNavigationGuard();

// Drop per-tab pill-dismissal entries when the tab closes (session storage).
const tabsApi = api.tabs || (api.raw && api.raw.tabs);
if (tabsApi && tabsApi.onRemoved && typeof tabsApi.onRemoved.addListener === 'function') {
  tabsApi.onRemoved.addListener((tabId) => {
    (async () => {
      try {
        const { cg_pill_dismissed_tabs: set } = await api.storage.session.get('cg_pill_dismissed_tabs');
        if (set && Object.prototype.hasOwnProperty.call(set, String(tabId))) {
          const next = { ...set };
          delete next[String(tabId)];
          await api.storage.session.set({ cg_pill_dismissed_tabs: next });
        }
      } catch (e) { /* session storage unavailable */ }
    })();
  });
}

async function getTabScanVerdict(msg) {
  const tabId = msg && msg.tabId;
  try {
    const stored = await api.storage.session.get(TAB_SCAN_KEY);
    const all = stored[TAB_SCAN_KEY] || {};
    if (tabId != null && all[tabId]) return { ok: true, verdict: all[tabId] };
    if (tabId != null) return { ok: true, verdict: null };
  } catch (e) { /* fall through */ }
  return { ok: false, error: 'tab_verdict_unavailable' };
}

async function openUrlView(msg) {
  const url = String((msg && msg.url) || '');
  if (!/^https?:\/\//i.test(url)) return { ok: false, error: 'invalid url' };
  // action.openPopup() is gesture-gated and silently unreliable across
  // browsers, so the deterministic path is the popup page itself in a new
  // tab: ?view=url&url=… triggers the same pre-filled URL view (popup.js).
  const getURL = api.raw.runtime && api.raw.runtime.getURL
    ? api.raw.runtime.getURL('popup/popup.html')
    : 'popup/popup.html';
  await api.tabs.create({ url: `${getURL}?view=url&url=${encodeURIComponent(url)}` });
  return { ok: true, via: 'tab' };
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg && msg.type) {
      case 'EXT_AUTH_START':
        return startAuth();
      case 'EXT_AUTH':
        return handleExtAuth(msg, sender);
      case 'EXT_AUTH_GET': {
        const auth = await getAuth();
        return { ok: true, auth };
      }
      case 'EXT_AUTH_REFRESH':
        return doRefresh();
      case 'EXT_AUTH_SIGNOUT':
        return signOut();
      case 'ANALYZE_BATCH':
        return analyzeBatch(msg);
      case 'GET_TAB_SCAN_VERDICT':
        return getTabScanVerdict(msg);
      case 'SCAN_TAB_URL':
        // Explicit on-demand path (popup "check this page" button): same
        // pipeline as the automatic guard, ignoring the auto_scan_tab toggle.
        return (async () => {
          const tabId = msg.tabId;
          const url = msg.url;
          if (!url || CyberGuardExt.detect.isInternalUrl(url)) {
            return { ok: false, error: 'url_not_scannable' };
          }
          return { ok: true, verdict: await analyzeCurrentTabUrl(tabId, url) };
        })();
      case 'PILL_DISMISS': {
        // Sticky per-tab pill dismissal (scanner S6): survives reloads until
        // the popup auto-detect toggle flips (which clears the whole set).
        const tabId = sender && sender.tab && sender.tab.id;
        if (tabId != null) {
          try {
            const { cg_pill_dismissed_tabs: set } = await api.storage.session.get('cg_pill_dismissed_tabs');
            const next = set && typeof set === 'object' ? { ...set } : {};
            next[String(tabId)] = 1;
            await api.storage.session.set({ cg_pill_dismissed_tabs: next });
          } catch (e) { /* session storage unavailable — dismissal stays in-memory */ }
        }
        return { ok: true };
      }
      case 'PILL_RESUME': {
        const tabId = sender && sender.tab && sender.tab.id;
        if (tabId != null) {
          try {
            const { cg_pill_dismissed_tabs: set } = await api.storage.session.get('cg_pill_dismissed_tabs');
            if (set && Object.prototype.hasOwnProperty.call(set, String(tabId))) {
              const next = { ...set };
              delete next[String(tabId)];
              await api.storage.session.set({ cg_pill_dismissed_tabs: next });
            }
          } catch (e) { /* session storage unavailable */ }
        }
        return { ok: true };
      }
      case 'GET_PILL_DISMISSED': {
        const tabId = sender && sender.tab && sender.tab.id;
        if (tabId == null) return { ok: true, dismissed: false };
        try {
          const { cg_pill_dismissed_tabs: set } = await api.storage.session.get('cg_pill_dismissed_tabs');
          return { ok: true, dismissed: Boolean(set && set[String(tabId)]) };
        } catch (e) {
          return { ok: true, dismissed: false };
        }
      }
      case 'OPEN_URL_VIEW':
        return openUrlView(msg);
      case 'NAV_ALLOWLIST_ADD':
        setNavAllowlist(msg.url, msg.ttlMs);
        return { ok: true };
      case 'GET_NAV_SETTINGS': {
        const autoBlock = await isAutoBlockNavigationEnabled();
        return { ok: true, autoBlockNavigation: autoBlock };
      }
      case 'SET_NAV_SETTINGS': {
        if (typeof msg.autoBlockNavigation === 'boolean') {
          await api.storage.local.set({ autoBlockNavigation: msg.autoBlockNavigation });
        }
        return { ok: true };
      }
      default:
        return { ok: false, error: 'unknown_message' };
    }
  })().then(sendResponse, (err) => sendResponse({ ok: false, error: String((err && err.message) || err) }));
  return true; // keep the message channel open for the async response
});

if (api.alarms && api.alarms.onAlarm) {
  api.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === REFRESH_ALARM) doRefresh().catch(() => {});
  });
}

// Re-arm the refresh timer whenever the worker restarts.
(async () => {
  const auth = await getAuth();
  if (auth && auth.refresh_token) scheduleRefresh(auth);
})();

globalThis.CyberGuardBackground = {
  handleExtAuth,
  startAuth,
  doRefresh,
  signOut,
  scheduleRefresh,
  randomNonce,
  analyzeBatch,
  openUrlView,
  analyzeCurrentTabUrl,
  getTabScanVerdict,
  clearTabScan,
  handleBeforeNavigate,
  handleNavCompleted,
  isNavAllowlisted,
  setNavAllowlist,
  isAutoBlockNavigationEnabled,
};
