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
 * Tokens live only in storage.local (fragment handoff only, never query
 * strings, never server logs).
 */
/* global importScripts, crypto, FormData, Blob */
importScripts('config.js', 'lib/browser-adapter.js', 'lib/auth.js', 'lib/api-client.js');

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
      case 'OPEN_URL_VIEW':
        return openUrlView(msg);
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

globalThis.CyberGuardBackground = { handleExtAuth, startAuth, doRefresh, signOut, scheduleRefresh, randomNonce, analyzeBatch, openUrlView };
