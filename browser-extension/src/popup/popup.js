/*
 * CyberGuard extension — popup controller (EXT-P2: main menu + 3 analyzers).
 *
 * Auth states use the pure reducer in lib/auth.js; tool views and scan
 * status use lib/popup-views.js so transitions stay node-testable:
 *   menu ⇄ url | email | deepfake, each with idle → loading → done|error.
 */
/* global CyberGuardExt */
(function () {
  'use strict';

  const api = CyberGuardExt.api;
  const CFG = globalThis.EXT_CONFIG;
  const { nextPopupState, isExpired, popupViews, apiClient } = CyberGuardExt;
  const { nextView, nextScan, pickTabUrl, severityBadgeClass, scoreColorClass, deepfakeVerdict, suspiciousNetworkIndicators } = popupViews;

  const nowSec = () => Math.floor(Date.now() / 1000);

  // --- session wiring for the API client (popup talks to the background) ---
  apiClient.configure({
    getAuth: async () => {
      const res = await send({ type: 'EXT_AUTH_GET' });
      return res && res.ok ? res.auth : null;
    },
    refresh: async () => {
      const res = await send({ type: 'EXT_AUTH_REFRESH' });
      return res && res.ok ? res.auth : null;
    },
    signOut: async () => {
      await send({ type: 'EXT_AUTH_SIGNOUT' });
    },
  });

  const sections = {
    'signed-out': document.getElementById('state-signed-out'),
    loading: document.getElementById('state-loading'),
    authenticated: document.getElementById('state-authenticated'),
    error: document.getElementById('state-error'),
  };
  const tools = {
    url: document.getElementById('view-url'),
    email: document.getElementById('view-email'),
    deepfake: document.getElementById('view-deepfake'),
  };
  const emailEl = document.getElementById('auth-email');
  const statusEl = document.getElementById('auth-status');
  const signedOutError = document.getElementById('signed-out-error');

  let state = 'signed-out';
  let view = 'menu';
  let scan = 'idle';

  function showSection(name) {
    for (const [key, el] of Object.entries(sections)) {
      el.hidden = key !== name;
    }
  }

  function showTool(name) {
    for (const [key, el] of Object.entries(tools)) {
      el.hidden = key !== name;
    }
  }

  function syncVisibility() {
    if (state !== 'authenticated') {
      showSection(state);
      showTool('');
      return;
    }
    if (view === 'menu') {
      showSection('authenticated');
      showTool('');
    } else {
      showSection('');
      showTool(view);
    }
  }

  function renderAuth(next, extras = {}) {
    state = nextPopupState(state, next);
    if (state !== 'authenticated') view = 'menu';
    syncVisibility();
    if (state === 'authenticated') {
      statusEl.textContent = extras.status || 'Authenticated';
      emailEl.textContent = extras.email || '…';
    }
    if (state === 'signed-out' && extras.error) {
      signedOutError.textContent = extras.error;
      signedOutError.hidden = false;
    } else if (state === 'signed-out') {
      signedOutError.hidden = true;
    }
  }

  function openView(action) {
    view = nextView(view, action);
    scan = nextScan(scan, 'SCAN_RESET');
    syncVisibility();
    if (view === 'url') autofillUrl();
  }

  async function autofillUrl() {
    const input = document.getElementById('url-input');
    if (input.value) return;
    let tabs = [];
    try {
      tabs = await api.raw.tabs.query({ active: true, currentWindow: true });
    } catch (e) {
      tabs = [];
    }
    const url = pickTabUrl(tabs);
    if (url) input.value = url;
  }

  // --- scan result rendering -------------------------------------------------

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function renderIndicators(container, indicators) {
    const list = Array.isArray(indicators) ? indicators : [];
    if (!list.length) return;
    const wrap = el('div', 'indicators');
    wrap.appendChild(el('p', 'result__label', 'Indicators'));
    for (const ind of list) {
      const row = el('div', 'indicator');
      row.appendChild(el('span', `cg-badge ${severityBadgeClass(ind.severity)}`, String(ind.severity || 'low').toUpperCase()));
      row.appendChild(el('span', 'indicator__value cg-score', String(ind.value ?? '')));
      if (ind.description) row.appendChild(el('span', 'indicator__desc', String(ind.description)));
      wrap.appendChild(row);
    }
    container.appendChild(wrap);
  }

  function renderMitre(container, mitre) {
    const list = Array.isArray(mitre) ? mitre : [];
    if (!list.length) return;
    const wrap = el('div', 'mitre');
    wrap.appendChild(el('p', 'result__label', 'MITRE'));
    for (const tech of list) {
      const id = typeof tech === 'string' ? tech : tech.id;
      const name = typeof tech === 'string' ? '' : tech.name;
      wrap.appendChild(el('span', 'mitre__tag cg-score', name ? `${id} · ${name}` : String(id)));
    }
    container.appendChild(wrap);
  }

  function renderAlertResult(container, data, { mitre = false } = {}) {
    container.replaceChildren();
    const score = Number(data.risk_score);
    const sev = data.severity || 'low';
    const top = el('div', 'score-head');
    top.appendChild(el('span', `score cg-score ${scoreColorClass(score)}`, Number.isFinite(score) ? String(score) : '—'));
    const right = el('div', 'score-head__right');
    right.appendChild(el('span', `cg-badge ${severityBadgeClass(sev)}`, String(sev).toUpperCase()));
    const conf = Number(data.confidence);
    if (Number.isFinite(conf)) {
      right.appendChild(el('p', 'result__meta cg-score', `confidence ${conf <= 1 ? Math.round(conf * 100) : Math.round(conf)}%`));
    }
    top.appendChild(right);
    container.appendChild(top);
    if (data.explanation) container.appendChild(el('p', 'result__explanation', String(data.explanation)));
    if (mitre) renderMitre(container, data.mitre);
    renderIndicators(container, data.indicators);
    container.hidden = false;
  }

  function renderDeepfakeResult(container, data) {
    container.replaceChildren();
    const prob = Number(data.manipulation_probability);
    const { verdict, confidence } = deepfakeVerdict(Number.isFinite(prob) ? prob : NaN);
    const sev = data.severity || 'low';
    const top = el('div', 'score-head');
    top.appendChild(el('span', `score score-verdict cg-score ${verdict === 'FAKE' ? 'score-critical' : verdict === 'REAL' ? 'score-safe' : 'score-low'}`, verdict));
    const right = el('div', 'score-head__right');
    right.appendChild(el('span', `cg-badge ${severityBadgeClass(sev)}`, String(sev).toUpperCase()));
    if (confidence != null) {
      right.appendChild(el('p', 'result__meta cg-score', `confidence ${Math.round(confidence * 100)}%`));
    }
    top.appendChild(right);
    container.appendChild(top);
    if (Number.isFinite(prob)) {
      container.appendChild(el('p', 'result__meta cg-score', `manipulation probability ${Math.round(prob * 100)}% · authenticity ${Math.round((1 - prob) * 100)}%`));
    }
    if (data.explanation) container.appendChild(el('p', 'result__explanation', String(data.explanation)));
    const boxes = data.bounding_boxes || data.bboxes;
    if (Array.isArray(boxes) && boxes.length) {
      const wrap = el('div', 'indicators');
      wrap.appendChild(el('p', 'result__label', 'Regions'));
      for (const box of boxes) {
        wrap.appendChild(el('span', 'mitre__tag cg-score', JSON.stringify(box)));
      }
      container.appendChild(wrap);
    } else {
      container.appendChild(el('p', 'result__meta', 'No bounding-box regions returned by the API.'));
    }
    renderIndicators(container, data.indicators);
    container.hidden = false;
  }

  // --- scan flows -------------------------------------------------------------

  function scanError(viewName, message) {
    scan = nextScan(scan, 'SCAN_FAIL');
    const banner = document.getElementById(`${viewName}-error`);
    banner.textContent = message;
    banner.hidden = false;
    document.getElementById(`${viewName}-result`).hidden = true;
  }

  function scanBegin(viewName, button) {
    scan = nextScan(scan, 'SCAN_START');
    scanError(viewName, '');
    document.getElementById(`${viewName}-error`).hidden = true;
    document.getElementById(`${viewName}-result`).hidden = true;
    button.disabled = true;
    button.classList.add('is-loading');
  }

  function scanEnd(viewName, button) {
    scan = nextScan(scan, 'SCAN_OK');
    button.disabled = false;
    button.classList.remove('is-loading');
  }

  function scanFail(viewName, button, err) {
    scanEnd(viewName, button);
    if (err && err.authLost) {
      renderAuth('REFRESH_FAIL', { error: 'Session expired — sign in again.' });
      return;
    }
    scanError(viewName, (err && err.message) || 'Scan failed.');
  }

  async function runUrlScan() {
    const button = document.getElementById('btn-scan-url');
    const url = document.getElementById('url-input').value.trim();
    if (!url) {
      scanError('url', 'Enter a URL to scan.');
      return;
    }
    scanBegin('url', button);
    try {
      const result = await apiClient.analyzeUrl(CFG.API_BASE_URL, url);
      scanEnd('url', button);
      renderAlertResult(document.getElementById('url-result'), result);
    } catch (err) {
      scanFail('url', button, err);
    }
  }

  async function runEmailScan() {
    const button = document.getElementById('btn-scan-email');
    const text = document.getElementById('email-input').value.trim();
    if (!text) {
      scanError('email', 'Paste an email to scan.');
      return;
    }
    scanBegin('email', button);
    try {
      const result = await apiClient.analyzeEmail(CFG.API_BASE_URL, text);
      scanEnd('email', button);
      const container = document.getElementById('email-result');
      renderAlertResult(container, result, { mitre: true });
      const network = suspiciousNetworkIndicators(result.indicators);
      if (network.length) {
        const wrap = el('div', 'indicators');
        wrap.appendChild(el('p', 'result__label', 'Suspicious links / domains'));
        for (const ind of network) {
          wrap.appendChild(el('span', 'mitre__tag cg-score', String(ind.value)));
        }
        container.appendChild(wrap);
      }
    } catch (err) {
      scanFail('email', button, err);
    }
  }

  async function runDeepfakeScan() {
    const button = document.getElementById('btn-scan-deepfake');
    const file = document.getElementById('deepfake-input').files[0];
    if (!file) {
      scanError('deepfake', 'Choose an image to analyze.');
      return;
    }
    scanBegin('deepfake', button);
    try {
      const result = await apiClient.analyzeDeepfake(CFG.API_BASE_URL, file);
      scanEnd('deepfake', button);
      renderDeepfakeResult(document.getElementById('deepfake-result'), result);
    } catch (err) {
      scanFail('deepfake', button, err);
    }
  }

  // --- auth boot (P1 flow) ------------------------------------------------------

  async function send(message) {
    try {
      return await api.runtime.sendMessage(message);
    } catch (err) {
      return { ok: false, error: String((err && err.message) || err) };
    }
  }

  async function showIdentity(auth) {
    try {
      const me = await CyberGuardExt.apiClient.fetchMe({ baseUrl: CFG.API_BASE_URL, token: auth.access_token });
      renderAuth('TOKENS_VALID', { email: me.email || 'unknown', status: 'Authenticated' });
    } catch (err) {
      renderAuth('TOKENS_VALID', { email: 'identity unavailable' });
    }
  }

  async function boot() {
    renderAuth('BOOT');
    const res = await send({ type: 'EXT_AUTH_GET' });
    const auth = res && res.ok ? res.auth : null;
    if (!auth || !auth.access_token || !auth.refresh_token) {
      renderAuth('NO_TOKENS');
      return;
    }
    if (!isExpired(auth, nowSec())) {
      await showIdentity(auth);
      return;
    }
    const refreshed = await send({ type: 'EXT_AUTH_REFRESH' });
    if (refreshed && refreshed.ok && refreshed.auth) {
      await showIdentity(refreshed.auth);
    } else {
      renderAuth('REFRESH_FAIL', refreshed && refreshed.error === 'session_expired'
        ? {}
        : { error: 'Session could not be refreshed — sign in again.' });
    }
  }

  // --- event wiring -------------------------------------------------------------

  document.getElementById('btn-sign-in').addEventListener('click', async () => {
    const btn = document.getElementById('btn-sign-in');
    btn.disabled = true;
    const start = await send({ type: 'EXT_AUTH_START' });
    if (!start || !start.ok || !start.nonce) {
      btn.disabled = false;
      return;
    }
    const url = `${start.webOrigin}/ext/auth?state=${encodeURIComponent(start.nonce)}&v=${start.v || 1}`;
    await api.tabs.create({ url });
    window.close();
  });

  document.getElementById('btn-sign-out').addEventListener('click', async () => {
    await send({ type: 'EXT_AUTH_SIGNOUT' });
    renderAuth('SIGNOUT');
  });

  document.getElementById('btn-retry').addEventListener('click', () => boot());

  document.getElementById('card-url').addEventListener('click', () => openView('OPEN_URL'));
  document.getElementById('card-email').addEventListener('click', () => openView('OPEN_EMAIL'));
  document.getElementById('card-deepfake').addEventListener('click', () => openView('OPEN_DEEPFAKE'));
  for (const back of document.querySelectorAll('[data-back]')) {
    back.addEventListener('click', () => openView('BACK'));
  }

  document.getElementById('btn-scan-url').addEventListener('click', () => runUrlScan());
  document.getElementById('btn-scan-email').addEventListener('click', () => runEmailScan());
  document.getElementById('btn-scan-deepfake').addEventListener('click', () => runDeepfakeScan());

  document.getElementById('deepfake-input').addEventListener('change', (e) => {
    const hint = document.getElementById('deepfake-file');
    const file = e.target.files[0];
    hint.hidden = !file;
    hint.textContent = file ? `${file.name} · ${Math.round(file.size / 1024)} KB` : '';
  });

  document.getElementById('ptr-connectors').addEventListener('click', async () => {
    await api.tabs.create({ url: CFG.WEB_ORIGIN + '/email-connectors' });
    window.close();
  });

  document.getElementById('ptr-console').addEventListener('click', async () => {
    await api.tabs.create({ url: CFG.WEB_ORIGIN + '/dashboard' });
    window.close();
  });

  // EXT-P3: honor "Open in popup" landings — a tab opened with
  // ?view=url&url=… (openUrlView fallback) or a pendingUrlView stashed in
  // storage.session (action.openPopup path).
  async function applyPrefill() {
    if (state !== 'authenticated') return;
    let prefill = null;
    const qs = new URLSearchParams(location.search);
    if (qs.get('view') === 'url' && qs.get('url')) {
      prefill = qs.get('url');
    } else {
      try {
        const stored = await api.storage.session.get('pendingUrlView');
        if (stored && stored.pendingUrlView) {
          prefill = stored.pendingUrlView;
          await api.storage.session.remove('pendingUrlView');
        }
      } catch (e) { /* storage.session unavailable */ }
    }
    if (prefill) {
      openView('OPEN_URL');
      const input = document.getElementById('url-input');
      if (!input.value) input.value = prefill;
    }
  }

  boot().then(applyPrefill);
})();
