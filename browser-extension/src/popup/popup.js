/*
 * CyberGuard extension — popup controller.
 *
 * States are driven through the pure reducer in lib/auth.js
 * (CyberGuardExt.nextPopupState) so the transitions are node-testable:
 *   BOOT → loading → (NO_TOKENS → signed-out | TOKENS_VALID/REFRESH_OK →
 *   authenticated | REFRESH_FAIL → signed-out) ; FATAL → error.
 */
/* global CyberGuardExt */
(function () {
  'use strict';

  const api = CyberGuardExt.api;
  const CFG = globalThis.EXT_CONFIG;
  const { nextPopupState, isExpired, apiClient } = CyberGuardExt;

  const AUTH_KEY = 'extAuth';
  const nowSec = () => Math.floor(Date.now() / 1000);

  const sections = {
    'signed-out': document.getElementById('state-signed-out'),
    loading: document.getElementById('state-loading'),
    authenticated: document.getElementById('state-authenticated'),
    error: document.getElementById('state-error'),
  };
  const emailEl = document.getElementById('auth-email');
  const statusEl = document.getElementById('auth-status');
  const signedOutError = document.getElementById('signed-out-error');

  let state = 'signed-out';

  function render(next, extras = {}) {
    state = nextPopupState(state, next);
    for (const [name, el] of Object.entries(sections)) {
      el.hidden = name !== state;
    }
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

  async function send(message) {
    try {
      return await api.runtime.sendMessage(message);
    } catch (err) {
      return { ok: false, error: String((err && err.message) || err) };
    }
  }

  async function showIdentity(auth) {
    try {
      const me = await apiClient.fetchMe({ baseUrl: CFG.API_BASE_URL, token: auth.access_token });
      render('TOKENS_VALID', { email: me.email || 'unknown', status: 'Authenticated' });
    } catch (err) {
      // Identity lookup failing doesn't invalidate a live session; keep the
      // authenticated shell and surface a placeholder.
      render('TOKENS_VALID', { email: 'identity unavailable' });
    }
  }

  async function boot() {
    render('BOOT');
    const res = await send({ type: 'EXT_AUTH_GET' });
    const auth = res && res.ok ? res.auth : null;
    if (!auth || !auth.access_token || !auth.refresh_token) {
      render('NO_TOKENS');
      return;
    }
    if (!isExpired(auth, nowSec())) {
      await showIdentity(auth);
      return;
    }
    // Expired (inside the 60s margin or worse): one refresh attempt, then
    // signed-out if the refresh token is dead.
    const refreshed = await send({ type: 'EXT_AUTH_REFRESH' });
    if (refreshed && refreshed.ok && refreshed.auth) {
      await showIdentity(refreshed.auth);
    } else {
      render('REFRESH_FAIL', refreshed && refreshed.error === 'session_expired'
        ? {}
        : { error: 'Session could not be refreshed — sign in again.' });
    }
  }

  document.getElementById('btn-sign-in').addEventListener('click', async () => {
    const btn = document.getElementById('btn-sign-in');
    btn.disabled = true;
    const start = await send({ type: 'EXT_AUTH_START' });
    if (!start || !start.ok || !start.nonce) {
      render(state, {});
      btn.disabled = false;
      return;
    }
    const url = `${start.webOrigin}/ext/auth?state=${encodeURIComponent(start.nonce)}&v=${start.v || 1}`;
    await api.tabs.create({ url });
    window.close();
  });

  document.getElementById('btn-open-console').addEventListener('click', async () => {
    await api.tabs.create({ url: CFG.WEB_ORIGIN + '/dashboard' });
    window.close();
  });

  document.getElementById('btn-sign-out').addEventListener('click', async () => {
    await send({ type: 'EXT_AUTH_SIGNOUT' });
    render('SIGNOUT');
  });

  document.getElementById('btn-retry').addEventListener('click', () => boot());

  boot();
})();
