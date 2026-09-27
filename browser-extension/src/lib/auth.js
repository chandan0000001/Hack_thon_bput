/*
 * CyberGuard extension — auth primitives (pure, node-testable).
 *
 * Everything here is deterministic logic with injectable clock/fetch so the
 * node test suite can exercise it without a browser. Browser wiring lives in
 * background.js / popup.js.
 */
(function (global) {
  'use strict';

  // Refresh fires this many seconds before the access token expires.
  const AUTH_EXPIRY_MARGIN_S = 60;
  // Retry cadence when a transient refresh error occurs.
  const REFRESH_RETRY_MS = 5 * 60 * 1000;

  /**
   * Parse an OAuth-style fragment handoff ("#access_token=..&refresh_token=..").
   * @param {string} hash raw location.hash (leading '#' optional)
   * @returns {{ok:true,value:{access_token,refresh_token,expires_at,state}}|
   *           {ok:false,reason:'missing'|'invalid'}}
   */
  function parseFragment(hash) {
    if (typeof hash !== 'string' || hash === '' || hash === '#') {
      return { ok: false, reason: 'missing' };
    }
    const query = hash.charAt(0) === '#' ? hash.slice(1) : hash;
    let params;
    try {
      params = new URLSearchParams(query);
    } catch {
      return { ok: false, reason: 'invalid' };
    }
    const access_token = params.get('access_token');
    const refresh_token = params.get('refresh_token');
    const expiresAtRaw = params.get('expires_at');
    const expires_at = Number(expiresAtRaw);
    const state = params.get('state') || '';
    if (!access_token || !refresh_token || !expiresAtRaw || !Number.isFinite(expires_at) || expires_at <= 0 || !state) {
      return { ok: false, reason: 'invalid' };
    }
    return { ok: true, value: { access_token, refresh_token, expires_at, state } };
  }

  /** Nonce comparison: both sides must be non-empty strings and equal. */
  function stateMatches(expected, got) {
    return typeof expected === 'string' && expected.length > 0 && expected === got;
  }

  /** True when the token is absent or inside the pre-expiry refresh margin. */
  function isExpired(auth, nowSec) {
    if (!auth || !auth.expires_at) return true;
    return auth.expires_at - AUTH_EXPIRY_MARGIN_S <= nowSec;
  }

  /**
   * Milliseconds from nowMs until the scheduled refresh moment
   * (expires_at minus margin). Never negative.
   */
  function refreshDelayMs(auth, nowMs) {
    if (!auth || !auth.expires_at) return 0;
    const fireAtMs = (auth.expires_at - AUTH_EXPIRY_MARGIN_S) * 1000;
    return Math.max(0, fireAtMs - nowMs);
  }

  /**
   * Exchange a refresh token for a fresh Supabase session.
   * @returns {Promise<{access_token,refresh_token,expires_at,email}>}
   */
  async function refreshTokens(opts) {
    const { refreshToken, supabaseUrl, anonKey, email = null, nowSec = null, fetchImpl = global.fetch } = opts;
    if (!refreshToken || !supabaseUrl || !anonKey) {
      throw new Error('refreshTokens: missing refreshToken/supabaseUrl/anonKey');
    }
    const res = await fetchImpl(`${supabaseUrl}/auth/v1/token?grant_type=refresh_token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) {
      const err = new Error(`supabase refresh failed: HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    const data = await res.json();
    if (!data || !data.access_token || !data.refresh_token) {
      throw new Error('supabase refresh response missing tokens');
    }
    return {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: data.expires_at ?? (nowSec != null ? nowSec + 3600 : 0),
      email: email ?? null,
    };
  }

  /** True for HTTP statuses meaning the refresh token is dead (not transient). */
  function isRefreshTerminal(status) {
    return status === 400 || status === 401 || status === 403;
  }

  /**
   * Popup UI state machine.
   * States:   'loading' | 'signed-out' | 'authenticated' | 'error'
   * Events:   BOOT, NO_TOKENS, TOKENS_VALID, REFRESH_STARTED, REFRESH_OK,
   *           REFRESH_FAIL, SIGNOUT, FATAL
   */
  function nextPopupState(current, event) {
    switch (event) {
      case 'BOOT':
        return 'loading';
      case 'NO_TOKENS':
      case 'REFRESH_FAIL':
      case 'SIGNOUT':
        return 'signed-out';
      case 'TOKENS_VALID':
      case 'REFRESH_OK':
        return 'authenticated';
      case 'FATAL':
        return 'error';
      default:
        return current;
    }
  }

  global.CyberGuardExt = global.CyberGuardExt || {};
  global.CyberGuardExt.AUTH_EXPIRY_MARGIN_S = AUTH_EXPIRY_MARGIN_S;
  global.CyberGuardExt.REFRESH_RETRY_MS = REFRESH_RETRY_MS;
  global.CyberGuardExt.parseFragment = parseFragment;
  global.CyberGuardExt.stateMatches = stateMatches;
  global.CyberGuardExt.isExpired = isExpired;
  global.CyberGuardExt.refreshDelayMs = refreshDelayMs;
  global.CyberGuardExt.refreshTokens = refreshTokens;
  global.CyberGuardExt.isRefreshTerminal = isRefreshTerminal;
  global.CyberGuardExt.nextPopupState = nextPopupState;
})(globalThis);
