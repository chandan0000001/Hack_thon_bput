/*
 * CyberGuard extension — backend API client.
 *
 * Contracts mirror the website frontend (frontend/src/services/api.ts):
 *   POST /analysis/url    JSON  {url}                      -> AlertResponse
 *   POST /analysis/email  JSON  {sender,subject,body,raw_headers?} -> AlertResponse
 *   POST /analysis/media  multipart 'file'                     -> media dict
 *
 * Every call carries the stored Bearer token. On 401 the client asks the
 * background to refresh once (EXT_AUTH_REFRESH) and retries; if the refresh
 * fails it clears the session (EXT_AUTH_SIGNOUT) and throws AuthLostError,
 * which the popup turns into the signed-out state.
 */
(function (global) {
  'use strict';

  class AuthLostError extends Error {
    constructor(message) {
      super(message);
      this.name = 'AuthLostError';
      this.authLost = true;
    }
  }

  // Injectable session wiring — popup.js configures this against the
  // background worker; node tests stub it directly.
  let wiring = {
    getAuth: async () => null,
    refresh: async () => null,
    signOut: async () => {},
    fetchImpl: null,
  };

  function configure(next) {
    wiring = { ...wiring, ...next };
  }

  async function authedFetch(url, init = {}, allowRetry = true, tokenOverride) {
    const auth = await wiring.getAuth();
    const token = tokenOverride || (auth && auth.access_token);
    if (!token) {
      await wiring.signOut();
      throw new AuthLostError('no active session');
    }
    const headers = { ...(init.headers || {}), Authorization: `Bearer ${token}` };
    if (init.body && !(init.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    const doFetch = wiring.fetchImpl || global.fetch;
    const res = await doFetch(url, { ...init, headers });
    if (res.status === 401) {
      if (allowRetry) {
        const next = await wiring.refresh();
        if (next && next.access_token) {
          return authedFetch(url, init, false, next.access_token);
        }
        await wiring.signOut();
        throw new AuthLostError('session expired (refresh failed)');
      }
      await wiring.signOut();
      throw new AuthLostError('unauthorized');
    }
    if (!res.ok) {
      const err = new Error(`API ${url} failed: HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  /** POST /analysis/url -> AlertResponse (risk_score 0-100, severity, indicators). */
  async function analyzeUrl(baseUrl, url) {
    return authedFetch(`${baseUrl}/analysis/url`, {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  /**
   * POST /analysis/email -> AlertResponse.
   * text is a pasted email body (optionally with RFC822 headers); From: and
   * Subject: lines are promoted to sender/subject when present.
   */
  async function analyzeEmail(baseUrl, text) {
    const payload = { sender: 'unknown@sender', subject: '(no subject)', body: text };
    const from = text.match(/^From:\s*(.+)$/im);
    if (from) payload.sender = from[1].trim();
    const subject = text.match(/^Subject:\s*(.+)$/im);
    if (subject) payload.subject = subject[1].trim();
    const headerBlock = text.split(/\r?\n\r?\n/, 1)[0] || '';
    const headerLines = headerBlock.split(/\r?\n/).filter((l) => /^[A-Za-z-]+:\s/.test(l));
    if (headerLines.length >= 2) payload.raw_headers = headerLines.join('\n');
    return authedFetch(`${baseUrl}/analysis/email`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /** POST /analysis/media (multipart 'file') -> media dict (authenticity_score etc.). */
  async function analyzeDeepfake(baseUrl, file) {
    const form = new FormData();
    form.append('file', file);
    return authedFetch(`${baseUrl}/analysis/media`, {
      method: 'POST',
      body: form,
    });
  }

  /** GET /auth/me -> identity payload (email, active_role, ...). */
  async function fetchMe({ baseUrl, token, fetchImpl = wiring.fetchImpl || global.fetch }) {
    if (!baseUrl || !token) throw new Error('fetchMe: missing baseUrl/token');
    const res = await fetchImpl(`${baseUrl}/auth/me`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const err = new Error(`/auth/me failed: HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  global.CyberGuardExt = global.CyberGuardExt || {};
  global.CyberGuardExt.apiClient = {
    configure,
    AuthLostError,
    fetchMe,
    analyzeUrl,
    analyzeEmail,
    analyzeDeepfake,
    // exposed for tests
    _authedFetch: authedFetch,
  };
})(globalThis);
