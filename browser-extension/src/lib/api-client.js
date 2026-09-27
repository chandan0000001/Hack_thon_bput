/*
 * CyberGuard extension — backend API client (stub surface for P1).
 *
 * P1 only needs GET /auth/me for the popup identity line. Scanner/OAS
 * endpoints arrive in P3 and will hang off this same client.
 */
(function (global) {
  'use strict';

  /**
   * Fetch the signed-in identity from the CyberGuard backend.
   * @param {object} opts { baseUrl, token, fetchImpl? }
   * @returns {Promise<object>} /auth/me payload (email, active_role, ...)
   */
  async function fetchMe(opts) {
    const { baseUrl, token, fetchImpl = global.fetch } = opts;
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
  global.CyberGuardExt.apiClient = { fetchMe };
})(globalThis);
