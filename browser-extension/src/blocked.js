/*
 * CyberGuard extension — auto-block interstitial controller (EXT-SCANNER-V2 S2).
 * Runs on blocked.html.
 */
(function (global) {
  'use strict';

  const g = (global && global.document) ? global : (typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));

  function parseQueryParams(search, win = (g.document ? g.document.defaultView : g)) {
    const s = search != null
      ? search
      : (win && win.location ? win.location.search : (g.location ? g.location.search : ''));
    const params = new URLSearchParams(s || '');
    let indicators = [];
    try {
      const rawInd = params.get('indicators');
      if (rawInd) indicators = JSON.parse(rawInd);
    } catch (e) {
      indicators = [];
    }
    return {
      url: params.get('url') || '',
      reason: params.get('reason') || 'High-risk navigation detected.',
      score: params.get('score') || '',
      severity: params.get('severity') || 'BLOCK',
      indicators: Array.isArray(indicators) ? indicators.slice(0, 3) : [],
    };
  }

  function init(doc = g.document) {
    if (!doc) return;
    const win = doc.defaultView || g;
    const search = win && win.location ? win.location.search : '';
    const data = parseQueryParams(search, win);
    const targetUrl = data.url;

    const urlEl = doc.getElementById('cg-target-url');
    if (urlEl) urlEl.textContent = targetUrl || '—';

    const reasonEl = doc.getElementById('cg-reason');
    if (reasonEl) reasonEl.textContent = data.reason;

    const scoreEl = doc.getElementById('cg-score');
    if (scoreEl) {
      let sc = data.score;
      if (sc !== '' && !Number.isNaN(Number(sc))) {
        const num = Number(sc);
        sc = num <= 1 && num > 0 ? Math.round(num * 100) : Math.round(num);
      }
      scoreEl.textContent = sc !== '' ? String(sc) : '—';
    }

    const sevEl = doc.getElementById('cg-severity');
    if (sevEl) {
      const sev = String(data.severity || 'BLOCK').toUpperCase();
      sevEl.textContent = sev;
    }

    const indListEl = doc.getElementById('cg-indicators');
    const indWrapEl = doc.getElementById('cg-indicators-wrap');
    if (indListEl) {
      indListEl.replaceChildren();
      if (!data.indicators.length) {
        if (indWrapEl) indWrapEl.hidden = true;
      } else {
        if (indWrapEl) indWrapEl.hidden = false;
        data.indicators.slice(0, 3).forEach((ind) => {
          const li = doc.createElement('li');
          const desc = typeof ind === 'string' ? ind : (ind.description || ind.value || ind.type || JSON.stringify(ind));
          li.textContent = desc;
          indListEl.appendChild(li);
        });
      }
    }

    const btnBack = doc.getElementById('btn-back');
    if (btnBack) {
      btnBack.addEventListener('click', () => goBack(win));
    }

    const btnContinue = doc.getElementById('btn-continue');
    if (btnContinue) {
      btnContinue.addEventListener('click', () => continueAnyway(targetUrl, win));
    }
  }

  function goBack(win = (g.document ? g.document.defaultView : g)) {
    // The guard pushed this page right after the blocked target, so session
    // history is […, target, blockedPage]. A single back() re-lands on the
    // blocked URL, the guard re-blocks it, and the two pages ping-pong
    // forever. Skip past the target entry; if the target was the first
    // entry in this tab, leave history entirely.
    if (win && win.history && win.history.length > 2) {
      win.history.go(-2);
    } else if (win && win.location) {
      win.location.replace('about:blank');
    }
  }

  async function continueAnyway(targetUrl, win = (g.document ? g.document.defaultView : g)) {
    if (!targetUrl) return;
    const ttlMs = 10 * 60 * 1000;
    const expiresAt = Date.now() + ttlMs;

    const raw = (win && (win.chrome || win.browser)) || g.chrome || g.browser;
    if (raw && raw.storage && raw.storage.session) {
      await new Promise((resolve) => {
        try {
          raw.storage.session.get({ navAllowlist: {} }, (stored) => {
            const list = (stored && stored.navAllowlist) || {};
            list[targetUrl] = expiresAt;
            try {
              const u = new URL(targetUrl);
              u.hash = '';
              list[u.href] = expiresAt;
            } catch (e) {}
            raw.storage.session.set({ navAllowlist: list }, () => resolve());
          });
        } catch (e) {
          resolve();
        }
      });
    }

    if (raw && raw.runtime && typeof raw.runtime.sendMessage === 'function') {
      try {
        raw.runtime.sendMessage({ type: 'NAV_ALLOWLIST_ADD', url: targetUrl, expiresAt });
      } catch (e) {}
    }

    if (win && win.location) {
      try {
        win.location.replace(targetUrl);
      } catch (e) {
        win.location.href = targetUrl;
      }
    }
  }

  g.CyberGuardBlocked = {
    parseQueryParams,
    init,
    goBack,
    continueAnyway,
  };

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => init());
    } else {
      init();
    }
  }
})(typeof global !== 'undefined' ? global : (typeof globalThis !== 'undefined' ? globalThis : this));
