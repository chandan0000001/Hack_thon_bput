/*
 * CyberGuard extension — content scanner detection core (pure, jsdom-testable).
 *
 * Everything here takes a document-like root (jsdom in tests, the real
 * document in the content script) and returns plain data. Network calls
 * NEVER happen here — the pill requires an explicit [Analyze?] click before
 * anything leaves the page.
 */
(function (global) {
  'use strict';

  const URL_RE = /\bhttps?:\/\/[^\s<>"'()]+[^\s<>"'().,;:!?'"]/g;

  // Web stores are excluded from scanning entirely.
  const EXCLUDED_HOSTS = /(^|\.)(chrome\.google\.com|chromewebstore\.google\.com|microsoftedge\.microsoft\.com)$/i;

  const EMAIL_SELECTORS = [
    'div[role="main"] .ii', // Gmail
    'div[aria-label="Message body"]', // Outlook web
    'div.message-content', // ProtonMail
  ];

  const MAX_EMAIL_TEXT_CHARS = 20000;
  const MAX_TEXT_SCAN_CHARS = 100000;

  function isExcludedHost(hostname) {
    return EXCLUDED_HOSTS.test(String(hostname || ''));
  }

  function safeHostname(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return null;
    }
  }

  /**
   * Detect URLs: all <a href> links plus plain-text matches. Deduped,
   * capped at maxDetections.
   */
  function detectUrls(doc, maxDetections = 20) {
    const found = [];
    const seen = new Set();
    const push = (url, source) => {
      const clean = String(url || '').trim();
      if (!clean || seen.has(clean) || found.length >= maxDetections) return;
      if (!/^https?:\/\//i.test(clean)) return;
      if (isExcludedHost(safeHostname(clean))) return;
      seen.add(clean);
      found.push({ kind: 'url', value: clean, source });
    };
    for (const a of doc.querySelectorAll('a[href]')) {
      push(a.href || a.getAttribute('href'), 'link');
      if (found.length >= maxDetections) return found;
    }
    // Text-node sweep (mailto-free; hrefs are already covered).
    if (found.length < maxDetections && doc.body) {
      const text = (doc.body.textContent || '').slice(0, MAX_TEXT_SCAN_CHARS);
      for (const m of text.matchAll(URL_RE)) {
        push(m[0], 'text');
        if (found.length >= maxDetections) break;
      }
    }
    return found;
  }

  /**
   * Detect webmail email bodies via provider-specific selectors.
   * Returns at most one email (the largest body text found).
   */
  function detectEmail(doc) {
    let best = null;
    for (const sel of EMAIL_SELECTORS) {
      for (const node of doc.querySelectorAll(sel)) {
        const text = (node.textContent || '').trim();
        if (text.length < 40) continue; // quoted snippets / fragments
        if (!best || text.length > best.value.length) {
          best = { kind: 'email', value: text.slice(0, MAX_EMAIL_TEXT_CHARS), source: sel };
        }
      }
    }
    return best;
  }

  /**
   * Detect content-sized images: rendered or intrinsic size > 200x200
   * (tracking pixels and icons are far smaller).
   */
  function detectImages(doc, maxDetections = 20) {
    const found = [];
    for (const img of doc.querySelectorAll('img')) {
      const w = Number(img.naturalWidth || img.width || img.getAttribute('width') || 0);
      const h = Number(img.naturalHeight || img.height || img.getAttribute('height') || 0);
      if (w > 200 && h > 200) {
        found.push({ kind: 'image', value: img.currentSrc || img.src, width: w, height: h });
        if (found.length >= maxDetections) break;
      }
    }
    return found;
  }

  /**
   * Domain allowlist (default empty = scan everywhere). URL and image
   * detections are additionally filtered by their own target host; email
   * detections belong to the page itself and are dropped when the page host
   * is not allowlisted.
   */
  function filterByAllowlist(detections, allowlist, pageHostname) {
    const list = (allowlist || []).map((d) => String(d).toLowerCase().trim()).filter(Boolean);
    if (!list.length) return detections;
    const hostAllowed = (host) => host && list.some((d) => host === d || host.endsWith(`.${d}`));
    return detections.filter((d) => {
      if (d.kind === 'url') return hostAllowed(safeHostname(d.value));
      if (d.kind === 'image') return hostAllowed(safeHostname(d.value)) || (!safeHostname(d.value) && hostAllowed(String(pageHostname || '')));
      return hostAllowed(String(pageHostname || ''));
    });
  }

  /** "3 links · 1 email · 2 images detected" (zero types omitted, none -> null). */
  function formatCounts(counts) {
    const parts = [];
    if (counts.url > 0) parts.push(`${counts.url} link${counts.url === 1 ? '' : 's'}`);
    if (counts.email > 0) parts.push(`${counts.email} email${counts.email === 1 ? '' : 's'}`);
    if (counts.image > 0) parts.push(`${counts.image} image${counts.image === 1 ? '' : 's'}`);
    return parts.length ? `${parts.join(' · ')} detected` : null;
  }

  /** Overlay summary line: "3 HIGH, 1 MEDIUM, 2 LOW" (severity order fixed). */
  function summarizeSeverities(results) {
    const order = ['critical', 'high', 'medium', 'low', 'safe'];
    const tally = {};
    for (const r of results || []) {
      const sev = String((r && r.data && r.data.severity) || '').toLowerCase();
      if (order.includes(sev)) tally[sev] = (tally[sev] || 0) + 1;
    }
    const line = order
      .map((sev) => (tally[sev] ? `${tally[sev]} ${sev.toUpperCase()}` : null))
      .filter(Boolean)
      .join(', ');
    return line || 'no results';
  }

  /** Debounced batcher: N rapid adds -> exactly one flush with all items. */
  function createBatcher(flushFn, delayMs) {
    let timer = null;
    let items = [];
    return {
      add(item) {
        items.push(item);
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
          timer = null;
          const batch = items;
          items = [];
          flushFn(batch);
        }, delayMs);
      },
      cancel() {
        if (timer) clearTimeout(timer);
        timer = null;
        items = [];
      },
    };
  }

  global.CyberGuardExt = global.CyberGuardExt || {};
  global.CyberGuardExt.detect = {
    URL_RE,
    isExcludedHost,
    detectUrls,
    detectEmail,
    detectImages,
    filterByAllowlist,
    formatCounts,
    summarizeSeverities,
    createBatcher,
  };
})(globalThis);
