/*
 * CyberGuard extension — popup view + scan state machines (pure, node-testable).
 *
 * View:  'menu' | 'url' | 'email' | 'deepfake'
 * Scan:  'idle' | 'loading' | 'done' | 'error'
 */
(function (global) {
  'use strict';

  function nextView(current, action) {
    switch (action) {
      case 'OPEN_URL':
        return 'url';
      case 'OPEN_EMAIL':
        return 'email';
      case 'OPEN_DEEPFAKE':
        return 'deepfake';
      case 'BACK':
      case 'GO_MENU':
        return 'menu';
      default:
        return current;
    }
  }

  function nextScan(current, action) {
    switch (action) {
      case 'SCAN_START':
        return 'loading';
      case 'SCAN_OK':
        return 'done';
      case 'SCAN_FAIL':
        return 'error';
      case 'SCAN_RESET':
        return 'idle';
      default:
        return current;
    }
  }

  /**
   * Pick the URL to auto-fill from a chrome.tabs.query result: prefer the
   * active http(s) tab, ignoring extension/internal pages entirely.
   */
  function pickTabUrl(tabs) {
    const list = Array.isArray(tabs) ? tabs : [];
    const usable = (t) => t && typeof t.url === 'string' && /^https?:\/\//i.test(t.url);
    const active = list.find((t) => t.active && usable(t));
    if (active) return active.url;
    const first = list.find(usable);
    return first ? first.url : '';
  }

  /** Severity -> badge CSS class (theme tokens; unknown severities degrade to low). */
  function severityBadgeClass(severity) {
    const known = ['safe', 'low', 'medium', 'high', 'critical'];
    const sev = known.includes(severity) ? severity : 'low';
    return `cg-badge--${sev}`;
  }

  /** Risk score 0-100 -> text color class (red ramp by severity thresholds). */
  function scoreColorClass(score) {
    if (!Number.isFinite(score)) return 'score-low';
    if (score >= 85) return 'score-critical';
    if (score >= 70) return 'score-high';
    if (score >= 40) return 'score-medium';
    if (score >= 15) return 'score-low';
    return 'score-safe';
  }

  /** Deepfake verdict from the API's manipulation_probability (0-1). */
  function deepfakeVerdict(manipulationProbability) {
    if (!Number.isFinite(manipulationProbability)) {
      return { verdict: 'UNKNOWN', confidence: null };
    }
    return manipulationProbability >= 0.5
      ? { verdict: 'FAKE', confidence: manipulationProbability }
      : { verdict: 'REAL', confidence: 1 - manipulationProbability };
  }

  /**
   * Suspicious links/domains for the email view: indicators whose type or
   * value looks like a URL/domain.
   */
  function suspiciousNetworkIndicators(indicators) {
    const list = Array.isArray(indicators) ? indicators : [];
    return list.filter((ind) => {
      const type = String((ind && ind.type) || '').toLowerCase();
      const value = String((ind && ind.value) || '');
      return type.includes('url') || type.includes('domain') || /^https?:\/\//i.test(value);
    });
  }

  global.CyberGuardExt = global.CyberGuardExt || {};
  global.CyberGuardExt.popupViews = {
    nextView,
    nextScan,
    pickTabUrl,
    severityBadgeClass,
    scoreColorClass,
    deepfakeVerdict,
    suspiciousNetworkIndicators,
  };
})(globalThis);
