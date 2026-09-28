/*
 * CyberGuard extension — floating pill UI (EXT-P3).
 *
 * Fixed bottom-right, dark bg / red accent / mono counts. Pure DOM wiring;
 * the count formatting itself lives in lib/detect.js (formatCounts). States:
 *   counts   — "{N} links · {M} emails · {K} images detected — [Analyze?]"
 *   loading  — "Analyzing…" + spinner
 *   error    — "Analysis failed" + retry
 * All selectors are namespaced under #cgext-pill (see pill.css).
 */
/* global CyberGuardExt */
(function () {
  'use strict';

  const formatCounts = globalThis.CyberGuardExt && globalThis.CyberGuardExt.detect &&
    globalThis.CyberGuardExt.detect.formatCounts;
  if (!formatCounts) return;

  const PILL_ID = 'cgext-pill';
  const pillUi = { setCounts, setLoading, setError, reset, init };

  function ensurePill() {
    let pill = document.getElementById(PILL_ID);
    if (pill) return pill;
    pill = document.createElement('div');
    pill.id = PILL_ID;
    const text = document.createElement('span');
    text.className = 'cgext-pill__text';
    const analyze = document.createElement('button');
    analyze.type = 'button';
    analyze.className = 'cgext-pill__analyze';
    analyze.textContent = 'Analyze?';
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'cgext-pill__close';
    close.setAttribute('aria-label', 'Dismiss');
    close.textContent = '×';
    pill.append(text, analyze, close);
    document.documentElement.appendChild(pill);
    return pill;
  }

  let counts = { url: 0, email: 0, image: 0 };
  let handlers = { onAnalyze: null, onShowOverlay: null };

  function setCounts(next) {
    counts = next || { url: 0, email: 0, image: 0 };
    const line = formatCounts(counts);
    const pill = ensurePill();
    pill.classList.remove('cgext-pill--loading', 'cgext-pill--error');
    if (!line) {
      pill.hidden = true;
      return;
    }
    pill.hidden = false;
    pill.querySelector('.cgext-pill__text').textContent = line;
    const analyzeBtn = pill.querySelector('.cgext-pill__analyze');
    analyzeBtn.hidden = false;
    analyzeBtn.disabled = false;
  }

  function setLoading() {
    const pill = ensurePill();
    pill.hidden = false;
    pill.classList.add('cgext-pill--loading');
    pill.querySelector('.cgext-pill__text').textContent = 'Analyzing…';
    pill.querySelector('.cgext-pill__analyze').hidden = true;
  }

  function setError(message) {
    const pill = ensurePill();
    pill.hidden = false;
    pill.classList.add('cgext-pill--error');
    pill.querySelector('.cgext-pill__text').textContent = message || 'Analysis failed';
    const analyzeBtn = pill.querySelector('.cgext-pill__analyze');
    analyzeBtn.hidden = false;
    analyzeBtn.textContent = 'Retry';
    analyzeBtn.disabled = false;
  }

  function reset() {
    const pill = ensurePill();
    pill.classList.remove('cgext-pill--loading', 'cgext-pill--error');
    const analyzeBtn = pill.querySelector('.cgext-pill__analyze');
    analyzeBtn.hidden = false;
    analyzeBtn.textContent = 'Analyze?';
  }

  async function runAnalysis() {
    setLoading();
    try {
      const res = await handlers.onAnalyze();
      if (!res || !res.ok) throw new Error((res && res.error) || 'Analysis failed');
      reset();
      setCounts(counts);
      handlers.onShowOverlay(res.results || []);
    } catch (err) {
      setError('Analysis failed');
    }
  }

  function init(nextHandlers) {
    handlers = nextHandlers;
    const pill = ensurePill();
    pill.hidden = true;
    pill.querySelector('.cgext-pill__analyze').addEventListener('click', runAnalysis);
    pill.querySelector('.cgext-pill__close').addEventListener('click', () => {
      pill.hidden = true;
    });
  }

  globalThis.CyberGuardExt = globalThis.CyberGuardExt || {};
  globalThis.CyberGuardExt.pillUi = pillUi;
})();
