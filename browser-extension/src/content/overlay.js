/*
 * CyberGuard extension — overlay results UI (EXT-P3).
 *
 * buildOverlayModel(results) is pure and node-testable: it turns the
 * background's BATCH_RESULTS array into {summary, cards} — summary like
 * "3 HIGH, 1 MEDIUM, 2 LOW", one card per detection. DOM rendering is
 * namespaced under #cgext-overlay-root (see overlay.css).
 */
/* global CyberGuardExt */
(function () {
  'use strict';

  const detectLib = globalThis.CyberGuardExt && globalThis.CyberGuardExt.detect;
  const ROOT_ID = 'cgext-overlay-root';

  function deepfakeVerdict(prob) {
    if (!Number.isFinite(prob)) return { verdict: 'UNKNOWN', confidence: null };
    return prob >= 0.5
      ? { verdict: 'FAKE', confidence: prob }
      : { verdict: 'REAL', confidence: 1 - prob };
  }

  function resolveDisplayConfidence(data) {
    if (!data) return null;
    const raw = data.confidence ?? data.model_confidence;
    if (raw != null) {
      const num = Number(raw);
      if (Number.isFinite(num) && num > 0) {
        const pct = num <= 1 ? Math.round(num * 100) : Math.round(num);
        return pct > 0 ? pct : null;
      }
    }
    const score = Number(data.risk_score);
    if (Number.isFinite(score)) {
      const pct = Math.round(Math.abs(score - 50) * 2);
      return pct > 0 ? pct : null;
    }
    return null;
  }

  /**
   * results: [{kind:'url'|'email'|'image', input, ok, data?, error?}]
   *   url/email data = AlertResponse; image data = media dict.
   */
  function buildOverlayModel(results) {
    const list = Array.isArray(results) ? results : [];
    const okResults = list.filter((r) => r && r.ok);
    const cards = list.map((r) => {
      if (!r || !r.ok) {
        return { kind: (r && r.kind) || 'unknown', input: (r && r.input) || '', failed: true, error: (r && r.error) || 'Analysis failed' };
      }
      if (r.kind === 'url') {
        const confPct = resolveDisplayConfidence(r.data);
        return {
          kind: 'url', input: r.input, failed: false,
          score: Number(r.data.risk_score), severity: r.data.severity || 'low',
          confidence: confPct != null ? confPct / 100 : null,
          confidencePct: confPct,
          explanation: r.data.explanation,
          indicators: r.data.indicators || [],
        };
      }
      if (r.kind === 'email') {
        const confPct = resolveDisplayConfidence(r.data);
        return {
          kind: 'email', input: r.input, failed: false,
          score: Number(r.data.risk_score), severity: r.data.severity || 'low',
          confidence: confPct != null ? confPct / 100 : null,
          confidencePct: confPct,
          explanation: r.data.explanation,
          mitre: r.data.mitre || [],
          network: (r.data.indicators || []).filter((i) =>
            String(i.type || '').toLowerCase().includes('url') ||
            String(i.type || '').toLowerCase().includes('domain') ||
            /^https?:\/\//i.test(String(i.value || ''))),
        };
      }
      const prob = Number(r.data.manipulation_probability);
      const verdict = deepfakeVerdict(prob);
      return {
        kind: 'image', input: r.input, failed: false,
        verdict: verdict.verdict, confidence: verdict.confidence,
        severity: r.data.severity || 'low', method: r.data.method,
        explanation: r.data.explanation,
      };
    });
    return { summary: detectLib.summarizeSeverities(okResults), cards };
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function badgeClass(sev) {
    const known = ['safe', 'low', 'medium', 'high', 'critical'];
    return `cg-badge--${known.includes(sev) ? sev : 'low'}`;
  }

  function renderCard(container, card) {
    const cardEl = el('div', 'cgext-card');
    const head = el('div', 'cgext-card__head');
    const label = { url: 'URL', email: 'Email', image: 'Image', unknown: 'Item' }[card.kind] || 'Item';
    head.appendChild(el('span', 'cgext-card__kind', label));
    const input = card.input || '';
    head.appendChild(el('span', 'cgext-card__input cg-score', input.length > 90 ? `${input.slice(0, 90)}…` : input));
    cardEl.appendChild(head);

    if (card.failed) {
      cardEl.classList.add('cgext-card--failed');
      cardEl.appendChild(el('p', 'cgext-card__error', card.error));
      container.appendChild(cardEl);
      return;
    }

    if (card.kind === 'image') {
      const line = el('div', 'cgext-card__metrics');
      line.appendChild(el('span', `cgext-card__verdict cg-score ${card.verdict === 'FAKE' ? 'is-fake' : 'is-real'}`, card.verdict));
      if (card.confidence != null && card.confidence > 0) {
        const pct = card.confidence <= 1 ? Math.round(card.confidence * 100) : Math.round(card.confidence);
        if (pct > 0) {
          line.appendChild(el('span', 'cgext-card__meta cg-score', `confidence ${pct}%`));
        }
      }
      if (card.method) line.appendChild(el('span', 'cgext-card__meta cg-score', `method ${card.method}`));
      cardEl.appendChild(line);
    } else {
      const line = el('div', 'cgext-card__metrics');
      line.appendChild(el('span', 'cgext-card__score cg-score', Number.isFinite(card.score) ? String(card.score) : '—'));
      line.appendChild(el('span', `cgext-pill-sev ${badgeClass(card.severity)}`, String(card.severity).toUpperCase()));
      const pct = card.confidencePct != null
        ? card.confidencePct
        : (Number.isFinite(card.confidence) && card.confidence > 0
            ? (card.confidence <= 1 ? Math.round(card.confidence * 100) : Math.round(card.confidence))
            : null);
      if (pct != null && pct > 0) {
        line.appendChild(el('span', 'cgext-card__meta cg-score', `confidence ${pct}%`));
      }
      cardEl.appendChild(line);
    }

    if (card.explanation) cardEl.appendChild(el('p', 'cgext-card__explanation', card.explanation));

    if (card.kind === 'email' && card.network && card.network.length) {
      const wrap = el('div', 'cgext-card__section');
      wrap.appendChild(el('p', 'cgext-card__label', 'Suspicious links / domains'));
      for (const ind of card.network) wrap.appendChild(el('span', 'cgext-card__tag cg-score', String(ind.value)));
      cardEl.appendChild(wrap);
    }
    if (card.kind === 'email' && card.mitre && card.mitre.length) {
      const wrap = el('div', 'cgext-card__section');
      wrap.appendChild(el('p', 'cgext-card__label', 'MITRE'));
      for (const tech of card.mitre) {
        const id = typeof tech === 'string' ? tech : tech.id;
        const name = typeof tech === 'string' ? '' : tech.name;
        wrap.appendChild(el('span', 'cgext-card__tag cg-score', name ? `${id} · ${name}` : String(id)));
      }
      cardEl.appendChild(wrap);
    }
    if (card.indicators && card.indicators.length) {
      const wrap = el('div', 'cgext-card__section');
      wrap.appendChild(el('p', 'cgext-card__label', 'Indicators'));
      for (const ind of card.indicators) {
        const row = el('div', 'cgext-card__indicator');
        row.appendChild(el('span', `cgext-pill-sev ${badgeClass(ind.severity)}`, String(ind.severity || 'low').toUpperCase()));
        row.appendChild(el('span', 'cgext-card__tag cg-score', String(ind.value ?? '')));
        if (ind.description) row.appendChild(el('span', 'cgext-card__meta', String(ind.description)));
        wrap.appendChild(row);
      }
      cardEl.appendChild(wrap);
    }
    if (card.kind === 'url') {
      const open = el('button', 'cgext-card__open');
      open.type = 'button';
      open.textContent = 'Open in popup';
      open.addEventListener('click', () => {
        const raw = globalThis.browser ?? globalThis.chrome;
        raw.runtime.sendMessage({ type: 'OPEN_URL_VIEW', url: card.input });
      });
      cardEl.appendChild(open);
    }
    container.appendChild(cardEl);
  }

  function show(results) {
    close();
    const model = buildOverlayModel(results);
    const root = document.createElement('div');
    root.id = ROOT_ID;
    const panel = el('div', 'cgext-overlay__panel');
    panel.appendChild(el('p', 'cgext-overlay__title', 'CyberGuard — batch analysis'));
    panel.appendChild(el('p', 'cgext-overlay__summary', model.summary));
    const list = el('div', 'cgext-overlay__cards');
    for (const card of model.cards) renderCard(list, card);
    panel.appendChild(list);
    const closeBtn = el('button', 'cgext-overlay__close');
    closeBtn.type = 'button';
    closeBtn.textContent = 'Close';
    closeBtn.addEventListener('click', close);
    panel.appendChild(closeBtn);
    root.appendChild(panel);
    root.addEventListener('click', (e) => {
      if (e.target === root) close();
    });
    document.documentElement.appendChild(root);
  }

  function close() {
    const existing = document.getElementById(ROOT_ID);
    if (existing) existing.remove();
  }

  globalThis.CyberGuardExt = globalThis.CyberGuardExt || {};
  globalThis.CyberGuardExt.overlayUi = { show, close, buildOverlayModel };
})();
