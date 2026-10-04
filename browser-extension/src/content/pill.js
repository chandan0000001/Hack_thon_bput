/*
 * CyberGuard extension — floating pill UI (EXT-SCANNER-V2 S4).
 *
 * Collapsed pill: counts ("1 email · 2 images") + [Analyze] + [🔒] + [×].
 * Click pill body -> EXPANDED panel listing each detected item as a row:
 *   type icon, snippet/preview (email first 80 chars / image thumb or src host),
 *   location hint, checkbox (pre-checked), per-row [×] to dismiss.
 * Footer: [Analyze selected (n)] [Analyze all] [Lock] [Collapse].
 * Only selected items are sent for analysis.
 */
/* global CyberGuardExt */
(function (global) {
  'use strict';

  const g = (global && global.document) ? global : (typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
  const getDoc = () => (g && g.document) || (typeof document !== 'undefined' ? document : null);

  const PILL_ID = 'cgext-pill';

  let items = []; // Array of detected item objects
  let counts = { email: 0, image: 0 };
  let isLocked = false;
  let isDismissed = false; // sticky until an unlock (popup auto-detect toggle)
  let isExpanded = false;
  let newBadgeCount = 0;
  let handlers = {
    onAnalyze: null,
    onToggleLock: null,
    onShowOverlay: null,
    onDismiss: null,
  };

  function ensurePill() {
    const doc = getDoc();
    if (!doc) return null;
    let pill = doc.getElementById(PILL_ID);
    if (pill) return pill;

    pill = doc.createElement('div');
    pill.id = PILL_ID;
    pill.className = 'cgext-pill';

    // Collapsed bar
    const collapsed = doc.createElement('div');
    collapsed.className = 'cgext-pill__collapsed';

    const body = doc.createElement('div');
    body.className = 'cgext-pill__body';
    body.setAttribute('role', 'button');
    body.setAttribute('tabindex', '0');
    body.setAttribute('title', 'Click to view details');

    const text = doc.createElement('span');
    text.className = 'cgext-pill__text';

    const badge = doc.createElement('span');
    badge.className = 'cgext-pill__badge';
    badge.hidden = true;

    const lockedTag = doc.createElement('span');
    lockedTag.className = 'cgext-pill__locked-tag';
    lockedTag.hidden = true;
    lockedTag.textContent = '🔒 Locked';

    body.append(text, badge, lockedTag);

    const analyzeBtn = doc.createElement('button');
    analyzeBtn.type = 'button';
    analyzeBtn.className = 'cgext-pill__analyze';
    analyzeBtn.textContent = 'Analyze';

    const lockBtn = doc.createElement('button');
    lockBtn.type = 'button';
    lockBtn.className = 'cgext-pill__lock';
    lockBtn.setAttribute('title', 'Toggle Lock / Pause detection');
    lockBtn.textContent = '🔒';

    const closeBtn = doc.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'cgext-pill__close';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.textContent = '×';

    collapsed.append(body, analyzeBtn, lockBtn, closeBtn);

    // Expanded panel
    const panel = doc.createElement('div');
    panel.className = 'cgext-pill__panel';
    panel.hidden = true;

    const panelHeader = doc.createElement('div');
    panelHeader.className = 'cgext-pill__panel-header';

    const panelTitle = doc.createElement('span');
    panelTitle.className = 'cgext-pill__panel-title';
    panelTitle.textContent = 'Detected Items';

    const panelBadge = doc.createElement('span');
    panelBadge.className = 'cgext-pill__badge';
    panelBadge.hidden = true;

    const panelClose = doc.createElement('button');
    panelClose.type = 'button';
    panelClose.className = 'cgext-pill__panel-close';
    panelClose.setAttribute('aria-label', 'Collapse');
    panelClose.textContent = '×';

    panelHeader.append(panelTitle, panelBadge, panelClose);

    const rowsContainer = doc.createElement('div');
    rowsContainer.className = 'cgext-pill__rows';

    const panelFooter = doc.createElement('div');
    panelFooter.className = 'cgext-pill__footer';

    const btnAnalyzeSelected = doc.createElement('button');
    btnAnalyzeSelected.type = 'button';
    btnAnalyzeSelected.className = 'cgext-pill__btn cgext-pill__btn-analyze-selected';
    btnAnalyzeSelected.textContent = 'Analyze selected (0)';

    const btnAnalyzeAll = doc.createElement('button');
    btnAnalyzeAll.type = 'button';
    btnAnalyzeAll.className = 'cgext-pill__btn cgext-pill__btn-analyze-all';
    btnAnalyzeAll.textContent = 'Analyze all';

    const btnLock = doc.createElement('button');
    btnLock.type = 'button';
    btnLock.className = 'cgext-pill__btn cgext-pill__btn-lock';
    btnLock.textContent = 'Lock';

    const btnCollapse = doc.createElement('button');
    btnCollapse.type = 'button';
    btnCollapse.className = 'cgext-pill__btn cgext-pill__btn-collapse';
    btnCollapse.textContent = 'Collapse';

    panelFooter.append(btnAnalyzeSelected, btnAnalyzeAll, btnLock, btnCollapse);
    panel.append(panelHeader, rowsContainer, panelFooter);

    pill.append(collapsed, panel);
    (doc.body || doc.documentElement).appendChild(pill);

    // Event listeners
    body.addEventListener('click', () => {
      toggleExpand();
    });

    analyzeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      runAnalysis(getSelectedItems());
    });

    lockBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleLock();
    });

    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      isDismissed = true;
      pill.hidden = true;
      if (typeof handlers.onDismiss === 'function') handlers.onDismiss();
    });

    panelClose.addEventListener('click', () => {
      collapse();
    });

    btnCollapse.addEventListener('click', () => {
      collapse();
    });

    btnLock.addEventListener('click', () => {
      toggleLock();
    });

    btnAnalyzeAll.addEventListener('click', () => {
      items.forEach((it) => { it.checked = true; });
      updateRows();
      runAnalysis(items);
    });

    btnAnalyzeSelected.addEventListener('click', () => {
      runAnalysis(getSelectedItems());
    });

    return pill;
  }

  function formatCountString(c) {
    const parts = [];
    if (c.email) parts.push(`${c.email} ${c.email === 1 ? 'email' : 'emails'}`);
    if (c.image) parts.push(`${c.image} ${c.image === 1 ? 'image' : 'images'}`);
    if (c.url) parts.push(`${c.url} ${c.url === 1 ? 'link' : 'links'}`);
    if (!parts.length) return '';
    return parts.join(' · ');
  }

  function updateFooterCounts() {
    const pill = ensurePill();
    if (!pill) return;
    const selected = getSelectedItems();
    const btn = pill.querySelector('.cgext-pill__btn-analyze-selected');
    if (btn) {
      btn.textContent = `Analyze selected (${selected.length})`;
      btn.disabled = selected.length === 0;
    }
  }

  function updateRows() {
    const doc = getDoc();
    const pill = ensurePill();
    if (!doc || !pill) return;
    const container = pill.querySelector('.cgext-pill__rows');
    if (!container) return;
    container.replaceChildren();

    if (!items.length) {
      const empty = doc.createElement('div');
      empty.className = 'cgext-pill__empty';
      empty.textContent = 'No items detected on this page.';
      container.appendChild(empty);
      updateFooterCounts();
      return;
    }

    items.forEach((item) => {
      const row = doc.createElement('div');
      row.className = 'cgext-pill__row';
      row.setAttribute('data-id', item.id);

      const check = doc.createElement('input');
      check.type = 'checkbox';
      check.className = 'cgext-pill__checkbox';
      check.checked = item.checked !== false;
      check.setAttribute('data-id', item.id);
      check.addEventListener('change', () => {
        item.checked = check.checked;
        updateFooterCounts();
      });

      const icon = doc.createElement('span');
      icon.className = 'cgext-pill__type-icon';
      icon.textContent = item.kind === 'email' ? '✉' : '🖼';

      const info = doc.createElement('div');
      info.className = 'cgext-pill__item-info';

      const preview = doc.createElement('div');
      preview.className = 'cgext-pill__preview';

      if (item.kind === 'image') {
        if (item.thumb || (item.value && /^https?:\/\//.test(item.value))) {
          const img = doc.createElement('img');
          img.className = 'cgext-pill__thumb';
          img.src = item.thumb || item.value;
          img.alt = 'preview';
          preview.appendChild(img);
        }
        let host = '';
        try { host = new URL(item.value).hostname; } catch (e) { host = item.value || ''; }
        const hostSpan = doc.createElement('span');
        hostSpan.className = 'cgext-pill__host';
        hostSpan.textContent = host;
        preview.appendChild(hostSpan);
      } else {
        const textSpan = doc.createElement('span');
        textSpan.className = 'cgext-pill__snippet';
        const txt = String(item.preview || item.value || '').trim();
        textSpan.textContent = txt.slice(0, 80) + (txt.length > 80 ? '…' : '');
        preview.appendChild(textSpan);
      }

      const hint = doc.createElement('span');
      hint.className = 'cgext-pill__location';
      hint.textContent = item.locationHint || (item.kind === 'email' ? 'Email body' : 'Image');

      info.append(preview, hint);

      if (item.cachedScore != null) {
        const cached = doc.createElement('span');
        cached.className = 'cgext-pill__cached';
        cached.textContent = `Score: ${item.cachedScore}`;
        info.appendChild(cached);
      }

      const dismissBtn = doc.createElement('button');
      dismissBtn.type = 'button';
      dismissBtn.className = 'cgext-pill__item-dismiss';
      dismissBtn.setAttribute('title', 'Dismiss item');
      dismissBtn.textContent = '×';
      dismissBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dismissItem(item.id);
      });

      row.append(check, icon, info, dismissBtn);
      container.appendChild(row);
    });

    updateFooterCounts();
  }

  function dismissItem(id) {
    items = items.filter((it) => it.id !== id);
    const emailCount = items.filter((it) => it.kind === 'email').length;
    const imgCount = items.filter((it) => it.kind === 'image').length;
    const urlCount = items.filter((it) => it.kind === 'url').length;
    setCounts({ email: emailCount, image: imgCount, url: urlCount });
    updateRows();
  }

  function setItems(newItems) {
    items = Array.isArray(newItems) ? newItems : [];
    items.forEach((it, idx) => {
      if (!it.id) it.id = `cg_item_${idx}_${Date.now()}`;
      if (it.checked === undefined) it.checked = true;
      if (!it.preview) {
        if (it.kind === 'email') it.preview = String(it.value || '').slice(0, 80);
        else it.preview = it.value || '';
      }
    });
    const emailCount = items.filter((it) => it.kind === 'email').length;
    const imgCount = items.filter((it) => it.kind === 'image').length;
    const urlCount = items.filter((it) => it.kind === 'url').length;
    setCounts({ email: emailCount, image: imgCount, url: urlCount });
    updateRows();
  }

  function getItems() {
    return items;
  }

  function getSelectedItems() {
    return items.filter((it) => it.checked !== false);
  }

  function setCounts(next) {
    if (isDismissed) return;
    counts = next || { email: 0, image: 0 };
    const line = formatCountString(counts);
    const pill = ensurePill();
    if (!pill) return;
    pill.classList.remove('cgext-pill--loading', 'cgext-pill--error');

    if (!line && !newBadgeCount && !isLocked) {
      pill.hidden = true;
      return;
    }
    pill.hidden = false;
    const textEl = pill.querySelector('.cgext-pill__text');
    if (textEl) textEl.textContent = line || 'Detections';

    const analyzeBtn = pill.querySelector('.cgext-pill__analyze');
    if (analyzeBtn) {
      analyzeBtn.hidden = false;
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = 'Analyze';
    }
  }

  function setNewBadge(count) {
    newBadgeCount = Number(count) || 0;
    const pill = ensurePill();
    if (!pill) return;
    const badges = pill.querySelectorAll('.cgext-pill__badge');
    badges.forEach((b) => {
      if (newBadgeCount > 0) {
        b.hidden = false;
        b.textContent = `+${newBadgeCount} new`;
      } else {
        b.hidden = true;
      }
    });
  }

  function setLocked(locked) {
    isLocked = Boolean(locked);
    // Unlocking (popup auto-detect toggle) revives a dismissed pill.
    if (!isLocked) isDismissed = false;
    const pill = ensurePill();
    if (!pill) return;
    if (isLocked) pill.classList.add('cgext-pill--locked');
    else pill.classList.remove('cgext-pill--locked');

    const tag = pill.querySelector('.cgext-pill__locked-tag');
    if (tag) tag.hidden = !isLocked;

    const lockBtn = pill.querySelector('.cgext-pill__lock');
    if (lockBtn) lockBtn.textContent = isLocked ? '🔓' : '🔒';

    const btnLock = pill.querySelector('.cgext-pill__btn-lock');
    if (btnLock) btnLock.textContent = isLocked ? 'Unlock' : 'Lock';
  }

  function toggleLock() {
    isLocked = !isLocked;
    setLocked(isLocked);
    if (typeof handlers.onToggleLock === 'function') {
      handlers.onToggleLock(isLocked);
    }
  }

  function expand() {
    isExpanded = true;
    const pill = ensurePill();
    if (!pill) return;
    pill.classList.add('cgext-pill--expanded');
    const panel = pill.querySelector('.cgext-pill__panel');
    if (panel) panel.hidden = false;
    updateRows();
  }

  function collapse() {
    isExpanded = false;
    const pill = ensurePill();
    if (!pill) return;
    pill.classList.remove('cgext-pill--expanded');
    const panel = pill.querySelector('.cgext-pill__panel');
    if (panel) panel.hidden = true;
  }

  function toggleExpand() {
    if (isExpanded) collapse();
    else expand();
  }

  function setLoading(isLoading = true, message = 'Analyzing…') {
    if (isDismissed) return;
    const pill = ensurePill();
    if (!pill) return;
    pill.hidden = false;
    if (isLoading) {
      pill.classList.add('cgext-pill--loading');
      const textEl = pill.querySelector('.cgext-pill__text');
      if (textEl) textEl.textContent = message;
      const analyzeBtn = pill.querySelector('.cgext-pill__analyze');
      if (analyzeBtn) analyzeBtn.hidden = true;
    } else {
      pill.classList.remove('cgext-pill--loading');
      const analyzeBtn = pill.querySelector('.cgext-pill__analyze');
      if (analyzeBtn) analyzeBtn.hidden = false;
    }
  }

  function setError(message = 'Analysis failed') {
    if (isDismissed) return;
    const pill = ensurePill();
    if (!pill) return;
    pill.hidden = false;
    pill.classList.remove('cgext-pill--loading');
    pill.classList.add('cgext-pill--error');
    const textEl = pill.querySelector('.cgext-pill__text');
    if (textEl) textEl.textContent = message;
    const analyzeBtn = pill.querySelector('.cgext-pill__analyze');
    if (analyzeBtn) {
      analyzeBtn.hidden = false;
      analyzeBtn.textContent = 'Retry';
      analyzeBtn.disabled = false;
    }
  }

  function reset() {
    const pill = ensurePill();
    if (!pill) return;
    pill.classList.remove('cgext-pill--loading', 'cgext-pill--error');
    const analyzeBtn = pill.querySelector('.cgext-pill__analyze');
    if (analyzeBtn) {
      analyzeBtn.hidden = false;
      analyzeBtn.textContent = 'Analyze';
    }
  }

  async function runAnalysis(selected = getSelectedItems()) {
    collapse();
    setLoading(true);
    try {
      if (typeof handlers.onAnalyze === 'function') {
        const res = await handlers.onAnalyze(selected);
        if (!res || res.ok === false) {
          throw new Error((res && res.error) || 'Analysis failed');
        }
        reset();
        setCounts(counts);
        if (typeof handlers.onShowOverlay === 'function') {
          handlers.onShowOverlay(res.results || []);
        }
      }
    } catch (err) {
      setError((err && err.message) || 'Analysis failed');
    }
  }

  function init(nextHandlers) {
    handlers = { ...handlers, ...nextHandlers };
    const pill = ensurePill();
    if (pill) pill.hidden = true;
  }

  const pillUi = {
    init,
    ensurePill,
    setItems,
    getItems,
    getSelectedItems,
    setCounts,
    setLoading,
    setError,
    reset,
    setLocked,
    isLocked: () => isLocked,
    isDismissed: () => isDismissed,
    setNewBadge,
    expand,
    collapse,
    isExpanded: () => isExpanded,
    runAnalysis,
    dismissItem,
  };

  g.CyberGuardExt = g.CyberGuardExt || {};
  g.CyberGuardExt.pillUi = pillUi;
})(typeof global !== 'undefined' ? global : (typeof globalThis !== 'undefined' ? globalThis : this));
