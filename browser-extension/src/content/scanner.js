/*
 * CyberGuard extension — page scanner content script (EXT-SCANNER-V2 S3, S5, S6).
 *
 * Runs on all http/https pages (document_idle).
 * Watches DOM mutations for email-body + image detections (NO link scanning per S3).
 *
 * S5 State Machine: idle -> detecting -> awaiting -> analyzing -> results.
 * S5 In-Flight Persistence:
 *   - On [Analyze]: snapshot selected items with requestId, AUTO-LOCK (pause observer).
 *   - Mutations during analyzing: DO NOT reset pill or drop request; queue as "+n new".
 *   - Dedup cache: content-hash -> result (TTL 10 min); re-detected items show cached score instantly, never re-sent.
 *   - Unlock re-enables observer.
 * S6 Lock Control:
 *   - [🔒] toggles locked state; observer paused; survives scroll; unlock resumes.
 *   - Lock state per-tab in-memory; toggle row in popup settings ("Pause on-page detection").
 */
/* global CyberGuardExt */
(function (global) {
  'use strict';

  const g = (global && global.document) ? global : (typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
  const getDoc = () => (g && g.document) || (typeof document !== 'undefined' ? document : null);

  const detectLib = g.CyberGuardExt && g.CyberGuardExt.detect;
  const pillUi = g.CyberGuardExt && g.CyberGuardExt.pillUi;
  if (!detectLib || !pillUi) return;
  if (g.location && detectLib.isExcludedHost(g.location.hostname)) return;
  if (typeof window !== 'undefined' && window.top !== window.self) return; // iframes excluded

  const DEFAULT_SETTINGS = {
    scan_email: true,
    scan_image: true,
    scan_allowlist: [],
    scan_max_detections: 20,
    pause_detection: false,
  };
  let settings = { ...DEFAULT_SETTINGS };

  // States: 'idle' | 'detecting' | 'awaiting' | 'analyzing' | 'results'
  let state = 'idle';
  let isLocked = false;
  let isAutoLocked = false;
  let currentRequestId = null;
  let activeSnapshot = [];
  let queuedNewDetections = [];

  // Dedup cache: content-hash -> { result, at } (TTL 10 min)
  const dedupCache = new Map();
  const DEDUP_TTL_MS = 10 * 60 * 1000;

  let latestItems = [];
  let observer = null;

  function computeHash(kind, val) {
    const s = `${kind}:${String(val || '')}`;
    let hash = 0;
    for (let i = 0; i < s.length; i++) {
      hash = ((hash << 5) - hash + s.charCodeAt(i)) | 0;
    }
    return `${kind}_${(hash >>> 0).toString(16)}`;
  }

  function getCached(hash) {
    if (!hash || !dedupCache.has(hash)) return null;
    const entry = dedupCache.get(hash);
    if (Date.now() - entry.at < DEDUP_TTL_MS) {
      return entry.result;
    }
    dedupCache.delete(hash);
    return null;
  }

  function formatCachedScore(res) {
    if (!res) return null;
    const score = (res.data && res.data.risk_score != null) ? res.data.risk_score : (res.risk_score != null ? res.risk_score : null);
    const sev = (res.data && res.data.severity) || res.severity || '';
    if (score != null) return `${score}${sev ? ' ' + String(sev).toUpperCase() : ''}`;
    return sev ? String(sev).toUpperCase() : 'CACHED';
  }

  function pageAllowed() {
    if (!g.location) return true;
    const list = (settings.scan_allowlist || []).map((d) => String(d).toLowerCase().trim()).filter(Boolean);
    if (!list.length) return true;
    const host = String(g.location.hostname || '').toLowerCase();
    return list.some((d) => host === d || host.endsWith(`.${d}`));
  }

  function scanDetections() {
    if (!pageAllowed()) return [];
    const doc = getDoc();
    if (!doc) return [];

    const items = [];
    // Scope change S3: NO <a href> link scanning! Only email and image.
    const email = settings.scan_email ? detectLib.detectEmail(doc) : null;
    const images = settings.scan_image ? detectLib.detectImages(doc, settings.scan_max_detections) : [];

    if (email) {
      const hash = computeHash('email', email.value);
      const cached = getCached(hash);
      items.push({
        id: 'email_0',
        kind: 'email',
        value: email.value,
        preview: email.value.slice(0, 80),
        locationHint: email.source || 'Email body',
        checked: true,
        hash,
        cachedScore: cached ? formatCachedScore(cached) : null,
      });
    }

    images.forEach((img, idx) => {
      const hash = computeHash('image', img.value);
      const cached = getCached(hash);
      items.push({
        id: `img_${idx}`,
        kind: 'image',
        value: img.value,
        thumb: img.value,
        locationHint: img.source || 'Image',
        checked: true,
        hash,
        cachedScore: cached ? formatCachedScore(cached) : null,
      });
    });

    return items;
  }

  function scan() {
    if (isLocked || isAutoLocked) return;
    if (state === 'analyzing') return;

    state = 'detecting';
    latestItems = scanDetections();
    pillUi.setItems(latestItems);
    state = 'awaiting';
  }

  // Debounce 500ms
  const batcher = detectLib.createBatcher(scan, 500);

  function scheduleScan() {
    if (isLocked) return;
    if (state === 'analyzing') {
      // S5: Mutations during analyzing: DO NOT reset pill or drop the request;
      // queue new detections as a "+n new" badge shown after results arrive.
      const fresh = scanDetections();
      const currentHashes = new Set(activeSnapshot.map((i) => i.hash));
      const queuedHashes = new Set(queuedNewDetections.map((i) => i.hash));
      for (const item of fresh) {
        if (!currentHashes.has(item.hash) && !queuedHashes.has(item.hash)) {
          queuedNewDetections.push(item);
          queuedHashes.add(item.hash);
        }
      }
      return;
    }
    if (isAutoLocked) return;
    batcher.add(0);
  }

  function armObserver() {
    if (observer) observer.disconnect();
    const doc = getDoc();
    if (!doc || !doc.body) return;
    if (typeof g.MutationObserver !== 'function') return;
    observer = new g.MutationObserver(scheduleScan);
    observer.observe(doc.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src'],
    });
  }

  function setLocked(locked) {
    isLocked = Boolean(locked);
    pillUi.setLocked(isLocked);
    if (isLocked) {
      if (observer) observer.disconnect();
    } else {
      isAutoLocked = false;
      armObserver();
      scheduleScan();
    }
  }

  function toggleLock() {
    setLocked(!isLocked);
  }

  async function loadSettings() {
    try {
      const raw = g.browser ?? g.chrome;
      if (raw && raw.storage && raw.storage.local) {
        const stored = await new Promise((resolve) => {
          try {
            raw.storage.local.get(Object.keys(DEFAULT_SETTINGS), (r) => resolve(r || {}));
          } catch (e) {
            resolve({});
          }
        });
        settings = { ...DEFAULT_SETTINGS, ...stored };
        if (settings.pause_detection) {
          setLocked(true);
        }
      }
    } catch (e) {
      settings = { ...DEFAULT_SETTINGS };
    }

    const raw = g.browser ?? g.chrome;
    if (raw && raw.storage && raw.storage.onChanged) {
      raw.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local') return;
        for (const key of Object.keys(DEFAULT_SETTINGS)) {
          if (changes[key]) settings[key] = changes[key].newValue;
        }
        if (changes.pause_detection) {
          setLocked(Boolean(changes.pause_detection.newValue));
        }
        scheduleScan();
      });
    }
  }

  // S5 In-Flight Persistence & Analysis Execution
  async function handleAnalyze(selectedItems) {
    const toAnalyze = Array.isArray(selectedItems) && selectedItems.length > 0
      ? selectedItems
      : pillUi.getSelectedItems();

    if (!toAnalyze.length) {
      return { ok: true, results: [] };
    }

    // 1. Snapshot selected items with a requestId
    currentRequestId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    activeSnapshot = [...toAnalyze];
    queuedNewDetections = [];

    // 2. AUTO-LOCK (pause normal scanning MutationObserver callbacks)
    isAutoLocked = true;

    // 3. Keep pill in "Analyzing…" state
    state = 'analyzing';
    pillUi.setLoading(true, 'Analyzing…');

    // 4. Split items into cached vs uncached
    const cachedResults = [];
    const uncachedItems = [];

    for (const item of activeSnapshot) {
      const hit = getCached(item.hash);
      if (hit) {
        cachedResults.push(hit);
      } else {
        uncachedItems.push(item);
      }
    }

    let backendResults = [];

    if (uncachedItems.length > 0) {
      // Build batch for uncached items only
      const images = [];
      const emails = [];

      for (const item of uncachedItems) {
        if (item.kind === 'email') {
          emails.push(item.value);
        } else if (item.kind === 'image') {
          let dataUrl = null;
          try {
            if (g.fetch) {
              const res = await g.fetch(item.value, { credentials: 'omit' });
              const blob = await res.blob();
              if (blob.size <= 5 * 1024 * 1024 && g.FileReader) {
                dataUrl = await new Promise((resolve, reject) => {
                  const reader = new g.FileReader();
                  reader.onload = () => resolve(reader.result);
                  reader.onerror = reject;
                  reader.readAsDataURL(blob);
                });
              }
            }
          } catch (e) {
            // cross-origin or size failure
          }
          images.push({ src: item.value, dataUrl, hash: item.hash });
        }
      }

      const batch = {
        type: 'ANALYZE_BATCH',
        urls: [], // S3 scope change: links removed from scanner
        emails,
        images,
        pageUrl: g.location ? g.location.href : '',
        requestId: currentRequestId,
      };

      const raw = g.browser ?? g.chrome;
      const res = await new Promise((resolve) => {
        if (!raw || !raw.runtime || !raw.runtime.sendMessage) {
          resolve({ ok: false, error: 'extension runtime unavailable' });
          return;
        }
        raw.runtime.sendMessage(batch, (response) => {
          resolve(response || { ok: false, error: 'no response from background' });
        });
      });

      if (res && res.ok && Array.isArray(res.results)) {
        backendResults = res.results;
        // Save uncached results into dedup cache
        backendResults.forEach((r, idx) => {
          const matchedItem = uncachedItems[idx];
          if (matchedItem && matchedItem.hash) {
            dedupCache.set(matchedItem.hash, { result: r, at: Date.now() });
          }
        });
      } else {
        state = 'awaiting';
        isAutoLocked = false;
        if (!isLocked) armObserver();
        throw new Error((res && res.error) || 'Analysis failed');
      }
    }

    const finalResults = [...cachedResults, ...backendResults];

    // 5. Results arrived: state -> results
    state = 'results';
    isAutoLocked = false;

    // Show "+n new" badge if mutations occurred during analyzing
    if (queuedNewDetections.length > 0) {
      pillUi.setNewBadge(queuedNewDetections.length);
    }

    // If locked was not explicitly requested by user, re-arm observer on unlock
    if (!isLocked) {
      armObserver();
    }

    return { ok: true, results: finalResults, requestId: currentRequestId };
  }

  // Initialize pill handlers
  pillUi.init({
    onAnalyze: handleAnalyze,
    onToggleLock: (locked) => setLocked(locked),
    onShowOverlay: (results) => {
      if (g.CyberGuardExt && g.CyberGuardExt.overlayUi) {
        g.CyberGuardExt.overlayUi.show(results);
      }
    },
  });

  // Message listener for popup settings and remote lock controls
  const raw = g.browser ?? g.chrome;
  if (raw && raw.runtime && raw.runtime.onMessage) {
    raw.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (!msg) return;
      if (msg.type === 'GET_LOCK_STATE') {
        sendResponse({ ok: true, locked: isLocked });
        return true;
      }
      if (msg.type === 'SET_LOCK_STATE') {
        setLocked(Boolean(msg.locked));
        sendResponse({ ok: true, locked: isLocked });
        return true;
      }
      if (msg.type === 'TOGGLE_LOCK') {
        toggleLock();
        sendResponse({ ok: true, locked: isLocked });
        return true;
      }
    });
  }

  (async () => {
    await loadSettings();
    scan();
    armObserver();
  })();

  // Export for node/unit testing
  g.CyberGuardScanner = {
    getState: () => state,
    setState: (s) => { state = s; },
    isLocked: () => isLocked,
    setLocked,
    toggleLock,
    scanDetections,
    scan,
    scheduleScan,
    cancelBatcher: () => batcher.cancel(),
    handleAnalyze,
    getDedupCache: () => dedupCache,
    computeHash,
    getQueuedNewDetections: () => queuedNewDetections,
    getActiveSnapshot: () => activeSnapshot,
    getCurrentRequestId: () => currentRequestId,
  };
})(typeof global !== 'undefined' ? global : (typeof globalThis !== 'undefined' ? globalThis : this));
