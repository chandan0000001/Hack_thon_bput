/*
 * CyberGuard extension — page scanner content script (EXT-P3).
 *
 * Runs on all http/https pages (document_idle). Watches DOM mutations,
 * batches URL / email / image detections (local-only — nothing is sent to
 * the backend until the user clicks [Analyze?] on the pill) and hands the
 * pill its counts. Settings live in chrome.storage.local:
 *   { scan_url: bool, scan_email: bool, scan_image: bool,
 *     scan_allowlist: string[] (default [] = all domains),
 *     scan_max_detections: number (default 20) }
 */
/* global CyberGuardExt */
(function () {
  'use strict';

  const detectLib = globalThis.CyberGuardExt && globalThis.CyberGuardExt.detect;
  const pillUi = globalThis.CyberGuardExt && globalThis.CyberGuardExt.pillUi;
  if (!detectLib || !pillUi) return;
  if (detectLib.isExcludedHost(location.hostname)) return;
  if (window.top !== window.self) return; // iframes: the top page owns the pill

  const DEFAULT_SETTINGS = {
    scan_url: true,
    scan_email: true,
    scan_image: true,
    scan_allowlist: [],
    scan_max_detections: 20,
  };
  let settings = { ...DEFAULT_SETTINGS };

  let latest = { url: [], email: null, image: [] };

  function pageAllowed() {
    const list = (settings.scan_allowlist || []).map((d) => String(d).toLowerCase().trim()).filter(Boolean);
    if (!list.length) return true;
    const host = String(location.hostname || '').toLowerCase();
    return list.some((d) => host === d || host.endsWith(`.${d}`));
  }

  function scan() {
    if (!pageAllowed()) {
      latest = { url: [], email: null, image: [] };
      pillUi.setCounts({ url: 0, email: 0, image: 0 });
      return;
    }
    const urls = settings.scan_url
      ? detectLib.filterByAllowlist(detectLib.detectUrls(document, settings.scan_max_detections), settings.scan_allowlist, location.hostname)
      : [];
    const email = settings.scan_email ? detectLib.detectEmail(document) : null;
    const images = settings.scan_image ? detectLib.detectImages(document, settings.scan_max_detections) : [];
    latest = { url: urls, email, image: images };
    pillUi.setCounts({ url: urls.length, email: email ? 1 : 0, image: images.length });
  }

  // Debounce 500ms — mutation storms collapse into one scan.
  const batcher = detectLib.createBatcher(scan, 500);

  function scheduleScan() {
    batcher.add(0);
  }

  function armObserver() {
    const observer = new MutationObserver(scheduleScan);
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'href'] });
  }

  async function loadSettings() {
    try {
      const raw = globalThis.browser ?? globalThis.chrome;
      const stored = await new Promise((resolve) => {
        try {
          raw.storage.local.get(Object.keys(DEFAULT_SETTINGS), (r) => resolve(r || {}));
        } catch (e) {
          resolve({});
        }
      });
      settings = { ...DEFAULT_SETTINGS, ...stored };
    } catch (e) {
      settings = { ...DEFAULT_SETTINGS };
    }
    if ((globalThis.browser ?? globalThis.chrome).storage.onChanged) {
      (globalThis.browser ?? globalThis.chrome).storage.onChanged.addListener((changes, area) => {
        if (area !== 'local') return;
        for (const key of Object.keys(DEFAULT_SETTINGS)) {
          if (changes[key]) settings[key] = changes[key].newValue;
        }
        scheduleScan();
      });
    }
  }

  // [Analyze?] click -> assemble the batch (images are inlined as data URLs
  // from the page's own origin; failures degrade to a skipped entry) and ask
  // the background to run it.
  async function buildBatch() {
    const images = [];
    for (const img of latest.image) {
      try {
        const res = await fetch(img.value, { credentials: 'omit' });
        const blob = await res.blob();
        if (blob.size <= 5 * 1024 * 1024) {
          const dataUrl = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsDataURL(blob);
          });
          images.push({ src: img.value, dataUrl });
          continue;
        }
      } catch (e) { /* cross-origin or too large -> skipped */ }
      images.push({ src: img.value, dataUrl: null });
    }
    return {
      type: 'ANALYZE_BATCH',
      urls: latest.url.map((u) => u.value),
      emails: latest.email ? [latest.email.value] : [],
      images,
      pageUrl: location.href,
    };
  }

  pillUi.init({
    onAnalyze: async () => {
      const batch = await buildBatch();
      const raw = globalThis.browser ?? globalThis.chrome;
      return new Promise((resolve) => {
        raw.runtime.sendMessage(batch, (res) => resolve(res || { ok: false, error: 'no response from background' }));
      });
    },
    onShowOverlay: (results) => globalThis.CyberGuardExt.overlayUi.show(results),
  });

  (async () => {
    await loadSettings();
    scan();
    armObserver();
  })();
})();
