#!/usr/bin/env node
/*
 * EXT-P3 — Chromium Playwright walkthrough for the content scanner.
 *
 * Local servers (no real backend):
 *   :8000  mock CyberGuard API  (/analysis/url, /analysis/email, /analysis/media)
 *   :51888 test page            (3 links + 1 content-sized image)
 *
 * Flow: inject session -> open test page -> pill appears with counts ->
 * [Analyze?] -> overlay shows 4 cards -> [Open in popup] on the URL card ->
 * popup.html?view=url&url=… tab opens with the input pre-filled.
 * Every state dumps text (screenshot-as-text).
 */
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { deflateSync } from 'node:zlib';

const EXT_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(EXT_ROOT, 'dist', 'chromium');
const PROFILE = join(EXT_ROOT, 'e2e', 'artifacts', 'profile-p3');
const WEB_PORT = 51888;
// The real backend may own :8000 — the mock API runs on :8010 and the
// extension is rebuilt against it for the duration of this e2e.
const API_PORT = 8010;

let chromium;
try {
  ({ chromium } = createRequire(import.meta.url)('playwright'));
} catch {
  ({ chromium } = createRequire(import.meta.url)('/usr/lib/node_modules/playwright'));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const URL_RESULTS = [
  { risk_score: 91, severity: 'high', confidence: 0.93, explanation: 'Credential-harvesting kit.', indicators: [{ type: 'url', value: 'https://phish-a.example/login', severity: 'high', description: 'Look-alike login' }], mitre: [] },
  { risk_score: 55, severity: 'medium', confidence: 0.8, explanation: 'Suspicious redirect chain.', indicators: [], mitre: [] },
  { risk_score: 12, severity: 'low', confidence: 0.7, explanation: 'No threats found.', indicators: [], mitre: [] },
];
const MEDIA_RESULT = {
  module: 'deepfake', media_type: 'image', manipulation_probability: 0.9,
  authenticity_score: 0.1, risk_score: 95, severity: 'critical', method: 'cnn-ensemble',
  explanation: 'Synthetic artifacts.', indicators: [],
};

function startMockApi(port) {
  let urlHits = 0;
  const server = http.createServer((req, res) => {
    const body = req.url.includes('/analysis/url')
      ? URL_RESULTS[Math.min(urlHits++, URL_RESULTS.length - 1)]
      : req.url.includes('/analysis/media')
        ? MEDIA_RESULT
        : { email: 'mock' };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}

// Minimal PNG encoder: solid-color image of any size (for a >200x200 detection target).
function solidPng(size) {
  const crcTable = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  const crc32 = (buf) => {
    let c = 0xffffffff;
    for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 2; // RGB
  const row = Buffer.concat([Buffer.from([0]), Buffer.alloc(size * 3, 0x26)]);
  const raw = Buffer.concat(Array.from({ length: size }, () => row));
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function startTestPage(port) {
  const icon = solidPng(300);
  const html = `<!doctype html><html><body>
    <h1>Scanner test page</h1>
    <a href="https://phish-a.example/login">Great deals</a>
    <a href="https://phish-b.example/verify">Verify account</a>
    <a href="https://safe-a.example/docs">Docs</a>
    <img src="/img.png" width="420" height="380" alt="content">
  </body></html>`;
  const server = http.createServer((req, res) => {
    if (req.url === '/img.png') {
      res.writeHead(200, { 'content-type': 'image/png' });
      res.end(icon);
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html);
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}

async function resolveExtensionId(context) {
  try {
    const sw = await context.waitForEvent('serviceworker', { timeout: 15000 });
    const id = new URL(sw.url()).host;
    if (/^[a-p]{32}$/.test(id)) return id;
  } catch { /* fall through */ }
  const existing = context.serviceWorkers().map((sw) => new URL(sw.url()).host).find((h) => /^[a-p]{32}$/.test(h));
  if (existing) return existing;
  throw new Error('extension service worker not found');
}

async function main() {
  execFileSync('node', ['build.mjs'], {
    cwd: EXT_ROOT,
    env: { ...process.env, EXT_API_BASE_URL: `http://localhost:${API_PORT}/api/v1` },
    stdio: 'ignore',
  });
  const apiServer = await startMockApi(API_PORT);
  const pageServer = await startTestPage(WEB_PORT);
  const context = await chromium.launchPersistentContext(PROFILE, {
    headless: false,
    args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`, '--no-first-run', '--no-default-browser-check'],
  });
  const results = [];
  const check = (name, ok, detail = '') => {
    results.push({ name, ok });
    console.log(`${ok ? 'PASS' : 'FAIL'} — ${name}${detail ? ` (${detail})` : ''}`);
  };

  try {
    const extId = await resolveExtensionId(context);

    // Inject a live session into storage.local (the background's api client
    // reads it directly), then load the test page.
    const bootstrap = await context.newPage();
    await bootstrap.goto(`chrome-extension://${extId}/popup/popup.html`);
    await bootstrap.evaluate(() => chrome.storage.local.set({
      extAuth: { access_token: 'e2e-token', refresh_token: 'e2e-rt', expires_at: Math.floor(Date.now() / 1000) + 3600, email: 'demo@cyberguard.local' },
    }));
    await bootstrap.close().catch(() => {});

    const page = await context.newPage();
    await page.goto(`http://localhost:${WEB_PORT}/test.html`);

    // ---- Pill appears with detection counts ---------------------------
    await page.waitForSelector('#cgext-pill:not([hidden])', { timeout: 15000 });
    await sleep(300);
    const pillText = await page.evaluate(() => document.getElementById('cgext-pill').innerText);
    console.log(`\n===== [pill] =====\n${pillText.replace(/\n/g, ' | ')}`);
    check('pill shows "3 links · 1 image detected"', /3 links · 1 image detected/.test(pillText), pillText.replace(/\n/g, ' '));

    // ---- Analyze -> overlay --------------------------------------------
    await page.click('#cgext-pill .cgext-pill__analyze');
    // The mock API answers instantly, so the loading pill may flash by —
    // accept either the explicit loading class or the overlay already up.
    const loadingSeen = await page
      .waitForSelector('#cgext-pill.cgext-pill--loading', { timeout: 3000 })
      .then(() => true)
      .catch(() => false);
    check('pill shows loading state', loadingSeen, loadingSeen ? 'loading pill seen' : 'batch too fast; overlay check below covers it');
    await page.waitForSelector('#cgext-overlay-root', { timeout: 20000 });
    await sleep(300);
    const overlayText = await page.evaluate(() => document.getElementById('cgext-overlay-root').innerText);
    console.log(`\n===== [overlay] =====\n${overlayText}`);
    check('overlay summary counts severities', /1 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW/.test(overlayText));
    check('overlay shows 4 cards (3 URL + 1 image + no failures)',
      (overlayText.match(/Open in popup/g) || []).length === 3 &&
      /FAKE/.test(overlayText) && !/Analysis failed/.test(overlayText),
      `${(overlayText.match(/cgext-card/g) || []).length} nodes`);

    // ---- Open in popup -> pre-filled URL view ---------------------------
    await page.locator('.cgext-card__open').first().click();
    const popupTab = await context
      .waitForEvent('page', { timeout: 10000 })
      .catch(() => null);
    check('Open in popup opened the popup', !!popupTab, popupTab && popupTab.url());
    await popupTab.waitForSelector('#url-input', { timeout: 10000 });
    await sleep(1200); // boot + prefill
    const prefilled = await popupTab.inputValue('#url-input');
    const urlViewVisible = await popupTab.evaluate(() => !document.getElementById('view-url').hidden);
    check('popup URL view pre-filled with the card URL',
      urlViewVisible && prefilled === 'https://phish-a.example/login', prefilled);
    await dump(popupTab, 'popup: URL view pre-filled');

    await popupTab.close().catch(() => {});
    await page.close().catch(() => {});
  } finally {
    await context.close().catch(() => {});
    apiServer.close();
    pageServer.close();
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\nE2E RESULTS: ${results.length - failed.length}/${results.length} passed`);
  if (failed.length) {
    console.log('FAILED:', failed.map((f) => f.name).join(' | '));
    process.exit(1);
  }
}

async function dump(page, label) {
  const t = await page.evaluate(() => document.body.innerText.trim());
  console.log(`\n===== [${label}] =====\n${t}`);
}

main().catch((err) => {
  console.error('E2E error:', err);
  process.exit(1);
});
