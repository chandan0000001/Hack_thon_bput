#!/usr/bin/env node
/*
 * EXT-SCANNER-V2 S8 — Playwright E2E walkthrough:
 *   1. Navigate to mock-malicious URL -> interstitial appears with reason -> [Continue anyway] -> original page loads.
 *   2. Page with 2 images: press Analyze -> scroll/append DOM mid-flight -> overlay still shows the 2 results + "+1 new" badge.
 *   3. Lock pill -> append image -> count unchanged; unlock -> count updates.
 */
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { deflateSync } from 'node:zlib';

const EXT_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(EXT_ROOT, 'dist', 'chromium');
const PROFILE = join(EXT_ROOT, 'e2e', 'artifacts', 'profile-scanner-v2');
const WEB_PORT = 51888;
const API_PORT = 8010;

let chromium;
try {
  ({ chromium } = createRequire(import.meta.url)('playwright'));
} catch {
  ({ chromium } = createRequire(import.meta.url)('/usr/lib/node_modules/playwright'));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

function startMockApi(port) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', async () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      if (req.url.includes('/analysis/url')) {
        let parsed = {};
        try { parsed = JSON.parse(body); } catch (e) {}
        const isMalicious = parsed.url && parsed.url.includes('malicious');
        if (isMalicious) {
          res.end(JSON.stringify({
            risk_score: 95,
            severity: 'critical',
            recommended_action: 'block',
            explanation: 'Credential harvesting phishing kit detected.',
            indicators: [
              { type: 'url', value: parsed.url, severity: 'critical', description: 'Credential harvester target' },
              { type: 'pattern', value: 'fake_login', severity: 'high', description: 'Deceptive login form' },
            ],
          }));
        } else {
          res.end(JSON.stringify({
            risk_score: 5,
            severity: 'low',
            recommended_action: 'pass',
            explanation: 'Clean destination.',
            indicators: [],
          }));
        }
      } else if (req.url.includes('/analysis/media')) {
        // 600ms delay to allow scroll and DOM append while mid-flight
        await sleep(600);
        res.end(JSON.stringify({
          module: 'deepfake',
          media_type: 'image',
          manipulation_probability: 0.95,
          authenticity_score: 0.05,
          risk_score: 92,
          severity: 'critical',
          method: 'cnn-ensemble',
          explanation: 'High probability of synthetic manipulation.',
          indicators: [],
        }));
      } else {
        res.end(JSON.stringify({ ok: true }));
      }
    });
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}

function startTestPage(port) {
  const imgData = solidPng(300);
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/img.png')) {
      res.writeHead(200, { 'content-type': 'image/png' });
      res.end(imgData);
      return;
    }
    if (req.url === '/malicious.html') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<!doctype html><html><body>
        <h1>Malicious Target Page Loaded Successfully</h1>
        <p>This is the real target page shown only after allowlisting.</p>
      </body></html>`);
      return;
    }
    if (req.url === '/scanner.html') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<!doctype html><html><body style="min-height: 2500px; padding: 20px;">
        <h1>Scanner V2 Test Page</h1>
        <p>Content images to detect:</p>
        <img id="img1" src="/img.png?1" width="300" height="300" alt="img1">
        <img id="img2" src="/img.png?2" width="350" height="350" alt="img2">
      </body></html>`);
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html><html><body><h1>Index</h1></body></html>`);
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}

async function resolveExtensionId(context) {
  try {
    const sw = await context.waitForEvent('serviceworker', { timeout: 15000 });
    const id = new URL(sw.url()).host;
    if (/^[a-p]{32}$/.test(id)) return id;
  } catch (e) {}
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

    // Bootstrap authentication in storage.local
    const bootstrap = await context.newPage();
    await bootstrap.goto(`chrome-extension://${extId}/popup/popup.html`);
    await bootstrap.evaluate(() => chrome.storage.local.set({
      extAuth: { access_token: 'e2e-token', refresh_token: 'e2e-rt', expires_at: Math.floor(Date.now() / 1000) + 3600, email: 'demo@cyberguard.local' },
      autoBlockNavigation: true,
    }));
    await bootstrap.close().catch(() => {});

    // =========================================================================
    // Scenario 1: Navigate to mock-malicious URL -> interstitial -> Continue anyway
    // =========================================================================
    console.log('\n--- Scenario 1: Navigation Guard & Auto-Block Interstitial ---');
    const page1 = await context.newPage();
    await page1.goto(`http://localhost:${WEB_PORT}/malicious.html`);

    // Verify redirected to blocked.html
    await page1.waitForURL((u) => u.pathname.includes('blocked.html'), { timeout: 15000 });
    await page1.waitForSelector('#cg-target-url', { timeout: 10000 });
    await sleep(400);

    const interstitialText = await page1.evaluate(() => document.body.innerText.trim());
    console.log(`\n===== [REPORT 2: INTERSTITIAL SCREENSHOT-AS-TEXT] =====\n${interstitialText}\n======================================================\n`);

    check('interstitial header displayed', /Navigation blocked/i.test(interstitialText));
    check('target URL displayed in mono', /malicious\.html/i.test(interstitialText));
    check('reason displayed', /credential harvester|phishing/i.test(interstitialText));
    check('severity badge and score displayed', /BLOCK|CRITICAL/i.test(interstitialText) && /95/i.test(interstitialText));

    // Click [Continue anyway]
    await page1.click('#btn-continue');
    await page1.waitForURL(`http://localhost:${WEB_PORT}/malicious.html`, { timeout: 15000 });
    const originalText = await page1.evaluate(() => document.body.innerText.trim());
    check('original page loads after continue anyway', /Malicious Target Page Loaded Successfully/i.test(originalText));
    await page1.close().catch(() => {});

    // =========================================================================
    // Scenario 2: 2 images -> expand pill -> analyze -> scroll mid-flight -> overlay + +n new badge
    // =========================================================================
    console.log('\n--- Scenario 2: State Machine, Mid-Flight Append & Pill V2 ---');
    const page2 = await context.newPage();
    await page2.goto(`http://localhost:${WEB_PORT}/scanner.html`);

    // Wait for collapsed pill
    await page2.waitForSelector('#cgext-pill:not([hidden])', { timeout: 15000 });
    await sleep(600);
    const pillTextCollapsed = await page2.evaluate(() => document.getElementById('cgext-pill').innerText);
    check('collapsed pill shows 2 images', /2 images/i.test(pillTextCollapsed), pillTextCollapsed.replace(/\n/g, ' '));

    // Expand pill by clicking pill body
    await page2.click('#cgext-pill .cgext-pill__body');
    await page2.waitForSelector('#cgext-pill.cgext-pill--expanded', { timeout: 5000 });
    await sleep(300);

    const pillExpandedText = await page2.evaluate(() => document.getElementById('cgext-pill').innerText.trim());
    console.log(`\n===== [REPORT 3: PILL V2 EXPANDED SCREENSHOT-AS-TEXT] =====\n${pillExpandedText}\n==========================================================\n`);

    check('expanded pill shows Detected Items header', /Detected Items/i.test(pillExpandedText));
    check('expanded pill shows Analyze selected button', /Analyze selected/i.test(pillExpandedText));

    // Click [Analyze selected (2)]
    await page2.click('#cgext-pill .cgext-pill__btn-analyze-selected');

    // While analyzing (in-flight): scroll and append DOM
    await sleep(100);
    await page2.evaluate(() => {
      window.scrollTo(0, 500);
      const img3 = document.createElement('img');
      img3.id = 'img3';
      img3.src = '/img.png?3';
      img3.width = 400;
      img3.height = 400;
      document.body.appendChild(img3);
    });

    // Wait for overlay to appear
    await page2.waitForSelector('#cgext-overlay-root', { timeout: 15000 });
    await sleep(400);

    const overlayText = await page2.evaluate(() => document.getElementById('cgext-overlay-root').innerText);
    const pillAfterAnalysis = await page2.evaluate(() => document.getElementById('cgext-pill').innerText);
    console.log(`\n===== [REPORT 4: STATE MACHINE PROOF (SCROLL TEST)] =====\nOverlay:\n${overlayText}\nPill:\n${pillAfterAnalysis.replace(/\n/g, ' | ')}\n========================================================\n`);

    check('overlay shows the 2 analyzed image results', /2 CRITICAL/i.test(overlayText) || /FAKE/i.test(overlayText));
    check('pill displays "+1 new" badge for mid-flight detection', /\+1 new/i.test(pillAfterAnalysis));

    await page2.close().catch(() => {});

    // =========================================================================
    // Scenario 3: Lock pill -> append image -> count unchanged; unlock -> count updates
    // =========================================================================
    console.log('\n--- Scenario 3: Lock Control ---');
    const page3 = await context.newPage();
    await page3.goto(`http://localhost:${WEB_PORT}/scanner.html`);

    await page3.waitForSelector('#cgext-pill:not([hidden])', { timeout: 15000 });
    await sleep(600);

    // Lock pill
    await page3.click('#cgext-pill .cgext-pill__lock');
    await page3.waitForSelector('#cgext-pill.cgext-pill--locked', { timeout: 5000 });

    const lockedTextBefore = await page3.evaluate(() => document.getElementById('cgext-pill').innerText);
    check('pill enters locked state', /Locked|🔓/i.test(lockedTextBefore));

    // Append image while locked
    await page3.evaluate(() => {
      const img = document.createElement('img');
      img.id = 'locked-img';
      img.src = '/img.png?locked';
      img.width = 300;
      img.height = 300;
      document.body.appendChild(img);
    });
    await sleep(800); // debounce time

    const lockedTextAfter = await page3.evaluate(() => document.getElementById('cgext-pill').innerText);
    check('count unchanged while locked (still 2 images)', /2 images/i.test(lockedTextAfter));

    // Unlock pill
    await page3.click('#cgext-pill .cgext-pill__lock');
    await sleep(800); // debounce time after resume

    const unlockedText = await page3.evaluate(() => document.getElementById('cgext-pill').innerText);
    console.log(`\n===== [REPORT 5: LOCK PROOF] =====\nLocked: ${lockedTextAfter.replace(/\n/g, ' | ')}\nUnlocked: ${unlockedText.replace(/\n/g, ' | ')}\n==================================\n`);

    check('count updates after unlock (now 3 images)', /3 images/i.test(unlockedText));
    await page3.close().catch(() => {});

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

main().catch((err) => {
  console.error('E2E error:', err);
  process.exit(1);
});
