import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

const EXT_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(EXT_ROOT, 'dist', 'chromium');
const PROFILE = join(EXT_ROOT, 'e2e', 'artifacts', 'profile-confidence-test');
const WEB_PORT = 51889;
const API_PORT = 8011;

let chromium;
try {
  ({ chromium } = createRequire(import.meta.url)('playwright'));
} catch {
  ({ chromium } = createRequire(import.meta.url)('/usr/lib/node_modules/playwright'));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startMockApi(port) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      if (req.url.includes('/analysis/email')) {
        res.end(JSON.stringify({
          id: 'alert_email_001',
          risk_score: 1,
          severity: 'safe',
          confidence: 0.98,
          explanation: 'Legitimate announcement from registrar@university.edu with no credential harvesting, financial demands, or malicious indicators.',
          indicators: [
            { type: 'ml_model', value: 'email_phishing_xgb.pkl', severity: 'safe', description: 'Trained model probability: 0.02' }
          ],
          mitre: [],
        }));
      } else {
        res.end(JSON.stringify({ ok: true }));
      }
    });
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}

function startTestPage(port) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html>
<html>
<head><title>Webmail Inbox</title></head>
<body style="padding: 24px; font-family: sans-serif;">
  <h1>University Webmail</h1>
  <div role="main">
    <div class="ii">
      The examination timetable has been published on the student portal. Please check your schedule. No further action is required at this time.
    </div>
  </div>
</body>
</html>`);
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

  try {
    const extId = await resolveExtensionId(context);

    // Bootstrap token in storage
    const bootstrap = await context.newPage();
    await bootstrap.goto(`chrome-extension://${extId}/popup/popup.html`);
    await bootstrap.evaluate(() => chrome.storage.local.set({
      extAuth: { access_token: 'e2e-token', refresh_token: 'e2e-rt', expires_at: Math.floor(Date.now() / 1000) + 3600, email: 'demo@cyberguard.local' },
    }));
    await bootstrap.close().catch(() => {});

    // Open Webmail test page
    const page = await context.newPage();
    await page.goto(`http://localhost:${WEB_PORT}/`);

    // Wait for pill to appear (should detect 1 email)
    await page.waitForSelector('#cgext-pill:not([hidden])', { timeout: 15000 });
    await sleep(600);

    const pillText = await page.evaluate(() => document.getElementById('cgext-pill').innerText);
    console.log(`Detected Pill: ${pillText.replace(/\n/g, ' ')}`);

    // Trigger analysis
    await page.click('#cgext-pill .cgext-pill__analyze');

    // Wait for overlay to appear
    await page.waitForSelector('#cgext-overlay-root', { timeout: 15000 });
    await sleep(400);

    const overlayText = await page.evaluate(() => document.getElementById('cgext-overlay-root').innerText);
    console.log('\n===== FIXED OVERLAY SCREENSHOT-AS-TEXT =====');
    console.log(overlayText);
    console.log('============================================\n');

    if (overlayText.includes('confidence 0%')) {
      throw new Error('FAIL: Overlay still displays "confidence 0%"!');
    }
    if (!overlayText.includes('confidence 98%')) {
      throw new Error(`FAIL: Expected "confidence 98%", got overlay text:\n${overlayText}`);
    }

    console.log('SUCCESS: Overlay displays realistic confidence (confidence 98%), and 0% is resolved.');
    await page.close().catch(() => {});
  } finally {
    await context.close().catch(() => {});
    apiServer.close();
    pageServer.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
