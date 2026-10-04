#!/usr/bin/env node
/*
 * EXT-P2 — Chromium Playwright walkthrough for the three analyzers.
 *
 * Auth state is injected (storage.local) and backend responses are mocked
 * via page.route, so no live backend is needed:
 *   Authenticated → Scan URL (auto-filled from mock tab) → mock scan →
 *   result view → Back → Email scan → Back → Deepfake scan → Back →
 *   Open Web Console (new tab).
 * Every state dumps popup innerText (screenshot-as-text).
 */
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const EXT_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(EXT_ROOT, 'dist', 'chromium');
const PROFILE = join(EXT_ROOT, 'e2e', 'artifacts', 'profile-p2');
const WEB_ORIGIN = 'http://localhost:5173';

let chromium;
try {
  ({ chromium } = createRequire(import.meta.url)('playwright'));
} catch {
  ({ chromium } = createRequire(import.meta.url)('/usr/lib/node_modules/playwright'));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const URL_RESULT = {
  id: 'evt-1', module: 'url', threat_type: 'phishing',
  risk_score: 87, severity: 'high', confidence: 0.92,
  explanation: 'Credential-harvesting kit on a look-alike domain.',
  indicators: [
    { type: 'url', value: 'http://secure-login.example/verify', severity: 'high', description: 'Look-alike login page' },
    { type: 'domain', value: 'secure-login.example', severity: 'high', description: 'Newly registered domain' },
  ],
  mitre: [{ id: 'T1566.002', name: 'Spearphishing Link', tactic: 'initial-access' }],
};
const EMAIL_RESULT = {
  id: 'evt-2', module: 'phishing', risk_score: 74, severity: 'high', confidence: 0.88,
  explanation: 'Urgent lure with mismatched sender domain.',
  indicators: [
    { type: 'url', value: 'http://pay.example/wire', severity: 'high', description: 'Payment lure link' },
    { type: 'keyword', value: 'urgent wire transfer', severity: 'medium', description: 'Urgency language' },
  ],
  mitre: [{ id: 'T1534', name: 'Internal Spearphishing', tactic: 'lateral-movement' }],
};
const MEDIA_RESULT = {
  module: 'deepfake', media_type: 'image',
  authenticity_score: 0.12, manipulation_probability: 0.88,
  risk_score: 91, severity: 'critical', method: 'cnn-ensemble', simulated: false,
  explanation: 'Gan artifacts around mouth region.',
  indicators: [{ type: 'deepfake', value: 'face-region', severity: 'critical', description: 'Synthetic face' }],
};

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

async function openPopup(context, extId) {
  const page = await context.newPage();
  let lastErr;
  for (let i = 0; i < 5; i++) {
    try {
      await page.goto(`chrome-extension://${extId}/popup/popup.html`, { timeout: 5000 });
      await page.waitForTimeout(400);
      return page;
    } catch (err) { lastErr = err; await sleep(500); }
  }
  throw lastErr;
}

function dump(page, label) {
  return page.evaluate(() => document.body.innerText.trim()).then((t) => {
    console.log(`\n===== [${label}] =====\n${t.replace(/\n{2,}/g, '\n')}`);
    return t;
  });
}

async function main() {
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
    // No live Vite server in this e2e: stub the web-origin pages the pointers open.
    await context.route(`${WEB_ORIGIN}/**`, (r) => r.fulfill({
      contentType: 'text/html',
      body: '<html><body data-cg-stub="web">CyberGuard Web (stub)</body></html>',
    }));
    const extId = await resolveExtensionId(context);

    // Mock the API surface (auth/me + the three analyzers) for this popup.
    const popup = await openPopup(context, extId);
    await popup.route(`**/api/v1/auth/me`, (r) => r.fulfill({ json: { email: 'demo@cyberguard.local' } }));
    await popup.route(`**/api/v1/analysis/url`, (r) => r.fulfill({ json: URL_RESULT }));
    await popup.route(`**/api/v1/analysis/email`, (r) => r.fulfill({ json: EMAIL_RESULT }));
    await popup.route(`**/api/v1/analysis/media`, (r) => r.fulfill({ json: MEDIA_RESULT }));
    // Mock chrome.tabs.query so auto-fill has a realistic "current tab".
    await popup.addInitScript(() => {
      const orig = chrome.tabs.query.bind(chrome.tabs);
      chrome.tabs.query = async (opts) => {
        const real = await orig(opts).catch(() => []);
        const fake = { id: 999, url: 'https://bank-login.example/verify?token=deadbeef', active: true, currentWindow: true };
        return opts && opts.active ? [fake, ...real] : real;
      };
    });
    // Inject a live session into storage.local, then boot.
    await popup.evaluate((now) => chrome.storage.local.set({
      extAuth: { access_token: 'e2e-token', refresh_token: 'e2e-rt', expires_at: now + 3600, email: 'demo@cyberguard.local' },
    }), Math.floor(Date.now() / 1000));
    await popup.reload();
    await popup.waitForTimeout(1200);

    // ---- State: main menu ---------------------------------------------
    const menuText = await dump(popup, 'popup: main menu');
    check('main menu shows Authenticated + email + 3 cards', /Authenticated/.test(menuText) &&
      menuText.includes('demo@cyberguard.local') &&
      /Scan URL/.test(menuText) && /Scan Email/.test(menuText) && /Detect Deepfake/.test(menuText));
    check('footer pointers present', menuText.includes('Connect Mailbox for Live Monitoring') && menuText.includes('Open Web Console'));

    // ---- URL view: auto-fill + mock scan ------------------------------
    await popup.locator('#card-url').click();
    await popup.waitForTimeout(600);
    const filled = await popup.inputValue('#url-input');
    check('URL view auto-fills current tab URL', filled === 'https://bank-login.example/verify?token=deadbeef', filled);
    await popup.getByRole('button', { name: 'Scan', exact: true }).click();
    await popup.waitForTimeout(700);
    const urlText = await dump(popup, 'popup: URL result');
    check('URL result shows score 87 + HIGH badge + indicators', urlText.includes('87') && urlText.includes('HIGH') &&
      urlText.includes('secure-login.example'));

    // ---- Back to menu ---------------------------------------------------
    await popup.locator('#view-url [data-back]').click();
    await popup.waitForTimeout(300);
    check('Back returns to main menu', (await popup.evaluate(() => !document.getElementById('state-authenticated').hidden)));

    // ---- Email view ------------------------------------------------------
    await popup.locator('#card-email').click();
    await popup.fill('#email-input', 'From: ceo@corp.example\nSubject: URGENT wire transfer\n\nPlease pay via http://pay.example/wire immediately.');
    await popup.getByRole('button', { name: 'Scan', exact: true }).click();
    await popup.waitForTimeout(700);
    const emailText = await dump(popup, 'popup: Email result');
    check('Email result shows probability + MITRE + links', emailText.includes('74') && emailText.includes('T1534') &&
      emailText.includes('pay.example/wire'));

    // ---- Deepfake view ---------------------------------------------------
    await popup.locator('#view-email [data-back]').click();
    await popup.locator('#card-deepfake').click();
    const tmp = join(mkdtempSync(join(tmpdir(), 'cg-e2e-')), 'suspect.png');
    copyFileSync(join(EXT_ROOT, 'dist', 'chromium', 'icons', 'icon32.png'), tmp);
    await popup.setInputFiles('#deepfake-input', tmp);
    await popup.getByRole('button', { name: 'Scan', exact: true }).click();
    await popup.waitForTimeout(700);
    const fakeText = await dump(popup, 'popup: Deepfake result');
    check('Deepfake result shows FAKE verdict + manipulation probability', fakeText.includes('FAKE') && fakeText.includes('88%'));

    // ---- Open Web Console ------------------------------------------------
    await popup.locator('#view-deepfake [data-back]').click();
    const [consoleTab] = await Promise.all([
      context.waitForEvent('page', { timeout: 10000 }),
      popup.getByText('Open Web Console ↗').click(),
    ]);
    await consoleTab.waitForLoadState('domcontentloaded').catch(() => {});
    await sleep(1500);
    const stubbed = await consoleTab.evaluate(() => document.body && document.body.dataset.cgStub === 'web').catch(() => false);
    check('Open Web Console opens a new tab', consoleTab.url().startsWith(WEB_ORIGIN) || stubbed, consoleTab.url());

    await popup.close().catch(() => {});
  } finally {
    await context.close().catch(() => {});
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
