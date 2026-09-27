#!/usr/bin/env node
/*
 * EXT-P1 — Chromium Playwright auth walkthrough.
 *
 * persistent context + --load-extension dist/chromium →
 *   popup signed-out → Sign In → /ext/auth tab → personal login →
 *   /ext/callback closes the tab → popup Authenticated + email →
 *   reload persists → Sign Out clears.
 *
 * Screenshot-as-text: every state dumps popup/page innerText.
 *
 * Usage:
 *   node e2e/playwright-auth.mjs            (needs backend :8000 + Vite :5173)
 */
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const EXT_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(EXT_ROOT, 'dist', 'chromium');
const PROFILE = join(EXT_ROOT, 'e2e', 'artifacts', 'profile');
const DEMO_EMAIL = process.env.E2E_EMAIL || 'demo@cyberguard.local';
const DEMO_PASSWORD = process.env.E2E_PASSWORD || 'demo1234!';

let chromium;
try {
  ({ chromium } = createRequire(import.meta.url)('playwright'));
} catch {
  ({ chromium } = createRequire(import.meta.url)('/usr/lib/node_modules/playwright'));
}

// The manifest pins a key, so the unpacked ID is deterministic — verify anyway.
const EXT_ID = 'mkhcpikficaipogflekjkoiplegbeaji';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function textOf(page, label) {
  return page
    .evaluate(() => document.body ? document.body.innerText.trim() : '(no body)')
    .then((t) => {
      console.log(`\n===== [${label}] =====\n${t}`);
      return t;
    });
}

async function resolveExtensionId(context) {
  // Wait for the MV3 service worker; its URL carries the runtime ID.
  try {
    const sw = await context.waitForEvent('serviceworker', { timeout: 15000 });
    const id = new URL(sw.url()).host;
    if (/^[a-p]{32}$/.test(id)) return id;
  } catch {
    // fall through to existing workers / pinned id
  }
  const existing = context.serviceWorkers().map((sw) => new URL(sw.url()).host).find((h) => /^[a-p]{32}$/.test(h));
  if (existing) return existing;
  throw new Error('extension service worker not found — extension failed to load');
}

async function openPopup(context, extId) {
  const page = await context.newPage();
  let lastErr;
  for (let i = 0; i < 5; i++) {
    try {
      await page.goto(`chrome-extension://${extId}/popup/popup.html`, { timeout: 5000 });
      await page.waitForTimeout(400);
      return page;
    } catch (err) {
      lastErr = err;
      await sleep(500);
    }
  }
  throw lastErr;
}

async function main() {
  execFileSync('node', ['build.mjs'], { cwd: EXT_ROOT, stdio: 'inherit' });

  const context = await chromium.launchPersistentContext(PROFILE, {
    headless: false,
    args: [
      `--disable-extensions-except=${DIST}`,
      `--load-extension=${DIST}`,
      '--no-first-run',
      '--no-default-browser-check',
    ],
  });
  const results = [];
  const check = (name, ok, detail = '') => {
    results.push({ name, ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'} — ${name}${detail ? ` (${detail})` : ''}`);
  };

  try {
    // ---- State 1: signed-out popup ------------------------------------
    const extId = await resolveExtensionId(context);
    check('extension service worker loaded with pinned ID', extId === EXT_ID, `id=${extId}`);
    let popup = await openPopup(context, extId);
    await textOf(popup, 'popup: signed-out');
    const signInVisible = await popup.getByText('Sign In to CyberGuard').isVisible();
    check('popup renders signed-out shield + Sign In button', signInVisible);

    // ---- State 2: sign-in tab opens /ext/auth -------------------------
    const [authTab] = await Promise.all([
      context.waitForEvent('page', { timeout: 10000 }),
      popup.getByText('Sign In to CyberGuard').click(),
    ]);
    await authTab.waitForLoadState('domcontentloaded');
    const authUrl = authTab.url();
    check('sign-in tab opens /ext/auth?state=…', /\/ext\/auth\?state=.+&v=1$/.test(authUrl), authUrl);
    await authTab.waitForURL(/\/ext\/auth/, { timeout: 10000 }).catch(() => {});
    await sleep(800); // hydration: session check → login form (or callback redirect)
    await textOf(authTab, 'auth tab: after load');
    if (/\/ext\/callback/.test(authTab.url())) {
      check('existing session → direct /ext/callback redirect', true);
      // fall through to the callback wait below
    } else {
      const loginForm = await authTab.locator('input[type="password"]').count();
      check('login form rendered for signed-out visitor', loginForm > 0);

      // ---- State 3: personal login ------------------------------------
      const emailInput = authTab.locator('input[placeholder*="you@company.com"]');
      await emailInput.fill(DEMO_EMAIL);
      await authTab.locator('input[type="password"]').fill(DEMO_PASSWORD);
      await Promise.all([
        authTab.waitForURL(/\/ext\/callback/, { timeout: 20000 }).catch(() => {}),
        authTab.getByRole('button', { name: 'Sign In to Workspace' }).click(),
      ]);
      check('login redirects to /ext/callback', /\/ext\/callback/.test(authTab.url()), authTab.url());
      await textOf(authTab, 'callback page');
    }

    // ---- State 4: callback tab closes itself --------------------------
    let closed = false;
    for (let i = 0; i < 40; i++) {
      if (authTab.isClosed()) { closed = true; break; }
      await sleep(250);
    }
    check('callback tab closes after handoff', closed);

    // ---- State 5: popup Authenticated + email -------------------------
    await popup.close().catch(() => {});
    popup = await openPopup(context, extId);
    await textOf(popup, 'popup: after auth');
    const body = await popup.evaluate(() => document.body.innerText);
    check('popup Authenticated with email', body.includes('Authenticated') && body.includes(DEMO_EMAIL));

    // ---- State 6: reload persistence ----------------------------------
    await popup.reload();
    await popup.waitForTimeout(800);
    const persisted = await popup.evaluate(() => document.body.innerText);
    check('popup still Authenticated after reload', persisted.includes('Authenticated'));
    await textOf(popup, 'popup: after reload');

    // ---- State 7: Sign Out clears -------------------------------------
    await popup.getByText('Sign Out').click();
    await popup.waitForTimeout(400);
    const signedOut = await popup.evaluate(() => document.body.innerText);
    check('sign out returns to signed-out state', signedOut.includes('Sign In to CyberGuard'));
    await textOf(popup, 'popup: after sign out');

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
