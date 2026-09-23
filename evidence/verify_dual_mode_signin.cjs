const { chromium } = require('playwright');
const path = require('path');
const assert = require('assert');

const BASE_URL = 'http://localhost:5173';
const EVIDENCE_DIR = path.resolve(__dirname);

async function runDualModeVerification() {
  console.log('=== Starting Dual-Mode Sign-In Verification (Same Account) ===');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();

  const ts = Date.now().toString().slice(-6);
  const password = 'Password123!@#';
  const testEmail = `dual_user_${ts}@cyberguard.local`;
  const testUsername = `dual_${ts}`;
  const testOrgName = `DualSec Org ${ts}`;

  try {
    // Step 0: Register an organization account
    console.log(`\n[Step 0] Registering account: ${testEmail}`);
    await page.goto(`${BASE_URL}/login?mode=org`);
    await page.waitForSelector('text=ORGANIZATION ACCESS');
    await page.getByRole('button', { name: 'Register' }).click();
    await page.waitForTimeout(300);

    await page.getByPlaceholder('alex.mercer').fill(testUsername);
    await page.waitForTimeout(500);
    await page.getByPlaceholder('Alex Mercer').fill('Dual Mode User');
    await page.getByPlaceholder('analyst@yourcompany.com').fill(testEmail);
    const orgPassInputs = await page.locator('input[type="password"]').all();
    await orgPassInputs[0].fill(password);
    await orgPassInputs[1].fill(password);

    await page.getByRole('button', { name: /Next: Organization Setup/ }).click();
    await page.waitForSelector('text=Step 2: Organization');

    await page.getByPlaceholder('Acme Cyber Defense').fill(testOrgName);
    await page.getByRole('button', { name: 'Create organization' }).click();

    await page.waitForFunction(() => window.location.pathname.includes('/org/select'), { timeout: 15000 });
    console.log(`✓ Account created and verified at /org/select`);

    // Clear session so we can test fresh sign-in
    await page.context().clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });

    // ──────────────────────────────────────────────────────────────────
    // Step 1: Sign in using PERSONAL MODE with the same account
    // ──────────────────────────────────────────────────────────────────
    console.log('\n[Step 1] Signing in with Personal mode chooser for same account...');
    await page.goto(`${BASE_URL}/login`);
    await page.waitForSelector('button:has-text("Personal")');

    // Ensure Personal tab is active
    const personalTab = page.getByRole('button', { name: /Personal Workspace/i });
    await personalTab.click();

    await page.getByPlaceholder('you@company.com or alex.mercer').fill(testEmail);
    const passInput = page.locator('input[type="password"]');
    await passInput.fill(password);

    // Click Sign In
    const signInBtn = page.getByRole('button', { name: /Sign In to Workspace/i });
    await signInBtn.click();

    // Assert lands on /dashboard
    await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 15000 });
    console.log(`✓ Successfully signed in via Personal mode and landed on: ${page.url()}`);
    assert.strictEqual(new URL(page.url()).pathname, '/dashboard');

    // Verify personal workspace UI & de-contamination
    await page.waitForTimeout(1000);
    const orgChip = await page.$('[data-testid="topbar-org-chip"]');
    assert.strictEqual(orgChip, null, 'Personal dashboard must NOT render org chip');

    const bodyText = await page.textContent('body');
    assert.ok(bodyText.includes('Security Operations Center'), 'Personal workspace header present');

    const personalScreenshot = path.join(EVIDENCE_DIR, 'dual_mode_personal_dashboard.png');
    await page.screenshot({ path: personalScreenshot, fullPage: true });
    console.log(`✓ Captured personal workspace screenshot: ${personalScreenshot}`);

    // Clear session for Step 2
    await page.context().clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });

    // ──────────────────────────────────────────────────────────────────
    // Step 2: Sign in using ORGANIZATION MODE with the same account
    // ──────────────────────────────────────────────────────────────────
    console.log('\n[Step 2] Signing in with Organization mode chooser for same account...');
    await page.goto(`${BASE_URL}/login?mode=org`);
    await page.waitForSelector('text=ORGANIZATION ACCESS');

    const orgEmailInput = page.getByPlaceholder('you@company.com or alex.mercer');
    await orgEmailInput.fill(testEmail);
    const orgPassInput = page.locator('input[type="password"]');
    await orgPassInput.fill(password);

    const orgSignInBtn = page.getByRole('button', { name: /Sign In to Organization/i });
    await orgSignInBtn.click();

    // Assert lands on /org/select
    await page.waitForFunction(() => window.location.pathname.startsWith('/org/select'), { timeout: 15000 });
    console.log(`✓ Successfully signed in via Organization mode and landed on: ${page.url()}`);
    assert.strictEqual(new URL(page.url()).pathname, '/org/select');

    // Verify org selector UI renders the organization card
    await page.waitForSelector(`text=${testOrgName}`);
    console.log(`✓ Org card "${testOrgName}" rendered in organization workspace`);

    const orgScreenshot = path.join(EVIDENCE_DIR, 'dual_mode_org_select.png');
    await page.screenshot({ path: orgScreenshot, fullPage: true });
    console.log(`✓ Captured org workspace screenshot: ${orgScreenshot}`);

    // ──────────────────────────────────────────────────────────────────
    // Step 3: Register a PERSONAL user (0 orgs) & sign in to Org mode
    // ──────────────────────────────────────────────────────────────────
    const persEmail = `pers_dual_${ts}@cyberguard.local`;
    const persUsername = `pdual_${ts}`;
    console.log(`\n[Step 3] Testing user created via Personal registration: ${persEmail}`);

    await page.context().clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });

    await page.goto(`${BASE_URL}/login`);
    await page.getByRole('button', { name: 'Register' }).click();
    await page.waitForTimeout(300);

    await page.getByPlaceholder('alex.mercer').fill(persUsername);
    await page.waitForTimeout(500);
    await page.getByPlaceholder('Alex Mercer').fill('Personal Dual User');
    await page.getByPlaceholder('analyst@yourcompany.com').fill(persEmail);
    const pPassInputs = await page.locator('input[type="password"]').all();
    await pPassInputs[0].fill(password);
    await pPassInputs[1].fill(password);

    await page.getByRole('button', { name: 'Create Account' }).click();
    await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 15000 });
    console.log(`✓ Personal user registered and landed on: ${page.url()}`);

    // Clear session and test signing into ORG mode with this personal user
    await page.context().clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });

    console.log('\n[Step 4] Signing in to Organization mode with Personal-registered user...');
    await page.goto(`${BASE_URL}/login?mode=org`);
    await page.waitForSelector('text=ORGANIZATION ACCESS');

    await page.getByPlaceholder('you@company.com or alex.mercer').fill(persEmail);
    await page.locator('input[type="password"]').fill(password);
    await page.getByRole('button', { name: /Sign In to Organization/i }).click();

    // Since this user has 0 orgs, they land on the org-name creation step!
    await page.waitForSelector('text=Step 2: Organization', { timeout: 15000 });
    console.log(`✓ User with 0 orgs presented with Org creation step`);

    // Create an organization for them
    const newPersOrgName = `Pers User Org ${ts}`;
    await page.getByPlaceholder('Acme Cyber Defense').fill(newPersOrgName);
    await page.getByRole('button', { name: 'Create organization' }).click();

    await page.waitForFunction(() => window.location.pathname.startsWith('/org/select'), { timeout: 15000 });
    console.log(`✓ Personal user created org and landed on /org/select`);

    // Now sign out and sign back in to Personal mode: must land on /dashboard
    await page.context().clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });

    console.log('\n[Step 5] Signing back into Personal mode with same user now having orgs...');
    await page.goto(`${BASE_URL}/login`);
    const personalTab2 = page.getByRole('button', { name: /Personal Workspace/i });
    await personalTab2.click();

    await page.getByPlaceholder('you@company.com or alex.mercer').fill(persEmail);
    await page.locator('input[type="password"]').fill(password);
    await page.getByRole('button', { name: /Sign In to Workspace/i }).click();

    await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 15000 });
    console.log(`✓ Same user signed into Personal mode lands on /dashboard (even though they now own orgs!)`);
    const chip2 = await page.$('[data-testid="topbar-org-chip"]');
    assert.strictEqual(chip2, null, 'Personal dashboard must NOT render org chip');

    console.log('\n=== ALL DUAL-MODE VERIFICATIONS (BOTH DIRECTIONS) PASSED SUCCESSFULLY ===');
  } catch (err) {
    console.error('Verification failed:', err);
    await page.screenshot({ path: path.join(EVIDENCE_DIR, 'dual_mode_failure.png'), fullPage: true });
    process.exitCode = 1;
  } finally {
    await browser.close();
  }
}

runDualModeVerification();
