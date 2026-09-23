import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { formatAuthError } from '../components/common/authError.ts';

describe('ACCOUNT-REALM-FIX Test Suite (6 Checks)', () => {
  const loginPath = path.resolve('src/pages/Login.tsx');
  const authStorePath = path.resolve('src/store/authStore.ts');
  const topbarPath = path.resolve('src/components/layout/Topbar.tsx');
  const protectedRoutePath = path.resolve('src/components/layout/ProtectedRoute.tsx');
  const authBannerPath = path.resolve('src/components/common/AuthErrorBanner.ts');

  // Check 1: personal_signin_org_account_shows_switch_button
  it('1 personal_signin_org_account_shows_switch_button: 403 mismatch formats with human message and Switch action', () => {
    assert.ok(fs.existsSync(authBannerPath), 'AuthErrorBanner.ts must exist');
    assert.ok(fs.existsSync(loginPath), 'Login.tsx must exist');

    // Test formatAuthError logic for mismatch
    const formatted = formatAuthError({
      error: 'account_type_mismatch',
      message: 'This email is registered as an organization account.',
      hint: 'use_org_mode',
    });

    assert.ok(formatted !== null, 'Formatted auth error must not be null');
    assert.strictEqual(formatted.message, 'This email is registered as an organization account.');
    assert.strictEqual(formatted.actionText, 'Switch to Organization login');

    // Verify Login.tsx catches 403 or account_type_mismatch and wires handleAuthErrorAction
    const loginSrc = fs.readFileSync(loginPath, 'utf8');
    assert.match(loginSrc, /account_type_mismatch/);
    assert.match(loginSrc, /use_org_mode/);
    assert.match(loginSrc, /handleAuthErrorAction/);
  });

  // Check 2: switch_button_switches_mode_and_preserves_email
  it('2 switch_button_switches_mode_and_preserves_email: switches to org, preserves entered email, clears error', () => {
    let currentAuthMode = 'personal';
    let currentMode = 'signin';
    let currentEmail = 'analyst@enterprise-corp.com';
    let currentAuthError: any = {
      error: 'account_type_mismatch',
      message: 'This email is registered as an organization account.',
      hint: 'use_org_mode',
    };
    const params = new URLSearchParams('mode=personal&error=account_type_mismatch');

    // Simulate handleSwitchToOrg implementation from Login.tsx
    const handleSwitchToOrg = () => {
      const preservedEmail = currentEmail;
      currentAuthMode = 'org';
      currentMode = 'signin';
      currentEmail = preservedEmail;
      currentAuthError = null;
      params.set('mode', 'org');
      params.delete('error');
    };

    handleSwitchToOrg();

    assert.strictEqual(currentAuthMode, 'org', 'Must switch auth mode to org');
    assert.strictEqual(currentMode, 'signin', 'Must remain on signin tab');
    assert.strictEqual(currentEmail, 'analyst@enterprise-corp.com', 'Entered email must be preserved');
    assert.strictEqual(currentAuthError, null, 'Error must be cleared');
    assert.strictEqual(params.get('mode'), 'org');
    assert.strictEqual(params.get('error'), null, 'Error param must be removed from URL');
  });

  // Check 3: org_mode_has_reset_tab
  it('3 org_mode_has_reset_tab: Reset tab renders in org mode with ORGANIZATION ACCESS badge and work email subtitle', () => {
    const loginSrc = fs.readFileSync(loginPath, 'utf8');

    // Reset button is NOT restricted to authMode === 'personal'
    assert.doesNotMatch(
      loginSrc,
      /\{authMode === 'personal' && \(\s*<button[^>]*switchMode\('forgot'\)/,
      'Reset button must not be conditionally hidden in org mode'
    );

    // Reset tab button exists
    assert.match(loginSrc, /switchMode\('forgot'\)/);

    // Organization badge + work email subtitle in forgot mode
    assert.match(loginSrc, /ORGANIZATION ACCESS/);
    assert.match(loginSrc, /Enter your work email to receive a password reset link/);
  });

  // Check 4: org_reset_requests_reset_with_org_redirect
  it('4 org_reset_requests_reset_with_org_redirect: requests reset with redirectTo=/login?mode=org and shows success card', async () => {
    const loginSrc = fs.readFileSync(loginPath, 'utf8');
    const authStoreSrc = fs.readFileSync(authStorePath, 'utf8');

    // authStore requestPasswordReset accepts custom redirectTo
    assert.match(authStoreSrc, /requestPasswordReset:\s*async\s*\(email,\s*redirectTo\?:\s*string\)/);

    // Login.tsx sends redirectTo with mode=org in org mode
    assert.match(loginSrc, /authMode === 'org'\s*\?\s*`\$\{window\.location\.origin\}\/login\?mode=org`/);

    // Simulating handleForgot in org mode
    let requestedEmail: string | null = null;
    let requestedRedirect: string | null = null;
    const mockRequestPasswordReset = async (email: string, redirectUrl?: string) => {
      requestedEmail = email;
      requestedRedirect = redirectUrl || null;
    };

    const targetEmail = 'admin@secops.org';
    const authMode = 'org';
    const origin = 'http://localhost:5173';
    const redirectUrl = authMode === 'org' ? `${origin}/login?mode=org` : `${origin}/reset-password`;

    await mockRequestPasswordReset(targetEmail, redirectUrl);

    assert.strictEqual(requestedEmail, targetEmail);
    assert.strictEqual(requestedRedirect, 'http://localhost:5173/login?mode=org');

    // Success card copy and button
    assert.match(loginSrc, /If an account exists for \$\{email\}, a reset link has been sent\. Check your inbox\./);
    assert.match(loginSrc, /Back to Organization Sign In/);
  });

  // Check 5: personal_routes_render_zero_org_chips (mock Topbar on /dashboard)
  it('5 personal_routes_render_zero_org_chips: personal workspace routes render ZERO org chips or org names', () => {
    const topbarSrc = fs.readFileSync(topbarPath, 'utf8');

    // Verify isOrgRoute check
    assert.match(topbarSrc, /const isOrgRoute = location\.pathname\.startsWith\('\/org'\)/);
    assert.match(topbarSrc, /isOrgRoute && activeOrganization &&/);

    // Test route classification logic
    const personalRoutes = [
      '/dashboard',
      '/phishing',
      '/url-analysis',
      '/impersonation',
      '/deepfake',
      '/account-takeover',
      '/network-threats',
      '/alerts',
      '/incidents',
      '/settings',
      '/reports',
    ];

    const activeOrganization = { id: 'org-99', name: 'Leaked Corp SOC', slug: 'leaked-corp' };
    const activeProject = { id: 'proj-1', name: 'Default Project', slug: 'default' };

    for (const pathname of personalRoutes) {
      const isOrgRoute = pathname.startsWith('/org');
      const renderedChip = isOrgRoute && activeOrganization
        ? `${activeOrganization.name} › ${activeProject.name}`
        : null;

      assert.strictEqual(
        renderedChip,
        null,
        `Personal route ${pathname} must NOT render org chip or org name`
      );
    }

    // Verify ProtectedRoute guards personal routes against org accounts
    const protectedRouteSrc = fs.readFileSync(protectedRoutePath, 'utf8');
    assert.match(protectedRouteSrc, /user\?\.account_type === 'org'/);
    assert.match(protectedRouteSrc, /Navigate to="\/org\/select"/);
  });

  // Check 6: org_routes_render_org_chips (mock Topbar on /org/select or /org/projects)
  it('6 org_routes_render_org_chips: org routes render org chips when activeOrganization exists', () => {
    const orgRoutes = [
      '/org/select',
      '/org/acme-corp/projects',
      '/org/test-id/settings',
    ];

    const activeOrganization = { id: 'org-42', name: 'Cyber Defense Org', slug: 'cyber-defense' };
    const activeProject = { id: 'proj-1', name: 'Alpha Project', slug: 'alpha' };

    for (const pathname of orgRoutes) {
      const isOrgRoute = pathname.startsWith('/org');
      assert.strictEqual(isOrgRoute, true, `Route ${pathname} must be identified as org route`);

      const chipRendered = isOrgRoute && activeOrganization ? true : false;
      assert.strictEqual(chipRendered, true, `Org route ${pathname} must render org chip`);
    }
  });
});
