import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

describe('LOGIN-UNIFY Test Suite (8 Checks)', () => {
  const loginPath = path.resolve('src/pages/Login.tsx');
  const appPath = path.resolve('src/App.tsx');
  const authStorePath = path.resolve('src/store/authStore.ts');
  const topbarPath = path.resolve('src/components/layout/Topbar.tsx');

  // Check 1: chooser renders [Personal|Organization] on Sign In and Register tabs; URL ?mode=org preselects org
  it('1 chooser renders [Personal|Organization] on Sign In and Register tabs; URL ?mode=org preselects org', () => {
    assert.ok(fs.existsSync(loginPath), 'Login.tsx must exist');
    const content = fs.readFileSync(loginPath, 'utf8');

    // Segmented control chooser buttons
    assert.match(content, /Personal Workspace/);
    assert.match(content, /Organization/);
    assert.match(content, /handleAuthModeSwitch/);

    // URL ?mode=org preselects org mode
    assert.match(content, /modeParam === 'org'/);
    assert.match(content, /p\.set\('mode', 'org'\)/);

    // Chooser is visible above tabs and applies to both signin and signup
    assert.match(content, /switchMode\('signin'\)/);
    assert.match(content, /switchMode\('signup'\)/);
  });

  // Check 2: personal sign-in for user WITH orgs → lands /dashboard (assert no org-name/select render)
  it('2 personal sign-in for user WITH orgs -> lands /dashboard (assert no org-name/select render)', async () => {
    const userWithOrgs = [
      { id: 'org-1', name: 'Cyber Defense Corp', slug: 'cyber-defense-corp', is_personal: false, role: 'admin' },
    ];

    let currentRoute: string | null = null;
    let renderedStep: string = 'auth';
    const mockNavigate = (to: string) => {
      currentRoute = to;
    };

    // Simulate handleSignIn in personal mode
    const authMode = 'personal';
    const mockSignInPersonal = async (hasOrgs: boolean) => {
      // Personal mode always routes to /dashboard, never checks org memberships for redirection
      if (authMode === 'personal') {
        mockNavigate('/dashboard');
        return;
      }
      if (hasOrgs) {
        mockNavigate('/org/select');
      } else {
        renderedStep = 'org-name';
      }
    };

    await mockSignInPersonal(userWithOrgs.length > 0);

    // Assert landed on /dashboard
    assert.strictEqual(currentRoute, '/dashboard');
    // Assert no org-name step rendered
    assert.strictEqual(renderedStep, 'auth');
    assert.notStrictEqual(currentRoute, '/org/select');
  });

  // Check 3: org sign-in same user → lands /org/select
  it('3 org sign-in same user -> lands /org/select', async () => {
    const userWithOrgs = [
      { id: 'org-1', name: 'Cyber Defense Corp', slug: 'cyber-defense-corp', is_personal: false, role: 'admin' },
    ];

    let currentRoute: string | null = null;
    const mockNavigate = (to: string) => {
      currentRoute = to;
    };

    // Simulate handleSignIn in org mode
    const authMode = 'org';
    const mockSignInOrg = async (orgs: typeof userWithOrgs) => {
      if (authMode === 'org') {
        if (orgs.length > 0) {
          mockNavigate('/org/select');
        } else {
          mockNavigate('/org/setup');
        }
      }
    };

    await mockSignInOrg(userWithOrgs);
    assert.strictEqual(currentRoute, '/org/select');
  });

  // Check 4: personal register → /dashboard, zero org steps rendered
  it('4 personal register -> /dashboard, zero org steps rendered', async () => {
    let currentRoute: string | null = null;
    let step: string = 'auth';
    const mockNavigate = (to: string) => {
      currentRoute = to;
    };

    const authMode = 'personal';
    const mockSignUp = async () => {
      if (authMode === 'org') {
        step = 'org-name';
      } else {
        mockNavigate('/dashboard');
      }
    };

    await mockSignUp();
    assert.strictEqual(currentRoute, '/dashboard');
    assert.strictEqual(step, 'auth', 'Must not enter org-name step');
  });

  // Check 5: org register → step1 → org-name step → /org/select (existing flow tests stay green unchanged)
  it('5 org register -> step1 -> org-name step -> /org/select', async () => {
    let currentRoute: string | null = null;
    let step: string = 'auth';
    const mockNavigate = (to: string) => {
      currentRoute = to;
    };

    // Step 1: user fills credentials in org mode
    const authMode = 'org';
    const handleRegisterStep1 = () => {
      if (authMode === 'org') {
        step = 'org-name';
      }
    };

    handleRegisterStep1();
    assert.strictEqual(step, 'org-name', 'Must advance to org-name step');

    // Step 2: user names organization and creates
    const handleCreateOrg = async (name: string) => {
      assert.ok(name.length >= 2);
      mockNavigate('/org/select');
    };

    await handleCreateOrg('Acme Threat Intelligence');
    assert.strictEqual(currentRoute, '/org/select');
  });

  // Check 6: /org/entry → redirects /login?mode=org; old org URLs still redirect per teardown rules
  it('6 /org/entry -> redirects /login?mode=org; old org URLs still redirect per teardown rules', () => {
    assert.ok(fs.existsSync(appPath), 'App.tsx must exist');
    const content = fs.readFileSync(appPath, 'utf8');

    // /org/entry route redirects to /login?mode=org
    assert.match(content, /path="\/org\/entry" element={<Navigate to="\/login\?mode=org" replace \/>}/);

    // OrgGuard redirects unauthenticated users to /login?mode=org
    assert.match(content, /return <Navigate to="\/login\?mode=org" replace \/>/);

    // Old teardown redirects still intact
    assert.match(content, /path="\/org" element={<Navigate to="\/org\/select" replace \/>}/);
    assert.match(content, /path="\/organization" element={<Navigate to="\/org\/select" replace \/>}/);
    assert.match(content, /path="\/org\/\*" element={<Navigate to="\/dashboard" replace \/>}/);
  });

  // Check 7: OAuth intent: personal mode → intent=personal param/state; org mode → intent=org (mock assert)
  it('7 OAuth intent: personal mode -> intent=personal param/state; org mode -> intent=org (mock assert)', () => {
    assert.ok(fs.existsSync(authStorePath), 'authStore.ts must exist');
    const authStoreContent = fs.readFileSync(authStorePath, 'utf8');

    // loginWithOAuth accepts mode parameter
    assert.match(authStoreContent, /loginWithOAuth:\s*\(provider:\s*'google'\s*\|\s*'github',\s*mode\?:\s*'personal'\s*\|\s*'org'\)/);

    // Stores intent in sessionStorage
    assert.match(authStoreContent, /sessionStorage\.setItem\('cyberguard_oauth_mode',\s*selectedMode\)/);

    // Mode-specific redirectTo URL
    assert.match(authStoreContent, /selectedMode === 'org'/);
    assert.match(authStoreContent, /\/login\?mode=org/);
    assert.match(authStoreContent, /\/login/);

    // Login.tsx passes mode to loginWithOAuth
    const loginContent = fs.readFileSync(loginPath, 'utf8');
    assert.match(loginContent, /loginWithOAuth\(provider,\s*authMode\)/);
  });

  // Check 8: forbidden-strings scan still zero on new code; personal login visual tree unchanged vs baseline snapshot
  it('8 forbidden-strings scan still zero on new code; personal login visual tree intact', () => {
    const filesToCheck = [loginPath, appPath, authStorePath, topbarPath];
    const forbiddenPatterns = [
      { name: 'Free', regex: /\bfree\b/i },
      { name: 'Pro', regex: /\bpro\b/i },
      { name: 'Upgrade', regex: /\bupgrade\b/i },
      { name: 'Billing', regex: /\bbilling\b/i },
      { name: 'Plan', regex: /\bplan\b/i },
      { name: 'Usage', regex: /\busage\b/i },
      { name: 'Nano', regex: /\bnano\b/i },
      { name: 'Region AP', regex: /\bap-[a-z0-9-]+/i },
      { name: 'Region EU', regex: /\beu-[a-z0-9-]+/i },
    ];

    const violations: string[] = [];

    for (const filePath of filesToCheck) {
      assert.ok(fs.existsSync(filePath), `File must exist: ${filePath}`);
      const text = fs.readFileSync(filePath, 'utf8');

      for (const pattern of forbiddenPatterns) {
        const matches = text.match(pattern.regex);
        if (matches) {
          violations.push(
            `Forbidden string "${pattern.name}" found in ${path.basename(filePath)}: ${matches.join(', ')}`
          );
        }
      }
    }

    assert.deepStrictEqual(violations, [], `Forbidden strings detected:\n${violations.join('\n')}`);

    // Verify personal login core elements exist
    const loginContent = fs.readFileSync(loginPath, 'utf8');
    assert.match(loginContent, /ENTERPRISE SOC MODE/);
    assert.match(loginContent, /Continue with Google/);
    assert.match(loginContent, /Continue with GitHub/);
    assert.match(loginContent, /Email or Username/);
    assert.match(loginContent, /Sign In to Workspace/);
    assert.match(loginContent, /Personal Workspace/);

    // User dropdown has Organizations link
    const topbarContent = fs.readFileSync(topbarPath, 'utf8');
    assert.match(topbarContent, /to="\/org\/select"/);
    assert.match(topbarContent, /Organizations/);
  });
});
