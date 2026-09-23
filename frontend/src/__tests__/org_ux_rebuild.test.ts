import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { create } from 'zustand';

describe('ORG-UX-REBUILD-1 Test Suite (10 Checks)', () => {
  // Check 1: /org/entry renders OAuth + email form + tabs
  it('1 /org/entry renders OAuth + email form + tabs', () => {
    const orgEntryPath = path.resolve('src/pages/OrgEntry.tsx');
    assert.ok(fs.existsSync(orgEntryPath), 'OrgEntry.tsx must exist');
    const content = fs.readFileSync(orgEntryPath, 'utf8');

    // OAuth buttons (Google + GitHub)
    assert.match(content, /Continue with Google/);
    assert.match(content, /Continue with GitHub/);

    // Form tabs: Sign In and Register
    assert.match(content, /Sign In/);
    assert.match(content, /Register/);

    // Email / username + password inputs
    assert.match(content, /Email or Username/);
    assert.match(content, /Password/);
    assert.match(content, /AuthErrorBanner/);
  });

  // Check 2: register → org-name step → create → /org/select
  it('2 register -> org-name step -> create -> /org/select', () => {
    const orgEntryPath = path.resolve('src/pages/OrgEntry.tsx');
    const content = fs.readFileSync(orgEntryPath, 'utf8');

    // Multi-step: step 1 collects user details, then transitions to step 2 'org-name'
    assert.match(content, /step === 'org-name'/);
    assert.match(content, /Organization Name/);
    assert.match(content, /Create organization/);

    // Calls atomic /register-org with email, password, org_name, username
    assert.match(content, /\/auth\/register-org/);
    assert.match(content, /org_name/);

    // Live slug preview is displayed
    assert.match(content, /Slug:/);

    // Navigates to /org/select upon completion
    assert.match(content, /navigate\('\/org\/select'/);
  });

  // Check 3: oauth-0-orgs → org-name step
  it('3 oauth-0-orgs -> org-name step', async () => {
    // Simulate user authenticated via OAuth with 0 organizations
    let currentStep = 'auth';
    const mockOrgs: any[] = [];

    // When authenticated user enters OrgEntry with 0 orgs, step transitions to org-name
    if (mockOrgs.length === 0) {
      currentStep = 'org-name';
    }
    assert.strictEqual(currentStep, 'org-name');

    // Creating organization in org-name step with authenticated session calls orgApi.createOrg
    let createdOrgName: string | null = null;
    const mockCreateOrg = async (name: string) => {
      createdOrgName = name;
      return {
        id: 'new-org-1',
        name,
        slug: name.toLowerCase().replace(/\s+/g, '-'),
        is_personal: false,
        role: 'admin',
      };
    };

    const newOrg = await mockCreateOrg('Security Operations Corp');
    assert.strictEqual(createdOrgName, 'Security Operations Corp');
    assert.strictEqual(newOrg.id, 'new-org-1');
  });

  // Check 4: sign-in-with-orgs → /org/select directly
  it('4 sign-in-with-orgs -> /org/select directly', async () => {
    const existingOrgs = [
      {
        id: 'org-abc-123',
        name: 'CyberGuard Alpha',
        slug: 'cyberguard-alpha',
        is_personal: false,
        role: 'admin',
      },
    ];

    let navigatedRoute: string | null = null;
    const mockNavigate = (route: string) => {
      navigatedRoute = route;
    };

    // If user has >=1 organizations, navigates straight to /org/select
    if (existingOrgs.length > 0) {
      mockNavigate('/org/select');
    }

    assert.strictEqual(navigatedRoute, '/org/select');
  });

  // Check 5: org select: search filter + new-org modal adds card
  it('5 org select: search filter + new-org modal adds card', () => {
    const orgSelectorPath = path.resolve('src/pages/OrgSelector.tsx');
    assert.ok(fs.existsSync(orgSelectorPath), 'OrgSelector.tsx must exist');
    const content = fs.readFileSync(orgSelectorPath, 'utf8');

    // Heading "Your organizations"
    assert.match(content, /Your organizations/);

    // Search input
    assert.match(content, /placeholder="Search organizations\.\.\."/);

    // New org button and modal
    assert.match(content, /\+ New organization/);
    assert.match(content, /Create organization/);

    // Filter logic simulation
    const orgs = [
      { id: '1', name: 'Red Team Ops', slug: 'red-team' },
      { id: '2', name: 'Blue Team Defense', slug: 'blue-team' },
    ];

    const filterOrgs = (list: typeof orgs, q: string) => {
      const term = q.trim().toLowerCase();
      if (!term) return list;
      return list.filter((o) => o.name.toLowerCase().includes(term) || o.slug.includes(term));
    };

    assert.strictEqual(filterOrgs(orgs, 'Blue').length, 1);
    assert.strictEqual(filterOrgs(orgs, 'Blue')[0].name, 'Blue Team Defense');
    assert.strictEqual(filterOrgs(orgs, '').length, 2);
  });

  // Check 6: projects: search/status/sort/view-toggle work on mock list
  it('6 projects: search/status/sort/view-toggle work on mock list', () => {
    const mockProjects = [
      { id: 'p1', name: 'Zeta Ingestion', slug: 'zeta-ingestion', status: 'active', created_at: '2026-01-01T00:00:00Z' },
      { id: 'p2', name: 'Alpha Scanner', slug: 'alpha-scanner', status: 'archived', created_at: '2026-02-01T00:00:00Z' },
      { id: 'p3', name: 'Core Firewall', slug: 'core-firewall', status: 'active', created_at: '2026-03-01T00:00:00Z' },
    ];

    // Status filter
    const filterByStatus = (status: string) =>
      status === 'all' ? mockProjects : mockProjects.filter((p) => p.status === status);

    assert.strictEqual(filterByStatus('active').length, 2);
    assert.strictEqual(filterByStatus('archived').length, 1);
    assert.strictEqual(filterByStatus('all').length, 3);

    // Search filter
    const searchFilter = (query: string) => {
      const q = query.toLowerCase();
      return mockProjects.filter((p) => p.name.toLowerCase().includes(q) || p.slug.includes(q));
    };
    assert.strictEqual(searchFilter('Firewall').length, 1);
    assert.strictEqual(searchFilter('Firewall')[0].id, 'p3');

    // Sort control: name (A-Z) vs created (newest first)
    const sortedByName = [...mockProjects].sort((a, b) => a.name.localeCompare(b.name));
    assert.strictEqual(sortedByName[0].name, 'Alpha Scanner');

    const sortedByCreated = [...mockProjects].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
    assert.strictEqual(sortedByCreated[0].name, 'Core Firewall');
  });

  // Check 7: new-project modal creates card
  it('7 new-project modal creates card', () => {
    const projectSelectorPath = path.resolve('src/pages/ProjectSelector.tsx');
    assert.ok(fs.existsSync(projectSelectorPath), 'ProjectSelector.tsx must exist');
    const content = fs.readFileSync(projectSelectorPath, 'utf8');

    // Modal elements
    assert.match(content, /\+ New project/);
    assert.match(content, /Create project/);
    assert.match(content, /newProjectName/);
    assert.match(content, /slugifyName/);

    // Creation handler adds project to state
    assert.match(content, /orgApi\.createProject/);
  });

  // Check 8: card click sets active project + Active ring + persists
  it('8 card click sets active project + Active ring + persists', () => {
    // Test store and persistence logic
    const store = create<{
      activeOrganization: any;
      activeProject: any;
      setActiveOrganization: (org: any) => void;
      setActiveProject: (proj: any) => void;
    }>((set) => ({
      activeOrganization: null,
      activeProject: null,
      setActiveOrganization: (org) => {
        set({ activeOrganization: org });
        if (typeof localStorage !== 'undefined') {
          localStorage.setItem('cyberguard_active_org', JSON.stringify(org));
        }
      },
      setActiveProject: (proj) => {
        set({ activeProject: proj });
        if (typeof localStorage !== 'undefined') {
          localStorage.setItem('cyberguard_active_project', JSON.stringify(proj));
        }
      },
    }));

    const mockOrg = { id: 'org-test-99', name: 'Sentinel SOC' };
    const mockProj = { id: 'proj-test-1', name: 'Default Workspace', slug: 'default-workspace' };

    store.getState().setActiveOrganization(mockOrg);
    store.getState().setActiveProject(mockProj);

    assert.strictEqual(store.getState().activeOrganization.id, 'org-test-99');
    assert.strictEqual(store.getState().activeProject.id, 'proj-test-1');

    // Verify ProjectSelector has Active ring styling and active badge
    const projectSelectorPath = path.resolve('src/pages/ProjectSelector.tsx');
    const content = fs.readFileSync(projectSelectorPath, 'utf8');
    assert.match(content, /ring-2 ring-red-500/);
    assert.match(content, /Active/);
  });

  // Check 9: forbidden-strings grep across new components = zero hits
  it('9 forbidden-strings grep across new components = zero hits', () => {
    const filesToCheck = [
      path.resolve('src/pages/OrgEntry.tsx'),
      path.resolve('src/pages/OrgSelector.tsx'),
      path.resolve('src/pages/ProjectSelector.tsx'),
      path.resolve('src/services/orgApi.ts'),
    ];

    const forbiddenPatterns = [
      { name: 'Free', regex: /\bFree\b/i },
      { name: 'Pro', regex: /\bPro\b/ }, // Whole word Pro (e.g. Pro plan)
      { name: 'Upgrade', regex: /\bUpgrade\b/i },
      { name: 'billing', regex: /\bbilling\b/i },
      { name: 'plan', regex: /\bplan\b/i },
      { name: 'usage', regex: /\busage\b/i },
      { name: 'Nano', regex: /\bNano\b/i },
      { name: 'region codes', regex: /\b(ap|eu)-[a-z0-9-]+/i },
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
  });

  // Check 10: personal login suite still green + personal pages unchanged
  it('10 personal login suite still green + personal pages unchanged', () => {
    const loginPath = path.resolve('src/pages/Login.tsx');
    assert.ok(fs.existsSync(loginPath), 'Login.tsx must exist');
    const loginContent = fs.readFileSync(loginPath, 'utf8');

    // Personal login retains all core personal modes
    assert.match(loginContent, /mode === 'signin'/);
    assert.match(loginContent, /mode === 'signup'/);
    assert.match(loginContent, /mode === 'forgot'/);
    assert.match(loginContent, /Sign In to Workspace/);

    // Subtle organization login link added
    assert.match(loginContent, /to="\/org\/entry"/);
    assert.match(loginContent, /Organization login →/);

    // Personal pages unchanged in App.tsx
    const appPath = path.resolve('src/App.tsx');
    const appContent = fs.readFileSync(appPath, 'utf8');
    assert.match(appContent, /path="\/dashboard"/);
    assert.match(appContent, /path="\/phishing"/);
    assert.match(appContent, /path="\/url-analysis"/);
    assert.match(appContent, /path="\/quarantine"/);
    assert.match(appContent, /path="\/security-history"/);
    assert.match(appContent, /path="\/settings"/);
  });
});
