import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const shellPath = path.resolve('src/pages/OrgWorkspaceShell.tsx');
const appPath = path.resolve('src/App.tsx');
const selectorPath = path.resolve('src/pages/ProjectSelector.tsx');
const topbarPath = path.resolve('src/components/layout/Topbar.tsx');

describe('ORG-SHELL-1 Test Suite (8 Checks)', () => {
  // Check 1: workspace route is session-guarded in App.tsx
  it('1 /org/:orgId/projects/:projectId/workspace route registered behind OrgGuard', () => {
    const app = fs.readFileSync(appPath, 'utf8');
    assert.match(app, /import OrgWorkspaceShell from '\.\/pages\/OrgWorkspaceShell'/);
    assert.match(app, /path="\/org\/:orgId\/projects\/:projectId\/workspace"/);
    // Route element wrapped in OrgGuard
    assert.match(
      app,
      /<OrgGuard>\s*<OrgWorkspaceShell \/>\s*<\/OrgGuard>/
    );
  });

  // Check 2: shell renders the standard layout frame
  it('2 shell renders Topbar + org identity sidebar + empty main', () => {
    const shell = fs.readFileSync(shellPath, 'utf8');
    assert.match(shell, /import Topbar from '\.\.\/components\/layout\/Topbar'/);
    // Org identity header (Building2 icon + org name) in the sidebar
    assert.match(shell, /<aside/);
    assert.match(shell, /Building2/);
    assert.match(shell, /\{org\.name\}/);
    assert.match(shell, /\{project\.name\}/);
    // Main renders the frame's children only (workspace frame passes none -> empty canvas)
    assert.match(shell, /<main\n?[^>]*data-testid="shell-main"/);
    assert.match(shell, /\{children \?\? null\}/);
  });

  // Check 3: zero widgets — no nav items, cards, tables, or empty-state copy
  it('3 shell has zero nav items and zero widget markup', () => {
    const shell = fs.readFileSync(shellPath, 'utf8');
    assert.doesNotMatch(shell, /NavLink/);
    assert.doesNotMatch(shell, /<table/i);
    assert.doesNotMatch(shell, /<canvas/i);
    // No empty-state copy / headings in the main area
    assert.doesNotMatch(shell, /Nothing here|Coming Soon|Get started|No projects/);
  });

  // Check 4: zero data fetching in the shell
  it('4 shell performs zero API calls (identity from session state only)', () => {
    const shell = fs.readFileSync(shellPath, 'utf8');
    assert.doesNotMatch(shell, /fetch\(/);
    assert.doesNotMatch(shell, /orgApi\./);
    assert.doesNotMatch(shell, /api\./);
    assert.doesNotMatch(shell, /useEffect/);
    // Identity resolution reads hydrated store state, not the network
    assert.match(shell, /useAuthStore\(\(s\) => s\.activeOrganization\)/);
    assert.match(shell, /useAuthStore\(\(s\) => s\.activeProject\)/);
  });

  // Check 5: wrong ids fall back to /org/select
  it('5 id mismatch redirects to /org/select', () => {
    const shell = fs.readFileSync(shellPath, 'utf8');
    assert.match(shell, /<Navigate to="\/org\/select" replace \/>/);
    assert.match(shell, /org\?\.id !== orgId \|\| project\?\.id !== projectId/);
  });

  // Check 6: ProjectSelector activation navigates to the shell
  it('6 selecting/creating a project navigates to the workspace shell', () => {
    const selector = fs.readFileSync(selectorPath, 'utf8');
    const navigations = selector.match(/navigate\(`\/org\/\$\{orgId\}\/projects\/\$\{[\w.]+\.id\}\/workspace`\)/g) || [];
    assert.ok(navigations.length >= 2, 'both select and create flows must navigate to the shell');
  });

  // Check 7: shell topbar keeps "All organizations" link + clickable switcher chip
  it('7 topbar shows All organizations link and clickable project-switcher chip on shell', () => {
    const topbar = fs.readFileSync(topbarPath, 'utf8');
    assert.match(topbar, /All organizations/);
    assert.match(topbar, /to="\/org\/select"/);
    assert.match(topbar, /data-testid="shell-all-orgs-link"/);
    // Chip becomes a Link to the project selector on the shell route
    assert.match(topbar, /to=\{`\/org\/\$\{workspaceMatch!\[1\]\}\/projects`\}/);
    assert.match(topbar, /title="Switch project"/);
    // Non-shell routes keep the inert chip
    assert.match(topbar, /data-testid="topbar-org-chip"/);
  });

  // Check 8: theme-token reuse — only the existing zinc/red palette
  it('8 shell reuses existing zinc/red theme tokens only', () => {
    const shell = fs.readFileSync(shellPath, 'utf8');
    // Collect every tailwind color family used
    const families = new Set(
      (shell.match(/(?:bg|text|border|ring|shadow)-(?:[a-z]+)-\d+/g) || [])
        .map((c) => c.split('-').slice(-2)[0])
    );
    for (const family of families) {
      assert.ok(
        ['zinc', 'red'].includes(family),
        `unexpected color family "${family}" — reuse existing tokens only`
      );
    }
    assert.ok(families.has('zinc'), 'shell should use the zinc neutrals');
  });
});
