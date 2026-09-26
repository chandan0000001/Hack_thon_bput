import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const settingsPagePath = path.resolve('src/pages/ProjectSettings.tsx');
const appPath = path.resolve('src/App.tsx');
const selectorPath = path.resolve('src/pages/ProjectSelector.tsx');
const topbarPath = path.resolve('src/components/layout/Topbar.tsx');

describe('ORG-SETTINGS-P2 Test Suite (4 Checks)', () => {
  // Check 1: both settings routes registered behind OrgGuard with correct sections
  it('1 both settings routes registered; General is default, api-keys has own route', () => {
    const app = fs.readFileSync(appPath, 'utf8');
    assert.match(app, /import ProjectSettings, \{ type ProjectSettingsSection \} from '\.\/pages\/ProjectSettings'/);
    assert.match(
      app,
      /path="\/org\/:orgId\/projects\/:projectId\/settings"[\s\S]{0,120}?<ProjectSettings section=\{'general' as ProjectSettingsSection\} \/>/
    );
    assert.match(
      app,
      /path="\/org\/:orgId\/projects\/:projectId\/settings\/api-keys"[\s\S]{0,120}?<ProjectSettings section=\{'api-keys' as ProjectSettingsSection\} \/>/
    );
    // Both wrapped in OrgGuard (session guard -> /login?mode=org)
    const guardCount = (app.match(/<OrgGuard>\s*<ProjectSettings[\s\S]*?<\/OrgGuard>/g) || []).length;
    assert.ok(guardCount === 2, `expected 2 OrgGuard-wrapped settings routes, got ${guardCount}`);
    assert.match(app, /if \(!isAuthenticated\) \{\s*return <Navigate to="\/login\?mode=org" replace \/>;/);
  });

  // Check 2: member/archived/missing guards redirect correctly
  it('2 guards: non-member -> /org/select; missing or archived -> /org/{orgId}/projects', () => {
    const page = fs.readFileSync(settingsPagePath, 'utf8');
    // 403 (non-member) -> org selector
    assert.match(page, /status === 403 \? '\/org\/select' : `\/org\/\$\{orgId\}\/projects`/);
    // archived project -> project list
    assert.match(page, /p\.status === 'archived'/);
    assert.match(page, /setRedirect\(`\/org\/\$\{orgId\}\/projects`\);/);
    // Data-minimal: exactly one API call, the project GET
    assert.match(page, /orgApi\.getProject\(orgId, projectId\)/);
    assert.doesNotMatch(page, /listProjects|listOrgs|dashboard|counters/);
  });

  // Check 3: sub-sidebar has Settings header + CONFIGURATION group with ONLY General/API Keys
  it('3 sub-sidebar: Settings header, CONFIGURATION group, exactly [General, API Keys]', () => {
    const page = fs.readFileSync(settingsPagePath, 'utf8');
    assert.match(page, />Settings</);
    assert.match(page, /Configuration/);
    // Router links with active highlight (aria-current) for both sections
    assert.match(page, /\{ id: 'general', label: 'General', icon: SettingsIcon \}/);
    assert.match(page, /\{ id: 'api-keys', label: 'API Keys', icon: KeyRound \}/);
    assert.match(page, /data-testid=\{`settings-nav-\$\{s\.id\}`\}/);
    assert.match(page, /aria-current=\{isActive \? 'page' : undefined\}/);
    // No other entries, ever
    assert.doesNotMatch(page, /Infrastructure|Integrations|Billing|Team|Members|Danger/);
    // Page header + subtitle + back link
    assert.match(page, />Project Settings</);
    assert.match(page, /General configuration, ownership, and lifecycle/);
    assert.match(page, /data-testid="settings-back-to-projects"/);
    assert.match(page, /to=\{`\/org\/\$\{orgId\}\/projects`\}/);
    // Topbar chips remain (topbar untouched on this route family)
    const topbar = fs.readFileSync(topbarPath, 'utf8');
    assert.match(topbar, /data-testid="topbar-org-chip"/);
    assert.match(topbar, /'Project Settings'/);
  });

  // Check 4: kebab menu shows Settings and navigates to that card's project
  it('4 kebab menu: Settings item navigates to /org/{orgId}/projects/{project.id}/settings', () => {
    const selector = fs.readFileSync(selectorPath, 'utf8');
    assert.match(selector, /data-testid=\{`kebab-settings-\$\{project\.id\}`\}/);
    assert.match(selector, /<Settings className="h-3\.5 w-3\.5" \/>/);
    assert.match(selector, /<span>Settings<\/span>/);
    assert.match(
      selector,
      /navigate\(`\/org\/\$\{orgId\}\/projects\/\$\{project\.id\}\/settings`\)/
    );
  });
});
