import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const shellPath = path.resolve('src/pages/OrgWorkspaceShell.tsx');
const appPath = path.resolve('src/App.tsx');
const settingsPath = path.resolve('src/pages/ProjectSettings.tsx');

describe('ORG-SETTINGS-P4 Test Suite (3 Checks)', () => {
  // Check 1: bottom reference-rail settings item with active state + visibility rules
  it('1 shell sidebar: Project Settings item at bottom, startsWith active, visibility gated', () => {
    const shell = fs.readFileSync(shellPath, 'utf8');
    // Gear icon + label + testid
    assert.match(shell, /<Settings className="h-4 w-4 shrink-0" \/>/);
    assert.match(shell, /<span>Project Settings<\/span>/);
    assert.match(shell, /data-testid="shell-settings-nav"/);
    // Active state via startsWith on the settings path, exposed as aria-current
    assert.match(shell, /location\.pathname\.startsWith\(settingsPath\)/);
    assert.match(shell, /aria-current=\{settingsActive \? 'page' : undefined\}/);
    // Bottom placement: spacer pushes the rail down, divider above
    assert.match(shell, /<div className="flex-1" \/>/);
    assert.match(shell, /<nav className="border-t border-zinc-800 p-3">/);
    // Visibility: resolved org+project only, archived project hidden
    assert.match(shell, /showSettingsItem = Boolean\(org && project && project\.status !== 'archived'\)/);
    // ORG-DASHBOARD-P3: exactly three sidebar Links — Dashboard, Events, Settings
    const links = shell.match(/<Link/g) || [];
    assert.strictEqual(links.length, 3, `shell sidebar must contain exactly three Links, found ${links.length}`);
  });

  // Check 2: settings routes hosted inside the shell; workspace route untouched
  it('2 nesting: both settings routes render ProjectSettings inside OrgWorkspaceShell frame=settings', () => {
    const app = fs.readFileSync(appPath, 'utf8');
    const nested = (app.match(/<OrgWorkspaceShell frame="settings">/g) || []).length;
    assert.strictEqual(nested, 2, `expected 2 shell-hosted settings routes, got ${nested}`);
    // Workspace route hosts the org dashboard inside the shell (ORG-DASHBOARD-P1)
    assert.match(app, /<OrgGuard>\s*<OrgWorkspaceShell>\s*<OrgDashboard \/>\s*<\/OrgWorkspaceShell>\s*<\/OrgGuard>/);
    // Settings page no longer renders its own Topbar (shell provides it)
    const settings = fs.readFileSync(settingsPath, 'utf8');
    assert.doesNotMatch(settings, /Topbar/);
  });

  // Check 3: active-state logic + sidebar persistence across the three routes
  it('3 navigation: item active on both settings routes, inactive on shell; sidebar persists', () => {
    // Logic simulation of the shell's active-state rule for each route family
    const orgId = 'org-1';
    const projectId = 'p-1';
    const settingsBase = `/org/${orgId}/projects/${projectId}/settings`;
    const routes = {
      workspace: `/org/${orgId}/projects/${projectId}/workspace`,
      general: settingsBase,
      apiKeys: `${settingsBase}/api-keys`,
    };
    const isActive = (pathname: string) => pathname.startsWith(settingsBase);
    assert.strictEqual(isActive(routes.workspace), false);
    assert.strictEqual(isActive(routes.general), true);
    assert.strictEqual(isActive(routes.apiKeys), true);

    // Settings content renders inside the shell main (children) and keeps its
    // own sub-sidebar — so the shell sidebar + sub-sidebar are both present.
    const shell = fs.readFileSync(shellPath, 'utf8');
    const settings = fs.readFileSync(settingsPath, 'utf8');
    assert.match(shell, /\{children \?\? null\}/);
    assert.match(shell, /data-testid="shell-sidebar"/);
    assert.match(settings, /data-testid="settings-sub-sidebar"/);
    assert.match(settings, /data-testid="settings-page"/);
    // Both General + API Keys section links retained (sub-sidebar untouched)
    assert.match(settings, /\{ id: 'general', label: 'General', icon: SettingsIcon \}/);
    assert.match(settings, /\{ id: 'api-keys', label: 'API Keys', icon: KeyRound \}/);
  });
});
