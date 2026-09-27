import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

/**
 * EXT-P1 — /ext/auth + /ext/callback routes exist, are public (outside
 * ProtectedRoute), and the Login `next` redirect guard is in place.
 */
describe('EXT-ROUTES Test Suite (3 Checks)', () => {
  const appPath = path.resolve('src/App.tsx');
  const loginPath = path.resolve('src/pages/Login.tsx');
  const authPagePath = path.resolve('src/pages/ExtAuthPage.tsx');
  const callbackPagePath = path.resolve('src/pages/ExtCallbackPage.tsx');

  it('1 /ext/auth and /ext/callback are registered as public routes', () => {
    const app = fs.readFileSync(appPath, 'utf8');
    assert.match(app, /path="\/ext\/auth"/);
    assert.match(app, /path="\/ext\/callback"/);
    // Routes must not be wrapped by ProtectedRoute (extension tab may be signed out)
    assert.doesNotMatch(app, /ProtectedRoute[\s\S]{0,80}path="\/ext\//);
  });

  it('2 ExtAuthPage reuses Login and redirects live sessions to /ext/callback', () => {
    const page = fs.readFileSync(authPagePath, 'utf8');
    assert.match(page, /import Login from '\.\/Login'/);
    assert.match(page, /\/ext\/callback\?state=/);
    assert.match(page, /supabase\.auth\.getSession/);
    assert.ok(fs.existsSync(callbackPagePath), 'ExtCallbackPage.tsx must exist');
  });

  it('3 Login honors a safe ?next= override (same-app paths only)', () => {
    const login = fs.readFileSync(loginPath, 'utf8');
    assert.match(login, /searchParams\.get\('next'\)/);
    assert.match(login, /raw\.startsWith\('\/'\)/, 'guard: must start with /');
    assert.match(login, /raw\.startsWith\('\/\/'\)/, 'guard: must reject protocol-relative');
    assert.match(login, /goTo\(nextPath\)/);
    // Post-auth navigation must preserve the hash (EXT-P1 fragment handoff)
    assert.match(login, /window\.location\.hash/);
  });
});
