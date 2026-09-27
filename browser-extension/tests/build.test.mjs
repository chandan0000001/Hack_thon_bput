/*
 * EXT-P1 Check 7 — build.mjs emits both dists with valid manifests and
 * web-ext lint is clean (0 errors) for each target.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import assert from 'node:assert';

const EXT = join(dirname(fileURLToPath(import.meta.url)), '..');

function manifest(target) {
  return JSON.parse(readFileSync(join(EXT, 'dist', target, 'manifest.json'), 'utf8'));
}

test('7.1 build runs clean and emits both dist trees', () => {
  const out = execFileSync('node', ['build.mjs'], { cwd: EXT, encoding: 'utf8' });
  assert.match(out, /built .*dist[\/\\]chromium/);
  assert.match(out, /built .*dist[\/\\]firefox/);
  for (const target of ['chromium', 'firefox']) {
    assert.ok(readFileSync(join(EXT, 'dist', target, 'config.js'), 'utf8').includes('EXT_CONFIG'));
    assert.ok(readFileSync(join(EXT, 'dist', target, 'background.js'), 'utf8').length > 0);
  }
});

test('7.2 chromium manifest: MV3 service worker + pinned key, no scripts', () => {
  const m = manifest('chromium');
  assert.equal(m.manifest_version, 3);
  assert.equal(m.background.service_worker, 'background.js');
  assert.ok(!m.background.scripts, 'chromium must not carry background.scripts');
  assert.ok(m.key && m.key.startsWith('MIIB'), 'pinned key present for stable dev ID');
  assert.equal(m.action.default_popup, 'popup/popup.html');
  assert.ok(m.permissions.includes('storage'));
  assert.equal(m.content_scripts[0].matches.length, 1);
  assert.ok(m.content_scripts[0].js.includes('content/callback-bridge.js'));
  assert.ok(m.content_scripts[0].js.includes('lib/path-gate.js'), 'path gate loads before the bridge');
});

test('7.3 firefox manifest: MV3 event page + pinned gecko id, no service worker', () => {
  const m = manifest('firefox');
  assert.equal(m.manifest_version, 3);
  assert.deepEqual(m.background.scripts, ['background.js']);
  assert.ok(!m.background.service_worker, 'firefox must not carry service_worker');
  assert.match(m.browser_specific_settings.gecko.id, /^cyberguard-soc@/);
  assert.ok(m.browser_specific_settings.gecko.strict_min_version);
  assert.equal(m.action.default_popup, 'popup/popup.html');
  assert.equal(m.content_scripts[0].matches.length, 1);
});

test('7.4 manifest diff chromium vs firefox is exactly the target delta', () => {
  const c = manifest('chromium');
  const f = manifest('firefox');
  const diffKeys = (a, b) =>
    [...new Set([...Object.keys(a), ...Object.keys(b)])].filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]));
  const keys = diffKeys(c, f);
  // Everything else (action, permissions, content_scripts, icons, name, ...)
  // must be byte-identical between the two builds.
  assert.deepEqual(
    keys.filter((k) => k !== 'background' && k !== 'key' && k !== 'browser_specific_settings' && k !== 'minimum_chrome_version'),
    [],
    `unexpected manifest divergence: ${keys.join(', ')}`
  );
});

test('7.5 web-ext lint per target (Firefox rules are the authority)', () => {
  // web-ext lint applies Firefox/AMO rules to every source dir. The Firefox
  // dist must therefore be fully clean. The Chromium dist intentionally uses
  // MV3 service_worker + a Chrome "key" (pinned dev ID) instead of a gecko
  // id, which Firefox rules report as MANIFEST_FIELD_UNSUPPORTED /
  // EXTENSION_ID_REQUIRED — those two codes and zero warnings are the
  // chromium gate; anything else fails.
  const CHROMIUM_EXPECTED_CODES = new Set(['MANIFEST_FIELD_UNSUPPORTED', 'EXTENSION_ID_REQUIRED']);
  for (const target of ['chromium', 'firefox']) {
    const res = spawnSync('npx', ['web-ext', 'lint', '--source-dir', join(EXT, 'dist', target)], {
      encoding: 'utf8',
      cwd: EXT,
      timeout: 120000,
    });
    const output = `${res.stdout || ''}${res.stderr || ''}`;
    // web-ext exits non-zero when ANY error is reported; chromium errors are
    // expected (Firefox rules applied to a Chrome manifest) and gated below.
    if (target === 'firefox' && res.status !== 0) {
      assert.fail(`web-ext lint failed for firefox:\n${output}`);
    }
    const warningMatch = output.match(/warnings\s+(\d+)/i);
    assert.equal(warningMatch && Number(warningMatch[1]), 0, `${target}: 0 warnings\n${output}`);
    // Codes are table rows in the ERRORS section (NOTICES are non-fatal).
    const errorsSection = output.split(/NOTICES?:/)[0];
    const errorCodes = [...errorsSection.matchAll(/^([A-Z][A-Z0-9_]{3,})(?=\s{2})/gm)].map((m) => m[1]);
    if (target === 'firefox') {
      assert.deepEqual(errorCodes, [], `firefox lint must have 0 errors\n${output}`);
    } else {
      assert.deepEqual(
        [...new Set(errorCodes)].sort(),
        [...CHROMIUM_EXPECTED_CODES].sort(),
        `chromium lint: only the documented cross-target codes allowed\n${output}`
      );
    }
  }
});
