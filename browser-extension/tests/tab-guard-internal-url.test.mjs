/*
 * Current-tab URL guard — isInternalUrl classification (pure lib/detect.js
 * logic; the background listener wires this the same way).
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
globalThis.CyberGuardExt = undefined;
new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
const { isInternalUrl } = globalThis.CyberGuardExt.detect;

test('internal pages are never scannable', () => {
  const internal = [
    'chrome://newtab/',
    'chrome://settings/privacy',
    'about:blank',
    'about:config',
    'edge://settings/',
    'chrome-extension://abcdef/popup/popup.html',
    'moz-extension://abcdef/popup.html',
    'devtools://devtools/bundled/inspector.html',
    'view-source:https://example.com/',
    'javascript:void(0)',
    'data:text/html,<h1>hi</h1>',
    'file:///home/user/report.html',
    '',
    null,
    undefined,
  ];
  for (const url of internal) {
    assert.ok(isInternalUrl(url), `should be internal: ${url}`);
  }
});

test('web stores remain excluded', () => {
  assert.ok(isInternalUrl('https://chrome.google.com/webstore/category/extensions'));
  assert.ok(isInternalUrl('https://microsoftedge.microsoft.com/addons/Microsoft-Edge-Extensions-Home'));
});

test('normal pages are scannable', () => {
  const external = [
    'https://example.com/',
    'http://neverssl.com/page',
    'https://accounts.google.com/o/oauth2/v2/auth?client_id=x',
    'https://sub.deep.host.co.uk/path?query=1#frag',
  ];
  for (const url of external) {
    assert.ok(!isInternalUrl(url), `should NOT be internal: ${url}`);
  }
});

test('cache key normalization strips fragments (SPA hash pushes)', () => {
  // The background uses new URL(url) with hash=''; verify the semantics the
  // guard relies on: fragment-only navigations share one cache entry.
  const a = new URL('https://example.com/app#/inbox');
  const b = new URL('https://example.com/app#/settings');
  a.hash = '';
  b.hash = '';
  assert.equal(a.href, b.href);
});
