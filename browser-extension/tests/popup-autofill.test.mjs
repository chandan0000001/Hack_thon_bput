/*
 * EXT-P2 Check 11 — URL auto-fill picks the right tab from a mock
 * chrome.tabs.query result (active http(s) tab; extension pages ignored).
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'popup-views.js'), 'utf8'), { filename: 'popup-views.js' });
const { pickTabUrl } = globalThis.CyberGuardExt.popupViews;

test('11 auto-fill URL comes from the active http(s) tab, never extension pages', () => {
  // The popup itself is the "active tab" in test harnesses — must be skipped.
  const tabs = [
    { id: 1, url: 'chrome-extension://mkhcpikficaipogflekjkoiplegbeaji/popup/popup.html', active: true },
    { id: 2, url: 'http://localhost:5173/dashboard', active: false },
  ];
  assert.equal(pickTabUrl(tabs), 'http://localhost:5173/dashboard');

  // Active http tab wins over background http tabs.
  assert.equal(
    pickTabUrl([
      { url: 'https://a.example', active: false },
      { url: 'https://b.example/login', active: true },
    ]),
    'https://b.example/login'
  );

  // Non-http schemes are unusable.
  assert.equal(
    pickTabUrl([{ url: 'chrome://settings', active: true }, { url: 'file:///etc/passwd', active: false }]),
    ''
  );
  assert.equal(pickTabUrl([]), '');
  assert.equal(pickTabUrl(undefined), '');
});
