/*
 * EXT-P3 Check 15/16 — scanner email + image detection on mock DOMs.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
const { detectEmail, detectImages } = globalThis.CyberGuardExt.detect;

const dom = (html) => new JSDOM(html).window.document;

test('15 email detection: mock Gmail DOM -> extract body text (largest wins)', () => {
  const longBody = 'Dear user, your account will be suspended. '.repeat(5);
  const doc = dom(`
    <div id="app">
      <div role="main">
        <div class="ii"><div>${longBody}</div></div>
        <div class="ii"><div>quoted fragment</div></div>
      </div>
    </div>
  `);
  const email = detectEmail(doc);
  assert.ok(email, 'email detected');
  assert.equal(email.kind, 'email');
  assert.equal(email.source, 'div[role="main"] .ii');
  assert.match(email.value, /account will be suspended/);

  // Outlook + ProtonMail selectors also recognized; largest body wins.
  const mixed = dom(`
    <div aria-label="Message body">short-ish outlook body that passes the forty character threshold here</div>
    <div class="message-content">${'ProtonMail body text. '.repeat(10)}</div>
  `);
  const mixedEmail = detectEmail(mixed);
  assert.match(mixedEmail.value, /ProtonMail body text/);

  // Fragments below the 40-char floor are ignored.
  assert.equal(detectEmail(dom('<div class="ii"><div>tiny</div></div>')), null);
  assert.equal(detectEmail(dom('<div>no email containers here</div>')), null);
});

test('16 image detection: >200x200 kept, tracking pixels and icons filtered', () => {
  const doc = dom(`
    <img id="big" src="https://site.example/photo.jpg" width="400" height="300">
    <img id="big2" src="https://site.example/other.png" width="201" height="201">
    <img id="pixel" src="https://track.example/pixel.gif" width="1" height="1">
    <img id="icon" src="https://site.example/icon.png" width="32" height="32">
    <img id="boundary" src="https://site.example/exact.png" width="200" height="200">
  `);
  const found = detectImages(doc, 20);
  const values = found.map((d) => d.value);
  assert.deepEqual(values, ['https://site.example/photo.jpg', 'https://site.example/other.png'],
    'strictly >200 required; 200x200 boundary excluded');
  assert.ok(found.every((d) => d.kind === 'image' && d.width > 200 && d.height > 200));

  // Cap respected.
  assert.equal(detectImages(doc, 1).length, 1);
});
