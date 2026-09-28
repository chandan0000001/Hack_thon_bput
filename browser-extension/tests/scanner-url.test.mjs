/*
 * EXT-P3 Check 14 — scanner URL detection: mock DOM with 5 links (+ text
 * URLs) yields exactly the deduped, capped detections.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const { window } = new JSDOM('<!doctype html><html><body></body></html>');
globalThis.CyberGuardExt = undefined;
// detect.js is a classic script attaching to globalThis — run it as a function body.
new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
const { detectUrls } = globalThis.CyberGuardExt.detect;

function dom(html) {
  return new JSDOM(html).window.document;
}

test('14 URL detection: 5 links -> 5 detections, deduped and capped', () => {
  const doc = dom(`
    <a href="https://a.example/1">one</a>
    <a href="https://b.example/2">two</a>
    <a href="https://c.example/3">three</a>
    <a href="https://a.example/1">dupe of one</a>
    <a href="http://d.example/4">four</a>
    <a href="https://e.example/5">five</a>
    <p>Read more at https://f.example/6 in plain text</p>
  `);
  const found = detectUrls(doc, 20);
  assert.equal(found.length, 6, '5 unique links + 1 text URL (dedup kills the 6th link)');
  const values = found.map((d) => d.value);
  assert.ok(values.includes('https://a.example/1'));
  assert.ok(values.every((v) => /^https?:\/\//.test(v)));
  assert.ok(found.every((d) => d.kind === 'url'));

  // Cap respected.
  assert.equal(detectUrls(doc, 3).length, 3);

  // javascript:/data: hrefs and web-store links are never reported.
  const hostile = dom(`
    <a href="javascript:alert(1)">js</a>
    <a href="data:text/html,hi">data</a>
    <a href="https://chromewebstore.google.com/x">store</a>
  `);
  assert.deepEqual(detectUrls(hostile, 20), []);
});
