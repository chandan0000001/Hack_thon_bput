/*
 * EXT-P3 Check 18 — domain allowlist: with ['example.com'], URLs pointing
 * elsewhere are dropped and page-owned detections require an allowed host.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
const { filterByAllowlist } = globalThis.CyberGuardExt.detect;

test('18 allowlist filters foreign URLs and gates page detections', () => {
  const detections = [
    { kind: 'url', value: 'https://example.com/page' },
    { kind: 'url', value: 'https://sub.example.com/deep' },
    { kind: 'url', value: 'https://evil.example/phish' },
    { kind: 'url', value: 'https://notexample.com/prefix-trick' },
    { kind: 'email', value: 'body text' },
    { kind: 'image', value: 'https://evil.example/pic.jpg' },
  ];

  // Empty allowlist = everything (default).
  assert.equal(filterByAllowlist(detections, [], 'evil.example').length, 6);

  const filtered = filterByAllowlist(detections, ['example.com'], 'example.com');
  const values = filtered.map((d) => `${d.kind}:${d.value}`);
  assert.deepEqual(values, [
    'url:https://example.com/page',
    'url:https://sub.example.com/deep',
    'email:body text',
  ], 'subdomains allowed, prefix-trick host rejected, image dropped (page host ok but URL host foreign)');

  // Page host not allowlisted -> email/image (page-owned) detections gone.
  const otherPage = filterByAllowlist(detections, ['example.com'], 'untrusted.example');
  assert.deepEqual(otherPage.map((d) => d.value), [
    'https://example.com/page',
    'https://sub.example.com/deep',
  ]);

  // Case/whitespace tolerant.
  assert.equal(
    filterByAllowlist([{ kind: 'url', value: 'https://EXAMPLE.com/x' }], [' Example.com '], 'example.com').length,
    1
  );
});
