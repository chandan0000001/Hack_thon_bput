/*
 * EXT-P3 Check 19 — pill count formatting.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
const { formatCounts } = globalThis.CyberGuardExt.detect;

test('19 pill formatting: "3 links · 1 email · 2 images detected"', () => {
  assert.equal(formatCounts({ url: 3, email: 1, image: 2 }), '3 links · 1 email · 2 images detected');
  assert.equal(formatCounts({ url: 1, email: 0, image: 0 }), '1 link detected');
  assert.equal(formatCounts({ url: 0, email: 1, image: 0 }), '1 email detected');
  assert.equal(formatCounts({ url: 0, email: 0, image: 1 }), '1 image detected');
  assert.equal(formatCounts({ url: 0, email: 0, image: 0 }), null, 'nothing detected -> no pill text');
  assert.equal(formatCounts({ url: 5, email: 2, image: 0 }), '5 links · 2 emails detected');
});
