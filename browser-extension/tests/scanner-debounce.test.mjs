/*
 * EXT-P3 Check 17 — debounce: rapid mutations collapse into ONE batch flush.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
const { createBatcher } = globalThis.CyberGuardExt.detect;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('17 rapid adds -> single debounced flush with every item', async () => {
  const flushes = [];
  const batcher = createBatcher((batch) => flushes.push(batch), 60);

  // Simulate a mutation storm: 8 rapid adds inside the debounce window.
  for (let i = 0; i < 8; i += 1) {
    batcher.add({ i });
    await sleep(5); // 5ms apart — each add resets the 60ms timer
  }
  assert.equal(flushes.length, 0, 'nothing flushed while mutations keep coming');

  await sleep(120); // let the window elapse
  assert.equal(flushes.length, 1, 'exactly one batch flushed');
  assert.equal(flushes[0].length, 8, 'all 8 items in the single batch');
  assert.deepEqual(flushes[0].map((x) => x.i), [0, 1, 2, 3, 4, 5, 6, 7]);

  // A follow-up add starts a fresh batch.
  batcher.add({ i: 9 });
  await sleep(120);
  assert.equal(flushes.length, 2);
  assert.deepEqual(flushes[1], [{ i: 9 }]);

  // cancel() drops pending work entirely.
  batcher.add({ i: 10 });
  batcher.cancel();
  await sleep(120);
  assert.equal(flushes.length, 2, 'cancelled batch never flushes');
});
