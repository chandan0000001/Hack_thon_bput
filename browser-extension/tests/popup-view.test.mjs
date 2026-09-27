/*
 * EXT-P2 Check 10 — popup view machine: Main menu → URL view → Back to menu.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'popup-views.js'), 'utf8'), { filename: 'popup-views.js' });
const { nextView } = globalThis.CyberGuardExt.popupViews;

test('10 main menu -> URL view -> Back returns to menu (and the other cards route too)', () => {
  let view = 'menu';
  view = nextView(view, 'OPEN_URL');
  assert.equal(view, 'url', 'Scan URL card opens the URL view');
  view = nextView(view, 'BACK');
  assert.equal(view, 'menu', 'Back returns to the main menu');

  // Round-trips for the other two tools.
  assert.equal(nextView('menu', 'OPEN_EMAIL'), 'email');
  assert.equal(nextView('email', 'BACK'), 'menu');
  assert.equal(nextView('menu', 'OPEN_DEEPFAKE'), 'deepfake');
  assert.equal(nextView('deepfake', 'BACK'), 'menu');

  // Unknown actions are no-ops.
  assert.equal(nextView('url', 'SOMETHING_ELSE'), 'url');
  assert.equal(nextView('menu', 'BACK'), 'menu');
});
