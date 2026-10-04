/*
 * Pill dismissal tests (sticky [×] behavior):
 * 1. [×] hides the pill; subsequent scans (mutations) do NOT reshow it.
 * 2. Unlock (popup auto-detect toggle off->on) revives the pill.
 * 3. Bootstrap honors the background's per-tab dismissed state (survives reloads).
 * 4. Analysis completing after dismissal does not reshow (setCounts guard).
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

const PAGE_HTML = `<!doctype html><html><body>
  <img src="https://example.com/img1.png" width="300" height="300">
</body></html>`;

function boot({ dismissedInBg = false } = {}) {
  const dom = new JSDOM(PAGE_HTML, { url: 'https://example.com/page' });
  dom.window.fetch = async () => { throw new Error('offline'); };
  // eslint-disable-next-line no-new-func
  new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
  dom.window.CyberGuardExt = { detect: globalThis.CyberGuardExt.detect };
  // eslint-disable-next-line no-new-func
  new Function('global', readFileSync(join(ROOT, 'content', 'pill.js'), 'utf8'))(dom.window);

  const sent = [];
  let bgDismissed = dismissedInBg;
  dom.window.chrome = {
    runtime: {
      sendMessage: (msg, cb) => {
        sent.push(msg);
        if (msg.type === 'GET_PILL_DISMISSED') return cb({ ok: true, dismissed: bgDismissed });
        if (msg.type === 'PILL_DISMISS') { bgDismissed = true; return cb({ ok: true }); }
        if (msg.type === 'PILL_RESUME') { bgDismissed = false; return cb({ ok: true }); }
        return cb({ ok: true, results: [] });
      },
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: { get: (k, cb) => cb({}) },
      onChanged: { addListener: () => {} },
    },
  };

  // eslint-disable-next-line no-new-func
  new Function('global', readFileSync(join(ROOT, 'content', 'scanner.js'), 'utf8'))(dom.window);

  return {
    dom,
    sent,
    scanner: dom.window.CyberGuardScanner,
    pillUi: dom.window.CyberGuardExt.pillUi,
    doc: dom.window.document,
    teardown: () => {
      try { dom.window.CyberGuardScanner.cancelBatcher(); } catch (e) {}
      try { dom.window.close(); } catch (e) {}
    },
  };
}

function closePill(doc) {
  doc.querySelector('#cgext-pill .cgext-pill__close').click();
}

test('dismiss [x] hides pill; rescans do not reshow; unlock revives', async (t) => {
  const { scanner, doc, teardown } = boot();
  t.after(teardown);
  // let the async bootstrap settle (scan + armObserver)
  await new Promise((r) => setTimeout(r, 10));

  const pill = doc.getElementById('cgext-pill');
  assert.ok(!pill.hidden, 'pill visible after initial scan');
  closePill(doc);
  assert.ok(pill.hidden, 'pill hidden after [x]');

  // New mutation -> scheduleScan -> would normally call setItems/setCounts
  const img2 = doc.createElement('img');
  img2.src = 'https://example.com/img2.png';
  img2.width = 300;
  img2.height = 300;
  doc.body.appendChild(img2);
  scanner.scheduleScan();
  scanner.scan(); // batcher flush equivalent
  assert.ok(pill.hidden, 'pill stays hidden across rescans after dismissal');
  assert.ok(scanner.isDismissed(), 'scanner marks tab dismissed');

  // Unlock (popup auto-detect re-toggle path) revives the pill
  scanner.setLocked(false);
  assert.ok(!scanner.isDismissed(), 'unlock clears dismissal');
  scanner.scan();
  assert.ok(!pill.hidden, 'pill visible again after unlock');
});

test('bootstrap honors background dismissed state (survives reloads)', async (t) => {
  const { scanner, doc, teardown } = boot({ dismissedInBg: true });
  t.after(teardown);
  await new Promise((r) => setTimeout(r, 10));
  const pill = doc.getElementById('cgext-pill');
  assert.ok(scanner.isDismissed(), 'scanner adopts dismissed state from background');
  assert.ok(pill.hidden, 'pill stays hidden on reload of a dismissed tab');
  scanner.scheduleScan();
  scanner.scan();
  assert.ok(pill.hidden, 'mutations still do not reshow the pill');
  scanner.setLocked(false);
  scanner.scan();
  assert.ok(!pill.hidden, 'auto-detect re-toggle revives the pill');
});

test('analysis completing after dismissal does not reshow pill', async (t) => {
  const { scanner, pillUi, doc, sent, teardown } = boot();
  t.after(teardown);
  await new Promise((r) => setTimeout(r, 10));
  const pill = doc.getElementById('cgext-pill');
  const item = scanner.scanDetections()[0];
  closePill(doc);
  await scanner.handleAnalyze([item]);
  pillUi.setCounts({ email: 0, image: 1 });
  assert.ok(pill.hidden, 'setCounts after dismissal must keep pill hidden');
  assert.ok(sent.some((m) => m.type === 'PILL_DISMISS'), 'dismissal reported to background');

  scanner.setLocked(false);
  assert.ok(sent.some((m) => m.type === 'PILL_RESUME'), 'resume clears background dismissed flag');
  scanner.scan();
  assert.ok(!pill.hidden, 'unlock still revives the pill afterwards');
});
