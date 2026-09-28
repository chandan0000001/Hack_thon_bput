/*
 * EXT-P3 Check 20 — overlay model: batch results render as summary + cards.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
new Function(readFileSync(join(ROOT, 'lib', 'detect.js'), 'utf8'))();
new Function(readFileSync(join(ROOT, 'content', 'overlay.js'), 'utf8'))();
const { buildOverlayModel } = globalThis.CyberGuardExt.overlayUi;

test('20 batch results -> severity summary + one card per detection', () => {
  const results = [
    { kind: 'url', input: 'https://a.example/1', ok: true, data: { risk_score: 91, severity: 'high', confidence: 0.9, indicators: [{ type: 'url', value: 'https://a.example/1', severity: 'high' }] } },
    { kind: 'url', input: 'https://b.example/2', ok: true, data: { risk_score: 55, severity: 'medium', confidence: 0.8, indicators: [] } },
    { kind: 'url', input: 'https://c.example/3', ok: true, data: { risk_score: 12, severity: 'low', confidence: 0.7, indicators: [] } },
    { kind: 'image', input: 'https://site.example/pic.jpg', ok: true, data: { manipulation_probability: 0.93, method: 'cnn-ensemble', severity: 'critical' } },
    { kind: 'url', input: 'https://d.example/4', ok: false, error: 'HTTP 503' },
  ];
  const model = buildOverlayModel(results);

  assert.equal(model.summary, '1 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW');
  assert.equal(model.cards.length, 5, 'one card per detection, including the failure');

  const urlCard = model.cards[0];
  assert.equal(urlCard.kind, 'url');
  assert.equal(urlCard.score, 91);
  assert.equal(urlCard.indicators.length, 1);

  const imageCard = model.cards[3];
  assert.equal(imageCard.kind, 'image');
  assert.equal(imageCard.verdict, 'FAKE');
  assert.equal(imageCard.confidence, 0.93);
  assert.equal(imageCard.method, 'cnn-ensemble');

  const failed = model.cards[4];
  assert.equal(failed.failed, true);
  assert.equal(failed.error, 'HTTP 503');

  // REAL verdict below the 0.5 line; empty batch -> "no results".
  const real = buildOverlayModel([{ kind: 'image', input: 'x', ok: true, data: { manipulation_probability: 0.2, severity: 'low' } }]);
  assert.equal(real.cards[0].verdict, 'REAL');
  assert.equal(buildOverlayModel([]).summary, 'no results');
});
