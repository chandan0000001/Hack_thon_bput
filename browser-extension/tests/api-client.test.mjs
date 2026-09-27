/*
 * EXT-P2 Check 8 — API client: mock fetch for URL, Email, Deepfake
 * (FormData verified for the image upload).
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'api-client.js'), 'utf8'), { filename: 'api-client.js' });
const { apiClient } = globalThis.CyberGuardExt;

const ALERT = { id: 'a1', risk_score: 82, severity: 'high', confidence: 0.9, indicators: [], mitre: [] };
const jsonRes = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});

test('8 API client methods hit the audited contracts (URL JSON, Email JSON, Deepfake FormData)', async () => {
  const calls = [];
  apiClient.configure({
    getAuth: async () => ({ access_token: 'tok-1', refresh_token: 'rt' }),
    refresh: async () => null,
    signOut: async () => {},
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return jsonRes(calls.length === 3 ? { module: 'deepfake', manipulation_probability: 0.87 } : ALERT);
    },
  });

  // URL: POST /analysis/url, JSON {url}, Bearer token
  const urlRes = await apiClient.analyzeUrl('http://api', 'https://evil.example/login');
  assert.equal(urlRes.risk_score, 82);
  assert.equal(calls[0].url, 'http://api/analysis/url');
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body), { url: 'https://evil.example/login' });
  assert.equal(calls[0].init.headers.Authorization, 'Bearer tok-1');
  assert.equal(calls[0].init.headers['Content-Type'], 'application/json');

  // Email: POST /analysis/email, From:/Subject: promoted into the payload
  const text = 'From: boss@corp.example\nSubject: URGENT wire transfer\n\nClick http://phish.example/pay now';
  const emailRes = await apiClient.analyzeEmail('http://api', text);
  assert.equal(emailRes.severity, 'high');
  assert.equal(calls[1].url, 'http://api/analysis/email');
  const body = JSON.parse(calls[1].init.body);
  assert.equal(body.sender, 'boss@corp.example');
  assert.equal(body.subject, 'URGENT wire transfer');
  assert.match(body.body, /phish\.example/);

  // Deepfake: POST /analysis/media, real FormData with the image under "file"
  const blob = new Blob(['pngbytes'], { type: 'image/png' });
  Object.defineProperty(blob, 'name', { value: 'suspect.png' });
  const mediaRes = await apiClient.analyzeDeepfake('http://api', blob);
  assert.equal(mediaRes.module, 'deepfake');
  assert.equal(calls[2].url, 'http://api/analysis/media');
  assert.ok(calls[2].init.body instanceof FormData, 'body is FormData');
  const stored = calls[2].init.body.get('file');
  assert.ok(stored instanceof Blob, 'image appended under field "file"');
  assert.equal(stored.size, blob.size, 'blob bytes preserved');
  assert.equal(calls[2].init.headers['Content-Type'], undefined, 'no JSON content-type (browser sets multipart boundary)');
  assert.equal(calls[2].init.headers.Authorization, 'Bearer tok-1');
});
