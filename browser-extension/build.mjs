#!/usr/bin/env node
/*
 * CyberGuard extension build — one source, two targets.
 *
 *   dist/chromium/  MV3, background.service_worker, pinned "key" so the
 *                   unpacked extension ID is stable (chrome-extension://mkhcpikficaipogflekjkoiplegbeaji)
 *   dist/firefox/   MV3, background.scripts (event page),
 *                   browser_specific_settings.gecko.id pinned
 *
 * Also emits dist/<target>/config.js from environment / frontend/.env.local
 * and validates both manifests structurally. Run `npx web-ext lint` per
 * target after building (see package.json "lint").
 */
import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const SRC = join(ROOT, 'src');

// Stable unpacked-extension identity for Chromium (dev CORS pinning).
const CHROMIUM_KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw37Yoh7cuE9ymlTObI7lNn8kajCI8lK0C8EBNG6rqhpJcwJ6/mzQPDFoR0X25svNZCT4VJuLwu0UTUo18ANpTt/CaDON9PT7fCVoGcadig8tXFs8xut8NETNik9C01LSsAduwcvk1SVVP2sAL0UHcvyBRjHKg80HdR5tS+HsRDziLJqDrcKnDnBVmaT14T5Zi7BBNuN+DT4r5KeUCePaQZWQYE/TrAe2tkCD3yX1HtFoeT0s/NDfkWKXETQkvUT2BylF3cJeGmVScZJMVxdnxSJFkFiX/8tCn+AQTBFM1qL2JVrmrPYBZb94468FgsEBdfF6p2hudRdaM+VHaZqlfwIDAQAB';
// Chrome ID derivation (crx_file::id_util): SHA256 of the SPKI DER, first
// 16 bytes rendered as 32 hex digits, mapped 0-f -> a-p.
export const CHROMIUM_EXT_ID = [...createHash('sha256')
  .update(Buffer.from(CHROMIUM_KEY, 'base64'))
  .digest()
  .subarray(0, 16)
  .toString('hex')]
  .map((c) => String.fromCharCode(97 + parseInt(c, 16)))
  .join('');
export const GECKO_ID = 'cyberguard-soc@cyberguard.local';

function loadDotEnv(path) {
  if (!existsSync(path)) return {};
  const out = {};
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return out;
}

/**
 * Config precedence: EXT_* env vars > frontend/.env.local VITE_* > dev defaults.
 */
export function resolveConfig(env = process.env) {
  const fe = loadDotEnv(join(ROOT, '..', 'frontend', '.env.local'));
  const pick = (envKey, feKey, fallback) =>
    (env[envKey] || (feKey ? fe[feKey] : undefined) || fallback).replace(/\/+$/, '');
  return {
    WEB_ORIGIN: pick('EXT_WEB_ORIGIN', null, 'http://localhost:5173'),
    API_BASE_URL: pick('EXT_API_BASE_URL', 'VITE_API_BASE_URL', 'http://localhost:8000/api/v1'),
    SUPABASE_URL: pick('EXT_SUPABASE_URL', 'VITE_SUPABASE_URL', ''),
    SUPABASE_ANON_KEY: pick('EXT_SUPABASE_ANON_KEY', 'VITE_SUPABASE_ANON_KEY', ''),
  };
}

export function buildManifest(target, cfg) {
  const base = JSON.parse(readFileSync(join(SRC, 'manifest.base.json'), 'utf8'));
  const manifest = {
    ...base,
    content_scripts: base.content_scripts.map((cs) => ({ ...cs, matches: [`${cfg.WEB_ORIGIN}/*`] })),
    host_permissions: hostPermissions(cfg),
  };
  if (target === 'chromium') {
    manifest.background = { service_worker: 'background.js' };
    manifest.key = CHROMIUM_KEY;
    manifest.minimum_chrome_version = '102';
  } else if (target === 'firefox') {
    manifest.background = { scripts: ['background.js'] };
    manifest.browser_specific_settings = {
      gecko: {
        id: GECKO_ID,
        strict_min_version: '115.0',
        // No telemetry/data collection (AMO notice: MISSING_DATA_COLLECTION_PERMISSIONS).
        data_collection_permissions: { required: ['none'] },
      },
    };
  } else {
    throw new Error(`unknown target: ${target}`);
  }
  return manifest;
}

function hostPermissions(cfg) {
  const perms = new Set([`${cfg.WEB_ORIGIN}/*`]);
  try {
    perms.add(`${new URL(cfg.API_BASE_URL).origin}/*`);
  } catch {
    throw new Error(`invalid EXT_API_BASE_URL: ${cfg.API_BASE_URL}`);
  }
  perms.add(cfg.SUPABASE_URL ? `${new URL(cfg.SUPABASE_URL).origin}/*` : 'https://*.supabase.co/*');
  return [...perms];
}

export function validateManifest(manifest, target) {
  const problems = [];
  if (manifest.manifest_version !== 3) problems.push('manifest_version must be 3');
  if (!manifest.name || !manifest.version) problems.push('name/version required');
  if (!manifest.action?.default_popup) problems.push('action.default_popup required');
  if (!manifest.permissions?.includes('storage')) problems.push('storage permission required');
  if (target === 'chromium') {
    if (manifest.background?.service_worker !== 'background.js') {
      problems.push('chromium background must be { service_worker }');
    }
    if (!manifest.key) problems.push('chromium manifest must pin key for stable dev ID');
    if (manifest.background?.scripts) problems.push('chromium must not use background.scripts');
  } else {
    if (!manifest.background?.scripts?.includes('background.js')) {
      problems.push('firefox background must be { scripts: [...] } event page');
    }
    if (!manifest.browser_specific_settings?.gecko?.id) problems.push('gecko.id required');
    if (manifest.background?.service_worker) problems.push('firefox must not use service_worker');
  }
  const cs = manifest.content_scripts?.[0];
  if (!cs || cs.matches?.length !== 1 || !cs.matches[0].endsWith('/*')) {
    problems.push('content_scripts must match the web origin');
  }
  if (!cs?.js?.includes('content/callback-bridge.js')) {
    problems.push('content script must include callback-bridge.js');
  }
  for (const icon of Object.values(manifest.icons || {})) {
    if (!existsSync(join(SRC, icon))) problems.push(`missing icon file: ${icon}`);
  }
  if (problems.length) throw new Error(`manifest validation (${target}): ${problems.join('; ')}`);
  return true;
}

export function build(target, cfg = resolveConfig()) {
  const dist = join(ROOT, 'dist', target);
  rmSync(dist, { recursive: true, force: true });
  cpSync(SRC, dist, { recursive: true });
  const manifest = buildManifest(target, cfg);
  validateManifest(manifest, target);
  writeFileSync(join(dist, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(
    join(dist, 'config.js'),
    `// Generated by build.mjs — do not edit.\n` +
      `globalThis.EXT_CONFIG = ${JSON.stringify(cfg, null, 2)};\n`
  );
  return { target, dist, manifest, cfg };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const cfg = resolveConfig();
  for (const target of ['chromium', 'firefox']) {
    const { dist } = build(target, cfg);
    console.log(`built ${dist}`);
  }
  console.log(`chromium extension id: ${CHROMIUM_EXT_ID} (chrome-extension://${CHROMIUM_EXT_ID})`);
  console.log(`firefox gecko id: ${GECKO_ID}`);
}
