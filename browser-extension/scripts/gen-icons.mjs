#!/usr/bin/env node
/*
 * CyberGuard extension — store icon generation (npm run icons).
 *
 * Renders the brand shield as SVG (dark bg #0b0d10, red accent #ef4444,
 * white inner shield) and rasterizes it with sharp to
 * src/icons/icon-{16,32,48,128}.png — the files manifest.base.json ships.
 */
import { mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'icons');
const SIZES = [16, 32, 48, 128];

// Shield: rounded dark tile, red outer shield, white inner shield, red check.
const SVG = (size) => `
<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="24" fill="#0b0d10"/>
  <path d="M64 16 26 30v30c0 27 16.5 44.5 38 52 21.5-7.5 38-25 38-52V30L64 16Z"
        fill="#ef4444"/>
  <path d="M64 28 38 38v22c0 20 11.5 33.5 26 39.5C78.5 93.5 90 80 90 60V38L64 28Z"
        fill="#ffffff"/>
  <path d="M52 63.5 61.5 73 79 52.5" fill="none" stroke="#ef4444"
        stroke-width="9" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

mkdirSync(OUT, { recursive: true });
for (const size of SIZES) {
  const target = join(OUT, `icon-${size}.png`);
  await sharp(Buffer.from(SVG(size))).resize(size, size).png().toFile(target);
}
// Legacy names from the P1 generator are superseded — remove them so the
// icons directory holds exactly what the manifest references.
for (const legacy of ['icon16.png', 'icon32.png', 'icon48.png', 'icon128.png']) {
  rmSync(join(OUT, legacy), { force: true });
}
console.log(`wrote ${SIZES.map((s) => `icon-${s}.png`).join(', ')} -> ${OUT}`);
