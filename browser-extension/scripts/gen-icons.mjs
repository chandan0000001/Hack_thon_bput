#!/usr/bin/env node
/*
 * Generate the CyberGuard shield icons (src/icons/icon{16,32,48,128}.png).
 * Pure-node PNG encoder — no image dependencies. Run once; outputs are
 * committed so builds stay offline-deterministic.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const ROOT = dirname(fileURLToPath(import.meta.url));
const OUT = join(ROOT, '..', 'src', 'icons');

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePng(width, height, rgba) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (width * 4 + 1)] = 0; // filter: none
    rgba.copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
  }
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

// Shield silhouette in unit coordinates (filled), red on transparent.
function shieldAlpha(x, y) {
  if (y < 0.08 || y > 0.92) return false;
  if (y <= 0.55) return x >= 0.24 && x <= 0.76;
  const t = (y - 0.55) / 0.37;
  const half = 0.26 * (1 - t);
  return x >= 0.5 - half && x <= 0.5 + half;
}

function makeIcon(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const RED = [0xdc, 0x26, 0x26];
  const DARK = [0x05, 0x05, 0x05];
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      const x = (px + 0.5) / size;
      const y = (py + 0.5) / size;
      const i = (py * size + px) * 4;
      if (shieldAlpha(x, y)) {
        // Inner check slash in near-black for texture on larger sizes.
        const inCheck =
          size >= 32 &&
          y > 0.38 && y < 0.62 &&
          x > 0.38 && x < 0.62 &&
          Math.abs((y - 0.62) + (x - 0.38)) < 0.07;
        const c = inCheck ? DARK : RED;
        rgba[i] = c[0];
        rgba[i + 1] = c[1];
        rgba[i + 2] = c[2];
        rgba[i + 3] = 255;
      }
    }
  }
  return encodePng(size, size, rgba);
}

mkdirSync(OUT, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  writeFileSync(join(OUT, `icon${size}.png`), makeIcon(size));
  console.log(`wrote ${OUT}/icon${size}.png`);
}
