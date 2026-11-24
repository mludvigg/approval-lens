import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const iconsDir = resolve(__dirname, '../public/icons');
mkdirSync(iconsDir, { recursive: true });

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function encodePng(width, height, rgba) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const raw = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y++) {
    const rowStart = y * (1 + width * 4);
    raw[rowStart] = 0; // filter None
    rgba.copy(raw, rowStart + 1, y * width * 4, (y + 1) * width * 4);
  }

  return Buffer.concat([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function drawIcon(size) {
  const buf = Buffer.alloc(size * size * 4);
  const cx = (size - 1) / 2;
  const cy = (size - 1) / 2;
  const radius = size * 0.44;
  const ringOuter = size * 0.30;
  const ringInner = size * 0.19;
  const dotRadius = size * 0.08;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.hypot(dx, dy);

      // Rounded-square dark navy badge with cyan lens ring
      const rx = Math.abs(dx) / (size * 0.46);
      const ry = Math.abs(dy) / (size * 0.46);
      const superEllipse = Math.pow(rx, 4) + Math.pow(ry, 4);

      if (superEllipse > 1.0) {
        buf[idx] = 0;
        buf[idx + 1] = 0;
        buf[idx + 2] = 0;
        buf[idx + 3] = 0;
        continue;
      }

      // Base background: #0f172a
      let r = 15, g = 23, b = 42, a = 255;

      // Subtle outer border
      if (superEllipse > 0.82) {
        r = 30; g = 41; b = 59;
      }

      // Lens ring: #38bdf8 (sky-400)
      if (dist <= ringOuter && dist >= ringInner) {
        r = 56; g = 189; b = 248;
      } else if (dist <= dotRadius) {
        // Center pupil: #34d399 (emerald-400)
        r = 52; g = 211; b = 153;
      } else if (dx > ringInner * 0.6 && dy > ringInner * 0.6 && Math.abs(dx - dy) < size * 0.075 && dist <= radius * 0.92) {
        // Lens handle diagonal
        r = 56; g = 189; b = 248;
      }

      buf[idx] = r;
      buf[idx + 1] = g;
      buf[idx + 2] = b;
      buf[idx + 3] = a;
    }
  }
  return encodePng(size, size, buf);
}

for (const size of [16, 48, 128]) {
  writeFileSync(resolve(iconsDir, `icon${size}.png`), drawIcon(size));
}
console.log('✓ Generated icons (16, 48, 128) in public/icons/');
