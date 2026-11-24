import { build } from 'vite';
import react from '@vitejs/plugin-react';
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(__dirname, '..');
const distDir = resolve(rootDir, 'dist');

const defineProd = {
  'process.env.NODE_ENV': JSON.stringify('production'),
};

async function main() {
  if (existsSync(distDir)) {
    rmSync(distDir, { recursive: true, force: true });
  }
  mkdirSync(distDir, { recursive: true });

  // 1. Build React UI entry points (popup.html & review.html)
  await build({
    root: resolve(rootDir, 'src/ui'),
    base: './',
    define: defineProd,
    plugins: [react()],
    build: {
      outDir: distDir,
      emptyOutDir: false,
      sourcemap: false,
      rollupOptions: {
        input: {
          popup: resolve(rootDir, 'src/ui/popup.html'),
          review: resolve(rootDir, 'src/ui/review.html'),
        },
      },
    },
    logLevel: 'warn',
  });

  // 2. Build Background Service Worker (ES module)
  await build({
    root: rootDir,
    define: defineProd,
    build: {
      outDir: distDir,
      emptyOutDir: false,
      sourcemap: false,
      lib: {
        entry: resolve(rootDir, 'src/background/index.ts'),
        formats: ['es'],
        fileName: () => 'background.js',
      },
      rollupOptions: {
        output: {
          inlineDynamicImports: true,
        },
      },
    },
    logLevel: 'warn',
  });

  // 3. Build Isolated Content Script (self-contained IIFE)
  await build({
    root: rootDir,
    define: defineProd,
    build: {
      outDir: distDir,
      emptyOutDir: false,
      sourcemap: false,
      lib: {
        entry: resolve(rootDir, 'src/content/index.ts'),
        name: 'ApprovalLensContent',
        formats: ['iife'],
        fileName: () => 'content.js',
      },
      rollupOptions: {
        output: {
          inlineDynamicImports: true,
        },
      },
    },
    logLevel: 'warn',
  });

  // 4. Build MAIN-world Inpage Interception Script (self-contained IIFE)
  await build({
    root: rootDir,
    define: defineProd,
    build: {
      outDir: distDir,
      emptyOutDir: false,
      sourcemap: false,
      lib: {
        entry: resolve(rootDir, 'src/inpage/index.ts'),
        name: 'ApprovalLensInpage',
        formats: ['iife'],
        fileName: () => 'inpage.js',
      },
      rollupOptions: {
        output: {
          inlineDynamicImports: true,
        },
      },
    },
    logLevel: 'warn',
  });

  // 5. Copy static public assets (manifest.json + icons)
  cpSync(resolve(rootDir, 'public'), distDir, { recursive: true });

  console.log('✓ Approval Lens built to dist/');
}

main().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
