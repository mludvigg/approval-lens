#!/usr/bin/env node
/**
 * Offline Threat-Intel Sync Script (0 runtime network calls inside Chrome extension).
 *
 * Fetches the open-source MetaMask/eth-phishing-detect blocklist (DBADPL-1.2 license),
 * takes the most recent N entries (default: 2500 to keep the MV3 service worker bundle small),
 * computes a SHA-256 integrity digest, and writes src/data/community-domains.json with full attribution.
 *
 * Usage:
 *   node scripts/sync-threat-intel.mjs [--limit 2500]
 */

import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const SOURCE_URL =
  'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json';
const REPO_URL = 'https://github.com/MetaMask/eth-phishing-detect';
const LICENSE = 'DBADPL-1.2';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_PATH = path.resolve(__dirname, '../src/data/community-domains.json');

function parseLimitArg() {
  const idx = process.argv.indexOf('--limit');
  if (idx !== -1 && process.argv[idx + 1]) {
    const n = Number.parseInt(process.argv[idx + 1], 10);
    if (Number.isInteger(n) && n > 0) return n;
  }
  return 2500;
}

async function main() {
  const limit = parseLimitArg();
  console.log(`[sync:intel] Fetching ${SOURCE_URL} (license: ${LICENSE}, limit: ${limit})…`);

  const res = await fetch(SOURCE_URL, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} fetching ${SOURCE_URL}`);
  }

  const config = await res.json();
  if (!config || !Array.isArray(config.blacklist)) {
    throw new Error('Unexpected config.json format: missing blacklist array.');
  }

  // Take the tail of blacklist (newest community additions are appended at the end)
  const slice = config.blacklist
    .filter((d) => typeof d === 'string' && d.includes('.') && !d.includes(' '))
    .map((d) => d.trim().toLowerCase())
    .slice(-limit);

  const uniqueSorted = Array.from(new Set(slice)).sort();
  const sha256 = createHash('sha256').update(uniqueSorted.join('\n')).digest('hex');

  const payload = {
    source: 'MetaMask/eth-phishing-detect',
    repository: REPO_URL,
    license: LICENSE,
    attribution: `Derived from the open-source MetaMask eth-phishing-detect community blocklist (${REPO_URL}) under ${LICENSE}. Synced offline at build time (0 runtime network calls).`,
    updatedAt: new Date().toISOString(),
    count: uniqueSorted.length,
    sha256,
    domains: uniqueSorted,
  };

  await writeFile(OUT_PATH, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  console.log(
    `✓ Wrote ${uniqueSorted.length} domains to src/data/community-domains.json (sha256: ${sha256.slice(0, 16)}…)`,
  );
}

main().catch((err) => {
  console.error('[sync:intel] Failed:', err.message || err);
  process.exit(1);
});
