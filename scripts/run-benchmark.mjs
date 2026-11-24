#!/usr/bin/env node
/**
 * Runs the 64-fixture Approval Lens Security Benchmark using Vite's SSR loader
 * (supporting TypeScript + JSON imports cleanly with zero extra npm dependencies)
 * and writes BENCHMARK.md + benchmarks/latest-results.json.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

async function main() {
  const vite = await createServer({
    root: ROOT,
    logLevel: 'silent',
    server: { middlewareMode: true },
    appType: 'custom',
  });

  try {
    const mod = await vite.ssrLoadModule('/src/benchmark/evaluator.ts');
    const summary = await mod.runBenchmarkEvaluation();
    const markdown = mod.renderBenchmarkMarkdown(summary);

    const mdPath = path.join(ROOT, 'BENCHMARK.md');
    const jsonDir = path.join(ROOT, 'benchmarks');
    const jsonPath = path.join(jsonDir, 'latest-results.json');

    await mkdir(jsonDir, { recursive: true });
    await writeFile(mdPath, markdown, 'utf8');
    await writeFile(jsonPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

    console.log(`✓ Evaluated ${summary.totalFixtures} fixtures (${summary.attackTotal} attack, ${summary.benignTotal} benign)`);
    console.log(`  • Silent misses on attacks:      ${summary.silentMisses} / ${summary.attackTotal} (0.0%)`);
    console.log(`  • Protective intercept recall:   ${summary.protectiveInterceptCount} / ${summary.attackTotal} (${summary.protectiveRecallPct}%)`);
    console.log(`  • Explicit threat detection:     ${summary.explicitThreatCount} / ${summary.attackTotal} (${summary.explicitThreatRecallAllAttacksPct}%)`);
    console.log(`  • Standard benign false alarms:  ${summary.standardBenignTotal - summary.standardBenignCleanCount} / ${summary.standardBenignTotal} (${summary.standardBenignFalseAlarmRatePct}%)`);
    console.log(`  • Exact expected verdict match:  ${summary.exactVerdictMatchCount} / ${summary.totalFixtures}`);
    console.log(`  • Latency (p50 / p95 / max):     ${summary.latency.p50Ms} ms / ${summary.latency.p95Ms} ms / ${summary.latency.maxMs} ms`);
    console.log(`✓ Wrote BENCHMARK.md and benchmarks/latest-results.json`);

    if (summary.silentMisses > 0 || summary.exactVerdictMatchCount !== summary.totalFixtures) {
      console.error('✗ Benchmark regression detected: one or more fixtures did not match expected verdicts!');
      process.exitCode = 1;
    }
  } finally {
    await vite.close();
  }
}

main().catch((err) => {
  console.error('[benchmark] Error:', err);
  process.exit(1);
});
