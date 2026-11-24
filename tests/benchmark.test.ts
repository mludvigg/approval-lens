import { describe, expect, it } from 'vitest';
import { renderBenchmarkMarkdown, runBenchmarkEvaluation } from '../src/benchmark/evaluator';

describe('Approval Lens v0.3.0 — 64-Fixture Security Benchmark Suite', () => {
  it('evaluates all 64 fixtures with 0 silent misses, 0% standard benign false alarms, and 64/64 expected verdicts', async () => {
    const summary = await runBenchmarkEvaluation();

    expect(summary.totalFixtures).toBe(64);
    expect(summary.attackTotal).toBe(32);
    expect(summary.benignTotal).toBe(32);
    expect(summary.standardBenignTotal).toBe(26);
    expect(summary.complexBenignTotal).toBe(6);

    // Zero silent misses: no attack is ever passed off as UNDERSTOOD
    expect(summary.silentMisses).toBe(0);
    expect(summary.protectiveRecallPct).toBe(100);
    expect(summary.explicitThreatCount).toBe(30);

    // Zero false alarms on everyday capped approvals, revokes, transfers, multicalls & SIWE logins
    expect(summary.standardBenignCleanCount).toBe(26);
    expect(summary.standardBenignFalseAlarmRatePct).toBe(0);

    // Every single fixture matches its ground-truth expected verdict
    const mismatches = summary.rows.filter((r) => !r.matchedExpected);
    expect(mismatches).toEqual([]);
    expect(summary.exactVerdictMatchCount).toBe(64);

    const md = renderBenchmarkMarkdown(summary);
    expect(md).toContain('Executive Scorecard');
    expect(md).toContain('0 / 32 (`0.0%`)');
  });
});
