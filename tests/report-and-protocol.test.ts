import { describe, expect, it } from 'vitest';
import { analyzeRequest } from '../src/core/analyzer';
import { buildSanitizedReport, renderHtmlReport } from '../src/core/report';
import { canonicalJson, deepFreeze, hashRpcPayload, safeClone } from '../src/shared/protocol';

describe('TOCTOU Payload Freezing & Canonical Hashing', () => {
  it('produces identical SHA-256 regardless of object key order', async () => {
    const h1 = await hashRpcPayload('eth_sendTransaction', [{ to: '0xabc', value: '0x1' }]);
    const h2 = await hashRpcPayload('eth_sendTransaction', [{ value: '0x1', to: '0xabc' }]);
    expect(h1).toBe(h2);
    expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it('prevents caller-side object mutation from altering frozen snapshot', () => {
    const mutableTx = { to: '0x1111', data: '0x095ea7b3' };
    const frozen = deepFreeze(safeClone([mutableTx]));

    // Simulate malicious dApp mutating its original object after calling provider.request
    mutableTx.to = '0xbad0';
    mutableTx.data = '0xffffffff';

    expect(frozen[0].to).toBe('0x1111');
    expect(() => {
      (frozen[0] as { to: string }).to = '0xhacked';
    }).toThrow();
  });
});

describe('Sanitized Report Generation & XSS Escaping', () => {
  it('redacts owner address, strips URL query tokens, and escapes HTML injection payloads', async () => {
    const result = await analyzeRequest({
      requestId: 'xss-test-1',
      createdAt: '2026-11-21T00:00:00.000Z',
      method: 'eth_signTypedData_v4',
      params: [
        '0x1111111111111111111111111111111111111111',
        JSON.stringify({
          primaryType: 'Permit',
          domain: {
            name: '<script>alert(1)</script>',
            verifyingContract: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
          },
          message: {
            owner: '0x1111111111111111111111111111111111111111',
            spender: '0xbad0000000000000000000000000000000000bad',
            value: '1000',
            deadline: '1900000000',
          },
        }),
      ],
      payloadHash: 'abcd'.repeat(16),
      origin: 'https://dapp.example/claim?session_token=SECRET123#frag',
    });

    const report = buildSanitizedReport(result, 'BLOCK');
    expect(report.origin).toBe('https://dapp.example');
    expect(report.decoded.owner).toContain('(redacted)');
    expect(report.decoded.owner).not.toBe('0x1111111111111111111111111111111111111111');

    const html = renderHtmlReport(report);
    expect(html).not.toContain('<script>');
    expect(html).not.toContain('SECRET123');
    expect(html).toContain('Approval Lens — Sanitized Inspection Report');
  });
});
