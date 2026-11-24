import { describe, expect, it } from 'vitest';
import { encodeFunctionData, maxUint256, parseAbi, type Address } from 'viem';
import { analyzeRequest } from '../src/core/analyzer';
import type { InspectionRequest } from '../src/core/types';

const ERC20_ABI = parseAbi([
  'function approve(address spender, uint256 amount)',
  'function transfer(address to, uint256 amount)',
  'function setApprovalForAll(address operator, bool approved)',
  'function multicall(bytes[] data)',
]);

const USER_WALLET = '0x1111111111111111111111111111111111111111' as Address;
const USDC_MAINNET = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as Address;
const BENIGN_SPENDER = '0x2222222222222222222222222222222222222222' as Address;
const MALICIOUS_SPENDER = '0xbad0000000000000000000000000000000000bad' as Address;
const MALICIOUS_NFT_OP = '0xdeaf00000000000000000000000000000000cafe' as Address;
const PERMIT2_ADDR = '0x000000000022d473030f116ddee9f6b43ac78ba3' as Address;

function makeRequest(overrides: Partial<InspectionRequest>): InspectionRequest {
  return {
    requestId: 'test-req-001',
    createdAt: '2026-11-21T00:00:00.000Z',
    method: 'eth_sendTransaction',
    params: [],
    payloadHash: '0'.repeat(64),
    origin: 'https://app.example.org',
    walletName: 'MetaMask',
    chainIdHex: '0x1',
    ...overrides,
  };
}

describe('Approval Lens Core Analyzer', () => {
  it('decodes a legitimate capped ERC-20 approve as UNDERSTOOD with explicit limitations', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [BENIGN_SPENDER, 100_000_000n], // 100 USDC
    });

    const result = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: USDC_MAINNET, data }],
      }),
    );

    expect(result.verdict).toBe('UNDERSTOOD');
    expect(result.decoded.kind).toBe('ERC20_APPROVE');
    expect(result.decoded.isUnlimited).toBe(false);
    expect(result.decoded.spender?.toLowerCase()).toBe(BENIGN_SPENDER);
    expect(result.limitations.length).toBeGreaterThanOrEqual(2);
    expect(result.networkLog[0].status).toBe('skipped'); // 0 external calls in local-only mode
  });

  it('flags unlimited ERC-20 approval (MAX_UINT256) as HIGH_RISK', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [BENIGN_SPENDER, maxUint256],
    });

    const result = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: USDC_MAINNET, data }],
      }),
    );

    expect(result.verdict).toBe('HIGH_RISK');
    expect(result.decoded.isUnlimited).toBe(true);
    expect(result.findings.some((f) => f.id === 'UNLIMITED_ERC20_APPROVAL')).toBe(true);
  });

  it('flags approval to a known malicious spender as KNOWN_MALICIOUS', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [MALICIOUS_SPENDER, maxUint256],
    });

    const result = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: USDC_MAINNET, data }],
      }),
    );

    expect(result.verdict).toBe('KNOWN_MALICIOUS');
    expect(result.findings.some((f) => f.id === 'KNOWN_MALICIOUS_ADDRESS')).toBe(true);
  });

  it('flags subdomain of a known phishing origin as KNOWN_MALICIOUS', async () => {
    const result = await analyzeRequest(
      makeRequest({
        origin: 'https://portal.claim-airdrop-bonus.example',
        params: [{ from: USER_WALLET, to: BENIGN_SPENDER, value: '0x0' }],
      }),
    );

    expect(result.verdict).toBe('KNOWN_MALICIOUS');
    expect(result.findings.some((f) => f.id === 'KNOWN_MALICIOUS_ORIGIN')).toBe(true);
  });

  it('flags cross-origin iframe signing trigger', async () => {
    const result = await analyzeRequest(
      makeRequest({
        origin: 'https://embedded-widget.example',
        topLevelOrigin: 'https://trusted-news.example',
        params: [{ from: USER_WALLET, to: BENIGN_SPENDER, value: '0x0' }],
      }),
    );

    expect(result.verdict).toBe('HIGH_RISK');
    expect(result.findings.some((f) => f.id === 'CROSS_ORIGIN_IFRAME')).toBe(true);
  });

  it('flags NFT setApprovalForAll(true) as HIGH_RISK and KNOWN_MALICIOUS for listed operator', async () => {
    const benignOpCall = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'setApprovalForAll',
      args: [BENIGN_SPENDER, true],
    });
    const resHigh = await analyzeRequest(
      makeRequest({ params: [{ from: USER_WALLET, to: '0x3333333333333333333333333333333333333333', data: benignOpCall }] }),
    );
    expect(resHigh.verdict).toBe('HIGH_RISK');
    expect(resHigh.findings.some((f) => f.id === 'NFT_APPROVAL_FOR_ALL')).toBe(true);

    const maliciousOpCall = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'setApprovalForAll',
      args: [MALICIOUS_NFT_OP, true],
    });
    const resCrit = await analyzeRequest(
      makeRequest({ params: [{ from: USER_WALLET, to: '0x3333333333333333333333333333333333333333', data: maliciousOpCall }] }),
    );
    expect(resCrit.verdict).toBe('KNOWN_MALICIOUS');
  });

  it('decodes gasless EIP-2612 Permit and catches chainId mismatch', async () => {
    const typedData = JSON.stringify({
      primaryType: 'Permit',
      domain: {
        name: 'USD Coin',
        version: '2',
        chainId: 1, // Mainnet permit requested while wallet is on Sepolia!
        verifyingContract: USDC_MAINNET,
      },
      message: {
        owner: USER_WALLET,
        spender: BENIGN_SPENDER,
        value: maxUint256.toString(),
        nonce: 0,
        deadline: 1900000000,
      },
    });

    const result = await analyzeRequest(
      makeRequest({
        method: 'eth_signTypedData_v4',
        chainIdHex: '0xaa36a7', // Sepolia (11155111)
        params: [USER_WALLET, typedData],
      }),
    );

    expect(result.verdict).toBe('HIGH_RISK');
    expect(result.decoded.kind).toBe('EIP2612_PERMIT');
    expect(result.findings.some((f) => f.id === 'GASLESS_PERMIT_UNLIMITED')).toBe(true);
    expect(result.findings.some((f) => f.id === 'EIP712_CHAIN_MISMATCH')).toBe(true);
  });

  it('decodes Uniswap Permit2 PermitSingle and PermitBatch', async () => {
    const permitSingle = JSON.stringify({
      primaryType: 'PermitSingle',
      domain: {
        name: 'Permit2',
        chainId: 1,
        verifyingContract: PERMIT2_ADDR,
      },
      message: {
        details: {
          token: USDC_MAINNET,
          amount: ((1n << 160n) - 1n).toString(),
          expiration: '1900000000',
          nonce: '0',
        },
        spender: MALICIOUS_SPENDER,
        sigDeadline: '1900000000',
      },
    });

    const result = await analyzeRequest(
      makeRequest({
        method: 'eth_signTypedData_v4',
        params: [USER_WALLET, permitSingle],
      }),
    );

    expect(result.verdict).toBe('KNOWN_MALICIOUS');
    expect(result.decoded.kind).toBe('PERMIT2_SINGLE');
    expect(result.decoded.isUnlimited).toBe(true);
    expect(result.findings.some((f) => f.id === 'PERMIT2_UNLIMITED')).toBe(true);
  });

  it('unwraps nested multicall to catch a hidden unlimited approve', async () => {
    const benignTransfer = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [BENIGN_SPENDER, 10n],
    });
    const hiddenApprove = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [BENIGN_SPENDER, maxUint256],
    });
    const batch = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'multicall',
      args: [[benignTransfer, hiddenApprove]],
    });

    const result = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: USDC_MAINNET, data: batch }],
      }),
    );

    expect(result.verdict).toBe('HIGH_RISK');
    expect(result.decoded.kind).toBe('MULTICALL');
    expect(result.decoded.subActions?.length).toBe(2);
    expect(
      result.findings.some((f) => f.id === 'MULTICALL_HIDDEN_UNLIMITED_APPROVAL'),
    ).toBe(true);
  });

  it('returns honest UNANALYZED verdict for unknown ABI selector or malformed calldata', async () => {
    const unknownCalldata = '0xdeadbeef00000000000000000000000000000000000000000000000000000001';
    const result = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: BENIGN_SPENDER, data: unknownCalldata }],
      }),
    );

    expect(result.verdict).toBe('UNANALYZED');
    expect(result.decoded.kind).toBe('UNKNOWN_CALLDATA');
    expect(result.decoded.selector).toBe('0xdeadbeef');
    expect(result.findings.some((f) => f.id === 'OPAQUE_CALLDATA')).toBe(true);
  });

  it('flags raw eth_sign blind hash signing as CRITICAL / HIGH_RISK', async () => {
    const result = await analyzeRequest(
      makeRequest({
        method: 'eth_sign',
        params: [USER_WALLET, '0x' + 'ab'.repeat(32)],
      }),
    );

    expect(result.verdict).toBe('HIGH_RISK');
    expect(result.findings.some((f) => f.id === 'RAW_ETH_SIGN' && f.severity === 'CRITICAL')).toBe(
      true,
    );
  });

  it('enriches with opt-in RPC (EOA spender + EIP-1967 proxy) and logs every call', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [BENIGN_SPENDER, 500_000_000n],
    });

    const mockFetch: typeof fetch = async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
      let result: unknown = '0x';
      if (body.method === 'eth_getCode') {
        result = '0x'; // Spender is an EOA!
      } else if (body.method === 'eth_getStorageAt') {
        // EIP-1967 implementation address stored in low 20 bytes
        result = '0x0000000000000000000000009999999999999999999999999999999999999999';
      }
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    const result = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: USDC_MAINNET, data }],
      }),
      {
        rpcEnrichmentEnabled: true,
        customRpcUrl: 'https://rpc.example.test',
        fetchImpl: mockFetch,
      },
    );

    expect(result.onChain.spenderIsContract).toBe(false);
    expect(result.onChain.targetIsProxy).toBe(true);
    expect(result.onChain.proxyImplementation).toBe(
      '0x9999999999999999999999999999999999999999',
    );
    expect(result.findings.some((f) => f.id === 'EOA_SPENDER_DETECTED')).toBe(true);
    expect(result.findings.some((f) => f.id === 'EIP1967_PROXY_CONTRACT')).toBe(true);
    expect(result.networkLog.length).toBeGreaterThanOrEqual(4);
    expect(result.networkLog.every((l) => l.target === 'rpc.example.test')).toBe(true);
  });
});
