import { describe, expect, it } from 'vitest';
import { encodeAbiParameters, encodeFunctionData, maxUint256, parseAbi, type Address } from 'viem';
import type { CachedAbiEntry } from '../src/core/abiLookup';
import { analyzeRequest } from '../src/core/analyzer';
import { buildPlainEnglishSummary } from '../src/core/format';
import { getCommunityFeedMetadata } from '../src/core/reputation';
import { parseEip1167Implementation } from '../src/core/rpc';
import type { InspectionRequest } from '../src/core/types';
import communityDomainsData from '../src/data/community-domains.json';

const ERC20_ABI = parseAbi([
  'function approve(address spender, uint256 amount)',
  'function transfer(address to, uint256 amount)',
]);

const MULTICALL3_ABI = parseAbi([
  'function aggregate3((address target, bool allowFailure, bytes callData)[] calls)',
  'function aggregate3Value((address target, bool allowFailure, uint256 value, bytes callData)[] calls)',
]);

const CUSTOM_STAKING_ABI = parseAbi([
  'function stake(uint256 amount, address receiver)',
]);

const USER_WALLET = '0x1111111111111111111111111111111111111111' as Address;
const USDC_MAINNET = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as Address;
const MULTICALL3_ADDR = '0xca11bde05977b3631167028862be2a173976ca11' as Address;
const SEAPORT_1_6 = '0x0000000000000068f116a894984e2db1123eb395' as Address;
const BENIGN_SPENDER = '0x2222222222222222222222222222222222222222' as Address;
const MALICIOUS_SPENDER = '0xbad0000000000000000000000000000000000bad' as Address;
const CUSTOM_CONTRACT = '0x4444444444444444444444444444444444444444' as Address;

function makeRequest(overrides: Partial<InspectionRequest>): InspectionRequest {
  return {
    requestId: 'test-v2-req-001',
    createdAt: '2026-11-24T00:00:00.000Z',
    method: 'eth_sendTransaction',
    params: [],
    payloadHash: '0'.repeat(64),
    origin: 'https://app.example.org',
    walletName: 'MetaMask',
    chainIdHex: '0x1',
    ...overrides,
  };
}

describe('Approval Lens v0.2.0 — Real-World DeFi Decoders, Proxies & Sourcify', () => {
  it('unpacks Multicall3.aggregate3 across multiple target contracts and catches hidden malicious approvals', async () => {
    const safeTransfer = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [BENIGN_SPENDER, 1_000_000n],
    });
    const hiddenApprove = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [MALICIOUS_SPENDER, maxUint256],
    });

    const data = encodeFunctionData({
      abi: MULTICALL3_ABI,
      functionName: 'aggregate3',
      args: [
        [
          { target: USDC_MAINNET, allowFailure: false, callData: safeTransfer },
          { target: USDC_MAINNET, allowFailure: false, callData: hiddenApprove },
        ],
      ],
    });

    const result = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: MULTICALL3_ADDR, data }],
      }),
    );

    expect(result.verdict).toBe('KNOWN_MALICIOUS');
    expect(result.decoded.kind).toBe('MULTICALL');
    expect(result.decoded.functionName).toBe('Multicall3.aggregate3');
    expect(result.decoded.subActions).toHaveLength(2);
    expect(result.decoded.subActions?.[1].targetContract?.toLowerCase()).toBe(USDC_MAINNET);
    expect(result.decoded.subActions?.[1].spender?.toLowerCase()).toBe(MALICIOUS_SPENDER);
    expect(result.findings.some((f) => f.id === 'MULTICALL_HIDDEN_UNLIMITED_APPROVAL')).toBe(
      true,
    );
    expect(result.findings.some((f) => f.id === 'KNOWN_MALICIOUS_ADDRESS')).toBe(true);
  });

  it('flags Seaport zero-consideration NFT drain as CRITICAL while distinguishing normal paid sales', async () => {
    const zeroDrainPayload = JSON.stringify({
      primaryType: 'OrderComponents',
      domain: {
        name: 'Seaport',
        version: '1.6',
        chainId: 1,
        verifyingContract: SEAPORT_1_6,
      },
      message: {
        offerer: USER_WALLET,
        offer: [
          {
            itemType: 2,
            token: '0x3333333333333333333333333333333333333333',
            identifierOrCriteria: '99',
            startAmount: '1',
            endAmount: '1',
          },
        ],
        consideration: [
          {
            itemType: 0,
            token: '0x0000000000000000000000000000000000000000',
            identifierOrCriteria: '0',
            startAmount: '1000000000000000',
            endAmount: '1000000000000000',
            recipient: BENIGN_SPENDER, // Attacker gets ETH, offerer gets 0!
          },
        ],
        endTime: '1899936000',
      },
    });

    const drainRes = await analyzeRequest(
      makeRequest({
        method: 'eth_signTypedData_v4',
        params: [USER_WALLET, zeroDrainPayload],
      }),
    );

    expect(drainRes.verdict).toBe('HIGH_RISK');
    expect(drainRes.decoded.seaportDetails?.zeroConsiderationToOfferer).toBe(true);
    expect(
      drainRes.findings.some(
        (f) => f.id === 'SEAPORT_ZERO_CONSIDERATION_DRAIN' && f.severity === 'CRITICAL',
      ),
    ).toBe(true);
    expect(buildPlainEnglishSummary(drainRes)).toContain('DANGER');

    // Legitimate sale paying 1 ETH back to USER_WALLET
    const paidSalePayload = JSON.stringify({
      primaryType: 'OrderComponents',
      domain: {
        name: 'Seaport',
        version: '1.6',
        chainId: 1,
        verifyingContract: SEAPORT_1_6,
      },
      message: {
        offerer: USER_WALLET,
        offer: [
          {
            itemType: 2,
            token: '0x3333333333333333333333333333333333333333',
            identifierOrCriteria: '99',
            startAmount: '1',
            endAmount: '1',
          },
        ],
        consideration: [
          {
            itemType: 0,
            token: '0x0000000000000000000000000000000000000000',
            identifierOrCriteria: '0',
            startAmount: '1000000000000000000', // 1 ETH to offerer
            endAmount: '1000000000000000000',
            recipient: USER_WALLET,
          },
        ],
      },
    });

    const paidRes = await analyzeRequest(
      makeRequest({
        method: 'eth_signTypedData_v4',
        params: [USER_WALLET, paidSalePayload],
      }),
    );

    expect(paidRes.decoded.seaportDetails?.zeroConsiderationToOfferer).toBe(false);
    expect(paidRes.findings.some((f) => f.id === 'SEAPORT_ZERO_CONSIDERATION_DRAIN')).toBe(
      false,
    );
    expect(paidRes.findings.some((f) => f.id === 'SEAPORT_ORDER_SIGNATURE')).toBe(true);
  });

  it('detects Blur zero-price sell drain as CRITICAL and Blur BulkOrderRoot as HIGH', async () => {
    const blurZeroSell = JSON.stringify({
      primaryType: 'Order',
      domain: {
        name: 'Blur Exchange',
        version: '1.0',
        chainId: 1,
        verifyingContract: '0x000000000000ad05ccc4f10045630fb830b95127',
      },
      message: {
        trader: USER_WALLET,
        side: 1, // Sell
        collection: '0x3333333333333333333333333333333333333333',
        tokenId: '7',
        amount: '1',
        paymentToken: '0x0000000000000000000000000000000000000000',
        price: '0',
        expirationTime: '1899936000',
      },
    });

    const zeroRes = await analyzeRequest(
      makeRequest({
        method: 'eth_signTypedData_v4',
        params: [USER_WALLET, blurZeroSell],
      }),
    );

    expect(zeroRes.decoded.kind).toBe('BLUR_ORDER');
    expect(
      zeroRes.findings.some((f) => f.id === 'BLUR_ZERO_PRICE_DRAIN' && f.severity === 'CRITICAL'),
    ).toBe(true);

    const blurRoot = JSON.stringify({
      primaryType: 'Root',
      domain: {
        name: 'Blur Exchange',
        version: '1.0',
        chainId: 1,
        verifyingContract: '0x000000000000ad05ccc4f10045630fb830b95127',
      },
      message: {
        root: '0x' + 'cd'.repeat(32),
      },
    });

    const rootRes = await analyzeRequest(
      makeRequest({
        method: 'eth_signTypedData_v4',
        params: [USER_WALLET, blurRoot],
      }),
    );

    expect(rootRes.findings.some((f) => f.id === 'BLUR_BULK_ROOT_SIGNATURE')).toBe(true);
  });

  it('detects EIP-1167 minimal proxy clones and EIP-1967 Beacon proxies via opt-in RPC', async () => {
    const implAddr = '0x7777777777777777777777777777777777777777';
    const cloneBytecode = `0x363d3d373d3d3d363d73${implAddr.slice(2)}5af43d82803e903d91602b57fd5bf3`;
    expect(parseEip1167Implementation(cloneBytecode)).toBe(implAddr);

    const approveData = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [BENIGN_SPENDER, 10_000_000n],
    });

    // Test EIP-1967 Beacon Proxy resolution
    const beaconAddr = '0x8888888888888888888888888888888888888888';
    const beaconImplAddr = '0x9999999999999999999999999999999999999999';

    const mockBeaconFetch: typeof fetch = async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
      let result: unknown = '0x';

      if (body.method === 'eth_getStorageAt') {
        const slot = String((body.params as unknown[])[1]);
        if (slot.startsWith('0x360894')) {
          result = '0x' + '00'.repeat(32); // No direct impl slot
        } else if (slot.startsWith('0xa3f0ad')) {
          result = `0x000000000000000000000000${beaconAddr.slice(2)}`;
        }
      } else if (body.method === 'eth_getCode') {
        result = '0x6080604052'; // Regular contract bytecode (not EIP-1167)
      } else if (body.method === 'eth_call') {
        const callObj = (body.params as Array<{ to?: string; data?: string }>)[0];
        if (callObj?.to?.toLowerCase() === beaconAddr) {
          result = encodeAbiParameters([{ type: 'address' }], [beaconImplAddr]);
        }
      }

      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    const res = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: CUSTOM_CONTRACT, data: approveData }],
      }),
      {
        rpcEnrichmentEnabled: true,
        customRpcUrl: 'https://rpc.example.test',
        fetchImpl: mockBeaconFetch,
      },
    );

    expect(res.onChain.targetIsProxy).toBe(true);
    expect(res.onChain.proxyKind).toBe('EIP1967_BEACON');
    expect(res.onChain.beaconAddress).toBe(beaconAddr);
    expect(res.onChain.proxyImplementation).toBe(beaconImplAddr);
    expect(res.findings.some((f) => f.id === 'EIP1967_BEACON_PROXY')).toBe(true);
  });

  it('keeps 0 network calls when abiLookupEnabled is false, decodes via Sourcify v2 when enabled, and falls back honestly to 4byte', async () => {
    const customCall = encodeFunctionData({
      abi: CUSTOM_STAKING_ABI,
      functionName: 'stake',
      args: [250_000_000n, USER_WALLET],
    });

    let fetchCalls = 0;
    const countingFetch: typeof fetch = async () => {
      fetchCalls += 1;
      throw new Error('Should not be called when disabled');
    };

    // 1. Disabled by default -> 0 fetch calls
    const localRes = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: CUSTOM_CONTRACT, data: customCall }],
      }),
      {
        abiLookupEnabled: false,
        fetchImpl: countingFetch,
      },
    );
    expect(fetchCalls).toBe(0);
    expect(localRes.verdict).toBe('UNANALYZED');

    // 2. Enabled with Sourcify v2 verified ABI + session cache
    let sourcifyNetworkHits = 0;
    const abiCache = new Map<string, CachedAbiEntry | string | null>();
    const mockSourcifyFetch: typeof fetch = async (input) => {
      sourcifyNetworkHits += 1;
      const url = String(input);
      if (url.includes('sourcify.dev/server/v2/contract/')) {
        return new Response(
          JSON.stringify({
            match: 'exact_match',
            compilation: { name: 'StakingVault' },
            abi: [
              {
                type: 'function',
                name: 'stake',
                stateMutability: 'nonpayable',
                inputs: [
                  { name: 'amount', type: 'uint256' },
                  { name: 'receiver', type: 'address' },
                ],
                outputs: [],
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('Not found', { status: 404 });
    };

    const verifiedRes = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: CUSTOM_CONTRACT, data: customCall }],
      }),
      {
        abiLookupEnabled: true,
        fetchImpl: mockSourcifyFetch,
        abiCache,
      },
    );

    expect(sourcifyNetworkHits).toBe(1);
    expect(verifiedRes.verdict).toBe('REVIEW_NEEDED'); // Honest: decoded ABI != audited safety!
    expect(verifiedRes.decoded.kind).toBe('SOURCIFY_DECODED');
    expect(verifiedRes.decoded.functionName).toBe('stake(uint256,address)');
    expect(verifiedRes.decoded.contractName).toBe('StakingVault');
    expect(verifiedRes.decoded.decodedArgs).toEqual([
      { name: 'amount', type: 'uint256', value: '250000000' },
      { name: 'receiver', type: 'address', value: USER_WALLET },
    ]);
    // Ensure JSON serialization succeeds (no raw bigint anywhere in InspectionResult)
    expect(() => JSON.stringify(verifiedRes)).not.toThrow();

    // Second call hits session cache with 0 additional HTTP requests
    await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: CUSTOM_CONTRACT, data: customCall }],
      }),
      {
        abiLookupEnabled: true,
        fetchImpl: mockSourcifyFetch,
        abiCache,
      },
    );
    expect(sourcifyNetworkHits).toBe(1);

    // 3. Sourcify 404 -> 4byte unverified fallback stays UNANALYZED with collision warning
    const mock4ByteFetch: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes('sourcify.dev/server/v2/contract/')) {
        return new Response('Not verified', { status: 404 });
      }
      if (url.includes('api.4byte.sourcify.dev')) {
        const sel = customCall.slice(0, 10).toLowerCase();
        return new Response(
          JSON.stringify({
            ok: true,
            result: {
              function: {
                [sel]: [{ name: 'stake(uint256,address)', filtered: false }],
              },
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('Not found', { status: 404 });
    };

    const fourByteRes = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: CUSTOM_CONTRACT, data: customCall }],
      }),
      {
        abiLookupEnabled: true,
        fetchImpl: mock4ByteFetch,
      },
    );

    expect(fourByteRes.verdict).toBe('UNANALYZED');
    expect(fourByteRes.decoded.abiSource).toBe('fourbyte_unverified');
    expect(fourByteRes.findings.some((f) => f.id === 'FOURBYTE_UNVERIFIED_GUESS')).toBe(true);
  });

  it('flags origins in the offline MetaMask eth-phishing-detect snapshot (exact + subdomain)', async () => {
    const meta = getCommunityFeedMetadata();
    expect(meta.source).toBe('MetaMask/eth-phishing-detect');
    expect(meta.license).toBe('DBADPL-1.2');
    expect(meta.count).toBeGreaterThan(0);

    const samplePhishingDomain = communityDomainsData.domains[0];
    const res = await analyzeRequest(
      makeRequest({
        origin: `https://claim.${samplePhishingDomain}`,
        params: [{ from: USER_WALLET, to: BENIGN_SPENDER, value: '0x0' }],
      }),
    );

    expect(res.verdict).toBe('KNOWN_MALICIOUS');
    expect(res.findings.some((f) => f.id === 'KNOWN_MALICIOUS_ORIGIN')).toBe(true);
  });
});
