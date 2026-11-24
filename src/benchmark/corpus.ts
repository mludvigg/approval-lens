import { encodeAbiParameters, encodeFunctionData, maxUint256, parseAbi, toHex, type Address } from 'viem';
import type { AnalyzeOptions } from '../core/analyzer';
import type { InspectionRequest, Verdict } from '../core/types';
import communityDomainsData from '../data/community-domains.json';

export type GroundTruthClass = 'MALICIOUS_OR_DANGEROUS' | 'BENIGN';

export interface BenchmarkFixture {
  id: string;
  category: string;
  name: string;
  groundTruth: GroundTruthClass;
  /** Expected honest Approval Lens verdict(s) for this fixture */
  expectedVerdicts: Verdict[];
  /** True when a benign complex interaction intentionally raises defensive review friction */
  intentionalFriction?: boolean;
  request: InspectionRequest;
  options?: AnalyzeOptions;
}

const ABI = parseAbi([
  'function approve(address spender, uint256 amount)',
  'function approve(address token, address spender, uint160 amount, uint48 expiration)',
  'function increaseAllowance(address spender, uint256 addedValue)',
  'function decreaseAllowance(address spender, uint256 subtractedValue)',
  'function transfer(address to, uint256 amount)',
  'function transferFrom(address from, address to, uint256 amount)',
  'function setApprovalForAll(address operator, bool approved)',
  'function safeTransferFrom(address from, address to, uint256 tokenId)',
  'function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes data)',
  'function multicall(bytes[] data)',
  'function multicall(uint256 deadline, bytes[] data)',
  'function aggregate((address target, bytes callData)[] calls)',
  'function aggregate3((address target, bool allowFailure, bytes callData)[] calls)',
  'function aggregate3Value((address target, bool allowFailure, uint256 value, bytes callData)[] calls)',
  'function stake(uint256 amount, address receiver)',
]);

const OWNER = '0x1111111111111111111111111111111111111111' as Address;
const ROUTER = '0x2222222222222222222222222222222222222222' as Address;
const FRIEND = '0x5555555555555555555555555555555555555555' as Address;
const NFT_COLLECTION = '0x3333333333333333333333333333333333333333' as Address;
const STAKING_VAULT = '0x4444444444444444444444444444444444444444' as Address;

const DRAINER_ERC20 = '0xbad0000000000000000000000000000000000bad' as Address;
const DRAINER_NFT = '0xdeaf00000000000000000000000000000000cafe' as Address;
const BURN_ADDR = '0x000000000000000000000000000000000000dead' as Address;

const USDC_MAINNET = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as Address;
const USDT_MAINNET = '0xdac17f958d2ee523a2206206994597c13d831ec7' as Address;
const WETH_MAINNET = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2' as Address;
const DAI_MAINNET = '0x6b175474e89094c44da98b954eedeac495271d0f' as Address;
const WBTC_MAINNET = '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599' as Address;
const USDC_SEPOLIA = '0x1c7d4b196cb0c7b01d743fbc6116a902379c7238' as Address;
const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3' as Address;
const MULTICALL3 = '0xca11bde05977b3631167028862be2a173976ca11' as Address;
const SEAPORT_1_5 = '0x00000000000000adc04c56bf30ac9d3c0aaf14dc' as Address;
const SEAPORT_1_6 = '0x0000000000000068f116a894984e2db1123eb395' as Address;
const BLUR_EXCHANGE = '0x000000000000ad05ccc4f10045630fb830b95127' as Address;

const MAX_UINT160 = (1n << 160n) - 1n;

function req(
  id: string,
  overrides: Partial<InspectionRequest>,
): InspectionRequest {
  return {
    requestId: id,
    createdAt: '2026-11-24T00:00:00.000Z',
    method: 'eth_sendTransaction',
    params: [],
    payloadHash: 'a'.repeat(64),
    origin: 'https://app.uniswap.org',
    walletName: 'MetaMask',
    chainIdHex: '0x1',
    ...overrides,
  };
}

// Offline deterministic RPC mocks
const mockEoaSpenderFetch: typeof fetch = async (_url, init) => {
  const body = JSON.parse(String(init?.body)) as { method: string };
  const result = body.method === 'eth_getCode' ? '0x' : '0x' + '00'.repeat(32);
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 });
};

const mockBeaconProxyFetch: typeof fetch = async (_url, init) => {
  const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
  let result: unknown = '0x6080604052'; // Contract bytecode (spender is contract)
  if (body.method === 'eth_getStorageAt') {
    const slot = String((body.params as unknown[])[1]);
    result = slot.startsWith('0xa3f0ad')
      ? '0x0000000000000000000000008888888888888888888888888888888888888888'
      : '0x' + '00'.repeat(32);
  } else if (body.method === 'eth_call') {
    result = encodeAbiParameters(
      [{ type: 'address' }],
      ['0x9999999999999999999999999999999999999999'],
    );
  }
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 });
};

const mockSafeContractRpcFetch: typeof fetch = async (_url, init) => {
  const body = JSON.parse(String(init?.body)) as { method: string };
  let result: unknown = '0x' + '00'.repeat(32);
  if (body.method === 'eth_getCode') {
    result = '0x6080604052348015600f57600080fd5b50'; // Non-proxy contract bytecode
  }
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 });
};

const mockMinimalCloneRpcFetch: typeof fetch = async (_url, init) => {
  const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
  let result: unknown = '0x' + '00'.repeat(32);
  if (body.method === 'eth_getCode') {
    const addr = String((body.params as unknown[])[0]).toLowerCase();
    result =
      addr === STAKING_VAULT.toLowerCase()
        ? '0x363d3d373d3d3d363d7377777777777777777777777777777777777777775af43d82803e903d91602b57fd5bf3'
        : '0x6080604052';
  }
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 });
};

const mockSourcifyStakingFetch: typeof fetch = async () =>
  new Response(
    JSON.stringify({
      match: 'exact_match',
      compilation: { name: 'StakingPool' },
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

export function buildBenchmarkCorpus(): BenchmarkFixture[] {
  const communitySample1 = communityDomainsData.domains[0] ?? 'airdrop-uniswap.org';
  const communitySample2 = communityDomainsData.domains[5] ?? 'claim-metamask.io';

  const attackFixtures: BenchmarkFixture[] = [
    // --- A. ERC-20 Token Drainers (6) ---
    {
      id: 'ATK-01',
      category: 'ERC-20 Token Drainers',
      name: 'Unlimited USDC approve(MAX_UINT256) to unknown spender',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-01', {
        params: [
          {
            from: OWNER,
            to: USDC_MAINNET,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'approve',
              args: [ROUTER, maxUint256],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-02',
      category: 'ERC-20 Token Drainers',
      name: 'Unlimited USDC approve to known malicious drainer (0xbad0…0bad)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-02', {
        params: [
          {
            from: OWNER,
            to: USDC_MAINNET,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'approve',
              args: [DRAINER_ERC20, maxUint256],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-03',
      category: 'ERC-20 Token Drainers',
      name: 'Near-unlimited USDT increaseAllowance(2^255)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-03', {
        params: [
          {
            from: OWNER,
            to: USDT_MAINNET,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'increaseAllowance',
              args: [ROUTER, 1n << 255n],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-04',
      category: 'ERC-20 Token Drainers',
      name: 'ERC-20 approve directed to burn address (0x0000…dead)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-04', {
        params: [
          {
            from: OWNER,
            to: DAI_MAINNET,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'approve',
              args: [BURN_ADDR, 100n * 10n ** 18n],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-05',
      category: 'ERC-20 Token Drainers',
      name: 'Capped ERC-20 approve to personal EOA wallet (RPC EOA check)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-05', {
        params: [
          {
            from: OWNER,
            to: USDC_MAINNET,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'approve',
              args: [FRIEND, 500_000_000n],
            }),
          },
        ],
      }),
      options: {
        rpcEnrichmentEnabled: true,
        customRpcUrl: 'https://rpc.benchmark.local',
        fetchImpl: mockEoaSpenderFetch,
      },
    },
    {
      id: 'ATK-06',
      category: 'ERC-20 Token Drainers',
      name: 'On-chain Permit2 approve(token, spender, MAX_UINT160, expiration)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-06', {
        params: [
          {
            from: OWNER,
            to: PERMIT2,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'approve',
              args: [USDC_MAINNET, ROUTER, MAX_UINT160, 1899936000],
            }),
          },
        ],
      }),
    },

    // --- B. NFT Collection & Seaport Drainers (4) ---
    {
      id: 'ATK-07',
      category: 'NFT & Seaport Drainers',
      name: 'ERC-721 setApprovalForAll(true) to known NFT drainer',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-07', {
        params: [
          {
            from: OWNER,
            to: NFT_COLLECTION,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'setApprovalForAll',
              args: [DRAINER_NFT, true],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-08',
      category: 'NFT & Seaport Drainers',
      name: 'ERC-1155 setApprovalForAll(true) to unverified operator',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-08', {
        params: [
          {
            from: OWNER,
            to: NFT_COLLECTION,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'setApprovalForAll',
              args: [ROUTER, true],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-09',
      category: 'NFT & Seaport Drainers',
      name: 'Seaport 1.6 OrderComponents offering 1 NFT for empty consideration',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-09', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'OrderComponents',
            domain: { name: 'Seaport', version: '1.6', chainId: 1, verifyingContract: SEAPORT_1_6 },
            message: {
              offerer: OWNER,
              offer: [{ itemType: 2, token: NFT_COLLECTION, identifierOrCriteria: '1', startAmount: '1', endAmount: '1' }],
              consideration: [],
              endTime: '1899936000',
            },
          }),
        ],
      }),
    },
    {
      id: 'ATK-10',
      category: 'NFT & Seaport Drainers',
      name: 'Seaport 1.5 multi-NFT sweep routing 100% of consideration to drainer',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-10', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'OrderComponents',
            domain: { name: 'Seaport', version: '1.5', chainId: 1, verifyingContract: SEAPORT_1_5 },
            message: {
              offerer: OWNER,
              offer: [
                { itemType: 2, token: NFT_COLLECTION, identifierOrCriteria: '10', startAmount: '1', endAmount: '1' },
                { itemType: 2, token: NFT_COLLECTION, identifierOrCriteria: '11', startAmount: '1', endAmount: '1' },
              ],
              consideration: [
                {
                  itemType: 0,
                  token: '0x0000000000000000000000000000000000000000',
                  identifierOrCriteria: '0',
                  startAmount: '100000',
                  endAmount: '100000',
                  recipient: DRAINER_NFT,
                },
              ],
            },
          }),
        ],
      }),
    },

    // --- C. Blur Marketplace Drains (3) ---
    {
      id: 'ATK-11',
      category: 'Blur Marketplace Drains',
      name: 'Blur Order selling NFT for 0 ETH',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-11', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'Order',
            domain: { name: 'Blur Exchange', version: '1.0', chainId: 1, verifyingContract: BLUR_EXCHANGE },
            message: { trader: OWNER, side: 1, collection: NFT_COLLECTION, tokenId: '4', price: '0' },
          }),
        ],
      }),
    },
    {
      id: 'ATK-12',
      category: 'Blur Marketplace Drains',
      name: 'Blur Order selling NFT for 500 wei dust',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-12', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'Order',
            domain: { name: 'Blur Exchange', version: '1.0', chainId: 1, verifyingContract: BLUR_EXCHANGE },
            message: { trader: OWNER, side: 1, collection: NFT_COLLECTION, tokenId: '5', price: '500' },
          }),
        ],
      }),
    },
    {
      id: 'ATK-13',
      category: 'Blur Marketplace Drains',
      name: 'Blur BulkOrderRoot blind Merkle tree signature',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-13', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'Root',
            domain: { name: 'Blur Exchange', version: '1.0', chainId: 1, verifyingContract: BLUR_EXCHANGE },
            message: { root: '0x' + 'ab'.repeat(32) },
          }),
        ],
      }),
    },

    // --- D. Gasless Permit & Permit2 Drains (6) ---
    {
      id: 'ATK-14',
      category: 'Gasless Permit & Permit2',
      name: 'EIP-2612 Permit unlimited USDC allowance',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-14', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'Permit',
            domain: { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC_MAINNET },
            message: { owner: OWNER, spender: ROUTER, value: maxUint256.toString(), nonce: 0, deadline: 1899936000 },
          }),
        ],
      }),
    },
    {
      id: 'ATK-15',
      category: 'Gasless Permit & Permit2',
      name: 'DAI-style Permit (allowed: true) unlimited approval',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-15', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'Permit',
            domain: { name: 'Dai Stablecoin', version: '1', chainId: 1, verifyingContract: DAI_MAINNET },
            message: { holder: OWNER, spender: ROUTER, allowed: true, nonce: 0, expiry: 1899936000 },
          }),
        ],
      }),
    },
    {
      id: 'ATK-16',
      category: 'Gasless Permit & Permit2',
      name: 'EIP-2612 Permit chainId mismatch (Mainnet signature while on Sepolia)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-16', {
        method: 'eth_signTypedData_v4',
        chainIdHex: '0xaa36a7', // Sepolia
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'Permit',
            domain: { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC_MAINNET },
            message: { owner: OWNER, spender: ROUTER, value: '25000000', nonce: 0, deadline: 1899936000 },
          }),
        ],
      }),
    },
    {
      id: 'ATK-17',
      category: 'Gasless Permit & Permit2',
      name: 'Permit2 PermitSingle unlimited allowance to drainer',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-17', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'PermitSingle',
            domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
            message: {
              details: { token: USDC_MAINNET, amount: MAX_UINT160.toString(), expiration: '1899936000', nonce: '0' },
              spender: DRAINER_ERC20,
              sigDeadline: '1899936000',
            },
          }),
        ],
      }),
    },
    {
      id: 'ATK-18',
      category: 'Gasless Permit & Permit2',
      name: 'Permit2 PermitBatch multi-token sweep (USDC + USDT + WETH)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-18', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'PermitBatch',
            domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
            message: {
              details: [
                { token: USDC_MAINNET, amount: MAX_UINT160.toString(), expiration: '1899936000', nonce: '0' },
                { token: USDT_MAINNET, amount: MAX_UINT160.toString(), expiration: '1899936000', nonce: '0' },
                { token: WETH_MAINNET, amount: MAX_UINT160.toString(), expiration: '1899936000', nonce: '0' },
              ],
              spender: ROUTER,
              sigDeadline: '1899936000',
            },
          }),
        ],
      }),
    },
    {
      id: 'ATK-19',
      category: 'Gasless Permit & Permit2',
      name: 'Permit2 PermitTransferFrom immediate signature sweep',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-19', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'PermitTransferFrom',
            domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
            message: {
              permitted: { token: USDC_MAINNET, amount: '5000000000' },
              spender: ROUTER,
              nonce: '1',
              deadline: '1899936000',
            },
          }),
        ],
      }),
    },

    // --- E. Nested Multicall & Multicall3 Obfuscation (5) ---
    {
      id: 'ATK-20',
      category: 'Multicall Obfuscation',
      name: 'multicall(bytes[]) hiding unlimited ERC-20 approve behind small transfer',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-20', {
        params: [
          {
            from: OWNER,
            to: USDC_MAINNET,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'multicall',
              args: [
                [
                  encodeFunctionData({ abi: ABI, functionName: 'transfer', args: [FRIEND, 1_000_000n] }),
                  encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, maxUint256] }),
                ],
              ],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-21',
      category: 'Multicall Obfuscation',
      name: 'multicall(deadline,bytes[]) hiding NFT setApprovalForAll(true)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-21', {
        params: [
          {
            from: OWNER,
            to: NFT_COLLECTION,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'multicall',
              args: [
                1899936000n,
                [
                  encodeFunctionData({ abi: ABI, functionName: 'safeTransferFrom', args: [OWNER, FRIEND, 1n] }),
                  encodeFunctionData({ abi: ABI, functionName: 'setApprovalForAll', args: [ROUTER, true] }),
                ],
              ],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-22',
      category: 'Multicall Obfuscation',
      name: 'Multicall3.aggregate3 cross-contract hidden drainer approval',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-22', {
        params: [
          {
            from: OWNER,
            to: MULTICALL3,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'aggregate3',
              args: [
                [
                  {
                    target: DAI_MAINNET,
                    allowFailure: false,
                    callData: encodeFunctionData({ abi: ABI, functionName: 'transfer', args: [FRIEND, 10n ** 18n] }),
                  },
                  {
                    target: USDC_MAINNET,
                    allowFailure: false,
                    callData: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [DRAINER_ERC20, maxUint256] }),
                  },
                ],
              ],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-23',
      category: 'Multicall Obfuscation',
      name: 'Multicall3.aggregate3Value mixing ETH payment + unlimited increaseAllowance',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-23', {
        params: [
          {
            from: OWNER,
            to: MULTICALL3,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'aggregate3Value',
              args: [
                [
                  { target: FRIEND, allowFailure: false, value: 10n ** 15n, callData: '0x' },
                  {
                    target: USDT_MAINNET,
                    allowFailure: false,
                    value: 0n,
                    callData: encodeFunctionData({ abi: ABI, functionName: 'increaseAllowance', args: [ROUTER, maxUint256] }),
                  },
                ],
              ],
            }),
          },
        ],
      }),
    },
    {
      id: 'ATK-24',
      category: 'Multicall Obfuscation',
      name: '2-layer nested multicall inside Multicall3.aggregate hiding unlimited approve',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-24', {
        params: [
          {
            from: OWNER,
            to: MULTICALL3,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'aggregate',
              args: [
                [
                  {
                    target: USDC_MAINNET,
                    callData: encodeFunctionData({
                      abi: ABI,
                      functionName: 'multicall',
                      args: [[encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, maxUint256] })]],
                    }),
                  },
                ],
              ],
            }),
          },
        ],
      }),
    },

    // --- F. Phishing Origins, Cross-Origin Iframes & Blind Signing (6) ---
    {
      id: 'ATK-25',
      category: 'Phishing & Blind Signing',
      name: 'Community phishing domain (MetaMask eth-phishing-detect exact match)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-25', {
        origin: `https://${communitySample1}`,
        params: [{ from: OWNER, to: FRIEND, value: '0x0' }],
      }),
    },
    {
      id: 'ATK-26',
      category: 'Phishing & Blind Signing',
      name: 'Subdomain of community phishing domain (claim.<domain>)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-26', {
        origin: `https://claim.${communitySample2}`,
        params: [{ from: OWNER, to: FRIEND, value: '0x0' }],
      }),
    },
    {
      id: 'ATK-27',
      category: 'Phishing & Blind Signing',
      name: 'Curated impersonation phishing origin (uniswap-v4-claim.example)',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['KNOWN_MALICIOUS'],
      request: req('ATK-27', {
        origin: 'https://uniswap-v4-claim.example',
        params: [{ from: OWNER, to: FRIEND, value: '0x0' }],
      }),
    },
    {
      id: 'ATK-28',
      category: 'Phishing & Blind Signing',
      name: 'Cross-origin malicious iframe embedded inside news page',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-28', {
        origin: 'https://widget-drainer.io',
        topLevelOrigin: 'https://crypto-news-portal.org',
        params: [{ from: OWNER, to: FRIEND, value: '0x0' }],
      }),
    },
    {
      id: 'ATK-29',
      category: 'Phishing & Blind Signing',
      name: 'Deprecated raw eth_sign 32-byte blind hash trap',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-29', {
        method: 'eth_sign',
        params: [OWNER, '0x' + 'de'.repeat(32)],
      }),
    },
    {
      id: 'ATK-30',
      category: 'Phishing & Blind Signing',
      name: 'Raw eth_sign arbitrary payload signature trap',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['HIGH_RISK'],
      request: req('ATK-30', {
        method: 'eth_sign',
        params: [OWNER, '0x1234567890abcdef'],
      }),
    },

    // --- G. Adversarial Evasion / Honest Uncertainty Cases (2) ---
    {
      id: 'ATK-31',
      category: 'Adversarial Evasion',
      name: 'Custom unverified selector (0x99887766 — fake claimRewards) refused as UNANALYZED',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['UNANALYZED'],
      request: req('ATK-31', {
        params: [
          {
            from: OWNER,
            to: STAKING_VAULT,
            data: '0x9988776600000000000000000000000000000000000000000000000000000001',
          },
        ],
      }),
    },
    {
      id: 'ATK-32',
      category: 'Adversarial Evasion',
      name: 'Upgradeable EIP-1967 Beacon proxy contract flagged as REVIEW_NEEDED',
      groundTruth: 'MALICIOUS_OR_DANGEROUS',
      expectedVerdicts: ['REVIEW_NEEDED'],
      request: req('ATK-32', {
        params: [
          {
            from: OWNER,
            to: STAKING_VAULT,
            data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 50_000_000n] }),
          },
        ],
      }),
      options: {
        rpcEnrichmentEnabled: true,
        customRpcUrl: 'https://rpc.benchmark.local',
        fetchImpl: mockBeaconProxyFetch,
      },
    },
  ];

  const benignFixtures: BenchmarkFixture[] = [
    // --- H. Safe Capped Approvals & Revokes (10) ---
    {
      id: 'BEN-01',
      category: 'Capped Approvals & Revokes',
      name: 'Capped 50 USDC approve on Mainnet',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-01', {
        params: [{ from: OWNER, to: USDC_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 50_000_000n] }) }],
      }),
    },
    {
      id: 'BEN-02',
      category: 'Capped Approvals & Revokes',
      name: 'Capped 250 USDT approve on Mainnet',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-02', {
        params: [{ from: OWNER, to: USDT_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 250_000_000n] }) }],
      }),
    },
    {
      id: 'BEN-03',
      category: 'Capped Approvals & Revokes',
      name: 'Capped 1.5 WETH approve on Mainnet',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-03', {
        params: [{ from: OWNER, to: WETH_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 15n * 10n ** 17n] }) }],
      }),
    },
    {
      id: 'BEN-04',
      category: 'Capped Approvals & Revokes',
      name: 'Capped 1,000 DAI approve on Mainnet',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-04', {
        params: [{ from: OWNER, to: DAI_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 1000n * 10n ** 18n] }) }],
      }),
    },
    {
      id: 'BEN-05',
      category: 'Capped Approvals & Revokes',
      name: 'Capped 0.25 WBTC approve on Mainnet',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-05', {
        params: [{ from: OWNER, to: WBTC_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 25_000_000n] }) }],
      }),
    },
    {
      id: 'BEN-06',
      category: 'Capped Approvals & Revokes',
      name: 'Capped 100 USDC approve on Sepolia Testnet',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-06', {
        chainIdHex: '0xaa36a7',
        params: [{ from: OWNER, to: USDC_SEPOLIA, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 100_000_000n] }) }],
      }),
    },
    {
      id: 'BEN-07',
      category: 'Capped Approvals & Revokes',
      name: 'Revoke USDC allowance via approve(spender, 0)',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-07', {
        params: [{ from: OWNER, to: USDC_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 0n] }) }],
      }),
    },
    {
      id: 'BEN-08',
      category: 'Capped Approvals & Revokes',
      name: 'Revoke WETH allowance via approve(spender, 0)',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-08', {
        params: [{ from: OWNER, to: WETH_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 0n] }) }],
      }),
    },
    {
      id: 'BEN-09',
      category: 'Capped Approvals & Revokes',
      name: 'ERC-20 decreaseAllowance by 50 USDC',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-09', {
        params: [{ from: OWNER, to: USDC_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'decreaseAllowance', args: [ROUTER, 50_000_000n] }) }],
      }),
    },
    {
      id: 'BEN-10',
      category: 'Capped Approvals & Revokes',
      name: 'Capped ERC-20 increaseAllowance by 25 DAI',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-10', {
        params: [{ from: OWNER, to: DAI_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'increaseAllowance', args: [ROUTER, 25n * 10n ** 18n] }) }],
      }),
    },

    // --- I. NFT Revokes & Direct Asset Transfers (8) ---
    {
      id: 'BEN-11',
      category: 'NFT Revokes & Direct Transfers',
      name: 'Revoke NFT collection operator setApprovalForAll(operator, false)',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-11', {
        params: [{ from: OWNER, to: NFT_COLLECTION, data: encodeFunctionData({ abi: ABI, functionName: 'setApprovalForAll', args: [ROUTER, false] }) }],
      }),
    },
    {
      id: 'BEN-12',
      category: 'NFT Revokes & Direct Transfers',
      name: 'Direct ERC-20 transfer of 20 USDC',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-12', {
        params: [{ from: OWNER, to: USDC_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'transfer', args: [FRIEND, 20_000_000n] }) }],
      }),
    },
    {
      id: 'BEN-13',
      category: 'NFT Revokes & Direct Transfers',
      name: 'Direct ERC-20 transferFrom of 10 DAI',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-13', {
        params: [{ from: OWNER, to: DAI_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'transferFrom', args: [OWNER, FRIEND, 10n * 10n ** 18n] }) }],
      }),
    },
    {
      id: 'BEN-14',
      category: 'NFT Revokes & Direct Transfers',
      name: 'Direct ERC-721 safeTransferFrom(from, to, tokenId)',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-14', {
        params: [{ from: OWNER, to: NFT_COLLECTION, data: encodeFunctionData({ abi: ABI, functionName: 'safeTransferFrom', args: [OWNER, FRIEND, 42n] }) }],
      }),
    },
    {
      id: 'BEN-15',
      category: 'NFT Revokes & Direct Transfers',
      name: 'Direct ERC-1155 safeTransferFrom(from, to, id, value, data)',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-15', {
        params: [{ from: OWNER, to: NFT_COLLECTION, data: encodeFunctionData({ abi: ABI, functionName: 'safeTransferFrom', args: [OWNER, FRIEND, 7n, 1n, '0x'] }) }],
      }),
    },
    {
      id: 'BEN-16',
      category: 'NFT Revokes & Direct Transfers',
      name: 'Native ETH transfer of 0.05 ETH',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-16', {
        params: [{ from: OWNER, to: FRIEND, value: toHex(5n * 10n ** 16n) }],
      }),
    },
    {
      id: 'BEN-17',
      category: 'NFT Revokes & Direct Transfers',
      name: 'Native ETH transfer of 1.0 ETH to WETH contract',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-17', {
        params: [{ from: OWNER, to: WETH_MAINNET, value: toHex(10n ** 18n) }],
      }),
    },
    {
      id: 'BEN-18',
      category: 'NFT Revokes & Direct Transfers',
      name: 'Capped on-chain Permit2 approve(USDC, router, 100 USDC, expiry)',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-18', {
        params: [{ from: OWNER, to: PERMIT2, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [USDC_MAINNET, ROUTER, 100_000_000n, 1899936000] }) }],
      }),
    },

    // --- J. Benign Batches, SIWE Logins & RPC-Verified Contracts (8) ---
    {
      id: 'BEN-19',
      category: 'Benign Batches & SIWE Logins',
      name: 'multicall(bytes[]) bundling transfer + allowance revoke',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-19', {
        params: [
          {
            from: OWNER,
            to: USDC_MAINNET,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'multicall',
              args: [
                [
                  encodeFunctionData({ abi: ABI, functionName: 'transfer', args: [FRIEND, 5_000_000n] }),
                  encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 0n] }),
                ],
              ],
            }),
          },
        ],
      }),
    },
    {
      id: 'BEN-20',
      category: 'Benign Batches & SIWE Logins',
      name: 'Multicall3.aggregate3 bundling two safe token transfers',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-20', {
        params: [
          {
            from: OWNER,
            to: MULTICALL3,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'aggregate3',
              args: [
                [
                  { target: USDC_MAINNET, allowFailure: false, callData: encodeFunctionData({ abi: ABI, functionName: 'transfer', args: [FRIEND, 10_000_000n] }) },
                  { target: DAI_MAINNET, allowFailure: false, callData: encodeFunctionData({ abi: ABI, functionName: 'transfer', args: [FRIEND, 10n * 10n ** 18n] }) },
                ],
              ],
            }),
          },
        ],
      }),
    },
    {
      id: 'BEN-21',
      category: 'Benign Batches & SIWE Logins',
      name: 'Multicall3.aggregate3Value sending ETH + capped 50 USDC approve',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-21', {
        params: [
          {
            from: OWNER,
            to: MULTICALL3,
            data: encodeFunctionData({
              abi: ABI,
              functionName: 'aggregate3Value',
              args: [
                [
                  { target: FRIEND, allowFailure: false, value: 10n ** 15n, callData: '0x' },
                  { target: USDC_MAINNET, allowFailure: false, value: 0n, callData: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 50_000_000n] }) },
                ],
              ],
            }),
          },
        ],
      }),
    },
    {
      id: 'BEN-22',
      category: 'Benign Batches & SIWE Logins',
      name: 'Standard Sign-In with Ethereum (SIWE) personal_sign message',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-22', {
        method: 'personal_sign',
        params: [
          toHex('app.uniswap.org wants you to sign in with your Ethereum account:\n0x1111111111111111111111111111111111111111\n\nNonce: 928374'),
          OWNER,
        ],
      }),
    },
    {
      id: 'BEN-23',
      category: 'Benign Batches & SIWE Logins',
      name: 'Plain-text wallet ownership login via personal_sign',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-23', {
        method: 'personal_sign',
        params: ['Verify wallet ownership for session #4821', OWNER],
      }),
    },
    {
      id: 'BEN-24',
      category: 'Benign Batches & SIWE Logins',
      name: 'Readable off-chain governance snapshot vote via personal_sign',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-24', {
        method: 'personal_sign',
        params: [toHex('Snapshot Governance Vote: Proposal #14 — Choice: FOR'), OWNER],
      }),
    },
    {
      id: 'BEN-25',
      category: 'Benign Batches & SIWE Logins',
      name: 'Capped USDC approve verified via RPC (contract spender, non-proxy)',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-25', {
        params: [{ from: OWNER, to: USDC_MAINNET, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 75_000_000n] }) }],
      }),
      options: {
        rpcEnrichmentEnabled: true,
        customRpcUrl: 'https://rpc.benchmark.local',
        fetchImpl: mockSafeContractRpcFetch,
      },
    },
    {
      id: 'BEN-26',
      category: 'Benign Batches & SIWE Logins',
      name: 'Capped approve on EIP-1167 minimal clone contract (INFO clone note)',
      groundTruth: 'BENIGN',
      expectedVerdicts: ['UNDERSTOOD'],
      request: req('BEN-26', {
        params: [{ from: OWNER, to: STAKING_VAULT, data: encodeFunctionData({ abi: ABI, functionName: 'approve', args: [ROUTER, 25_000_000n] }) }],
      }),
      options: {
        rpcEnrichmentEnabled: true,
        customRpcUrl: 'https://rpc.benchmark.local',
        fetchImpl: mockMinimalCloneRpcFetch,
      },
    },

    // --- K. Complex Legitimate Protocol Actions (6 — Intentional Defensive Friction) ---
    {
      id: 'BEN-27',
      category: 'Complex Protocol Actions (Defensive Friction)',
      name: 'Paid Seaport NFT listing returning 1.5 ETH to offerer',
      groundTruth: 'BENIGN',
      intentionalFriction: true,
      expectedVerdicts: ['HIGH_RISK'],
      request: req('BEN-27', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'OrderComponents',
            domain: { name: 'Seaport', version: '1.6', chainId: 1, verifyingContract: SEAPORT_1_6 },
            message: {
              offerer: OWNER,
              offer: [{ itemType: 2, token: NFT_COLLECTION, identifierOrCriteria: '88', startAmount: '1', endAmount: '1' }],
              consideration: [
                {
                  itemType: 0,
                  token: '0x0000000000000000000000000000000000000000',
                  identifierOrCriteria: '0',
                  startAmount: (15n * 10n ** 17n).toString(),
                  endAmount: (15n * 10n ** 17n).toString(),
                  recipient: OWNER,
                },
              ],
            },
          }),
        ],
      }),
    },
    {
      id: 'BEN-28',
      category: 'Complex Protocol Actions (Defensive Friction)',
      name: 'Capped EIP-2612 Permit (50 USDC on matching chain)',
      groundTruth: 'BENIGN',
      intentionalFriction: true,
      expectedVerdicts: ['REVIEW_NEEDED'],
      request: req('BEN-28', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'Permit',
            domain: { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC_MAINNET },
            message: { owner: OWNER, spender: ROUTER, value: '50000000', nonce: 1, deadline: 1899936000 },
          }),
        ],
      }),
    },
    {
      id: 'BEN-29',
      category: 'Complex Protocol Actions (Defensive Friction)',
      name: 'Capped Permit2 PermitSingle (25 USDC on matching chain)',
      groundTruth: 'BENIGN',
      intentionalFriction: true,
      expectedVerdicts: ['HIGH_RISK'],
      request: req('BEN-29', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'PermitSingle',
            domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
            message: {
              details: { token: USDC_MAINNET, amount: '25000000', expiration: '1899936000', nonce: '0' },
              spender: ROUTER,
              sigDeadline: '1899936000',
            },
          }),
        ],
      }),
    },
    {
      id: 'BEN-30',
      category: 'Complex Protocol Actions (Defensive Friction)',
      name: 'Sourcify-verified custom stake(uint256,address) call',
      groundTruth: 'BENIGN',
      intentionalFriction: true,
      expectedVerdicts: ['REVIEW_NEEDED'],
      request: req('BEN-30', {
        params: [
          {
            from: OWNER,
            to: STAKING_VAULT,
            data: encodeFunctionData({ abi: ABI, functionName: 'stake', args: [100_000_000n, OWNER] }),
          },
        ],
      }),
      options: {
        abiLookupEnabled: true,
        fetchImpl: mockSourcifyStakingFetch,
      },
    },
    {
      id: 'BEN-31',
      category: 'Complex Protocol Actions (Defensive Friction)',
      name: 'Custom DEX router selector in local-only mode (honest UNANALYZED)',
      groundTruth: 'BENIGN',
      intentionalFriction: true,
      expectedVerdicts: ['UNANALYZED'],
      request: req('BEN-31', {
        params: [{ from: OWNER, to: ROUTER, data: '0x12aa3caf00000000000000000000000000000000000000000000000000000064' }],
      }),
    },
    {
      id: 'BEN-32',
      category: 'Complex Protocol Actions (Defensive Friction)',
      name: 'Custom DAO ballot EIP-712 typed data (honest UNANALYZED)',
      groundTruth: 'BENIGN',
      intentionalFriction: true,
      expectedVerdicts: ['UNANALYZED'],
      request: req('BEN-32', {
        method: 'eth_signTypedData_v4',
        params: [
          OWNER,
          JSON.stringify({
            primaryType: 'Ballot',
            domain: { name: 'GovernorBravo', version: '1', chainId: 1, verifyingContract: STAKING_VAULT },
            message: { proposalId: '42', support: 1 },
          }),
        ],
      }),
    },
  ];

  return [...attackFixtures, ...benignFixtures];
}
