import {
  decodeFunctionResult,
  encodeFunctionData,
  parseAbi,
  type Address,
  type Hex,
} from 'viem';
import type { NetworkLogEntry, OnChainContext } from './types';

// EIP-1967 logic implementation slot: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
const EIP1967_IMPL_SLOT =
  '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

const DEFAULT_PUBLIC_RPCS: Record<number, string> = {
  1: 'https://ethereum-rpc.publicnode.com',
  11155111: 'https://ethereum-sepolia-rpc.publicnode.com',
  8453: 'https://base-rpc.publicnode.com',
  42161: 'https://arbitrum-one-rpc.publicnode.com',
  137: 'https://polygon-bor-rpc.publicnode.com',
  10: 'https://optimism-rpc.publicnode.com',
};

const ERC20_READ_ABI = parseAbi([
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function allowance(address owner, address spender) view returns (uint256)',
]);

export interface RpcEnrichParams {
  rpcEnabled: boolean;
  customRpcUrl?: string;
  chainId?: number;
  tokenAddress?: string;
  targetContract?: string;
  owner?: string;
  spender?: string;
  fetchImpl?: typeof fetch;
}

function isValidAddress(addr?: string): addr is Address {
  return typeof addr === 'string' && /^0x[0-9a-fA-F]{40}$/.test(addr);
}

function resolveRpcUrl(chainId?: number, customRpcUrl?: string): string | null {
  if (customRpcUrl && customRpcUrl.trim().startsWith('http')) {
    return customRpcUrl.trim();
  }
  if (chainId && DEFAULT_PUBLIC_RPCS[chainId]) {
    return DEFAULT_PUBLIC_RPCS[chainId];
  }
  return null;
}

async function rpcCall(
  rpcUrl: string,
  method: string,
  params: unknown[],
  purpose: string,
  networkLog: NetworkLogEntry[],
  fetchImpl: typeof fetch,
): Promise<unknown> {
  const timestamp = new Date().toISOString();
  const host = (() => {
    try {
      return new URL(rpcUrl).host;
    } catch {
      return rpcUrl;
    }
  })();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3500);

  try {
    const res = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: controller.signal,
    });
    if (!res.ok) {
      networkLog.push({
        timestamp,
        target: host,
        purpose,
        status: 'error',
        detail: `HTTP ${res.status}`,
      });
      return null;
    }
    const json = (await res.json()) as { result?: unknown; error?: { message?: string } };
    if (json.error) {
      networkLog.push({
        timestamp,
        target: host,
        purpose,
        status: 'error',
        detail: json.error.message ?? 'RPC error',
      });
      return null;
    }
    networkLog.push({ timestamp, target: host, purpose, status: 'ok' });
    return json.result ?? null;
  } catch (err) {
    networkLog.push({
      timestamp,
      target: host,
      purpose,
      status: 'error',
      detail: err instanceof Error ? err.message : 'Network error',
    });
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchOnChainContext(
  params: RpcEnrichParams,
): Promise<{ onChain: OnChainContext; networkLog: NetworkLogEntry[] }> {
  const networkLog: NetworkLogEntry[] = [];
  const onChain: OnChainContext = {
    rpcEnabled: params.rpcEnabled,
    chainId: params.chainId,
  };

  if (!params.rpcEnabled) {
    networkLog.push({
      timestamp: new Date().toISOString(),
      target: 'local-only',
      purpose: 'On-chain RPC enrichment disabled by user settings (0 bytes sent externally)',
      status: 'skipped',
    });
    return { onChain, networkLog };
  }

  const rpcUrl = resolveRpcUrl(params.chainId, params.customRpcUrl);
  if (!rpcUrl) {
    networkLog.push({
      timestamp: new Date().toISOString(),
      target: 'none',
      purpose: `No RPC endpoint configured for chainId ${params.chainId ?? 'unknown'}`,
      status: 'skipped',
    });
    return { onChain, networkLog };
  }

  const fetchImpl = params.fetchImpl ?? fetch;
  const tasks: Promise<void>[] = [];

  // 1. Token symbol & decimals
  if (isValidAddress(params.tokenAddress)) {
    const token = params.tokenAddress;

    tasks.push(
      (async () => {
        const data = encodeFunctionData({ abi: ERC20_READ_ABI, functionName: 'symbol' });
        const raw = await rpcCall(
          rpcUrl,
          'eth_call',
          [{ to: token, data }, 'latest'],
          'Read ERC-20 token symbol()',
          networkLog,
          fetchImpl,
        );
        if (typeof raw === 'string' && raw.length > 2) {
          try {
            const sym = decodeFunctionResult({
              abi: ERC20_READ_ABI,
              functionName: 'symbol',
              data: raw as Hex,
            });
            if (typeof sym === 'string' && sym.trim()) {
              onChain.tokenSymbol = sym.trim().slice(0, 24);
            }
          } catch {
            // Non-standard bytes32 symbol; ignore safely
          }
        }
      })(),
    );

    tasks.push(
      (async () => {
        const data = encodeFunctionData({ abi: ERC20_READ_ABI, functionName: 'decimals' });
        const raw = await rpcCall(
          rpcUrl,
          'eth_call',
          [{ to: token, data }, 'latest'],
          'Read ERC-20 token decimals()',
          networkLog,
          fetchImpl,
        );
        if (typeof raw === 'string' && raw.length > 2) {
          try {
            const dec = decodeFunctionResult({
              abi: ERC20_READ_ABI,
              functionName: 'decimals',
              data: raw as Hex,
            });
            const num = Number(dec);
            if (Number.isInteger(num) && num >= 0 && num <= 36) {
              onChain.tokenDecimals = num;
            }
          } catch {
            // Ignore
          }
        }
      })(),
    );

    // 2. Current allowance (before -> after comparison)
    if (isValidAddress(params.owner) && isValidAddress(params.spender)) {
      const owner = params.owner;
      const spender = params.spender;
      tasks.push(
        (async () => {
          const data = encodeFunctionData({
            abi: ERC20_READ_ABI,
            functionName: 'allowance',
            args: [owner, spender],
          });
          const raw = await rpcCall(
            rpcUrl,
            'eth_call',
            [{ to: token, data }, 'latest'],
            'Read current ERC-20 allowance(owner, spender)',
            networkLog,
            fetchImpl,
          );
          if (typeof raw === 'string' && raw.length > 2) {
            try {
              const allowance = decodeFunctionResult({
                abi: ERC20_READ_ABI,
                functionName: 'allowance',
                data: raw as Hex,
              });
              onChain.currentAllowanceRaw = BigInt(allowance).toString();
            } catch {
              // Ignore
            }
          }
        })(),
      );
    }
  }

  // 3. Check whether spender is a smart contract or an EOA (externally owned account)
  if (isValidAddress(params.spender)) {
    const spender = params.spender;
    tasks.push(
      (async () => {
        const code = await rpcCall(
          rpcUrl,
          'eth_getCode',
          [spender, 'latest'],
          'Check if spender is EOA or smart contract (eth_getCode)',
          networkLog,
          fetchImpl,
        );
        if (typeof code === 'string') {
          onChain.spenderIsContract = code !== '0x' && code !== '0x0' && code.length > 2;
        }
      })(),
    );
  }

  // 4. EIP-1967 proxy detection on target contract
  const proxyTarget = params.targetContract ?? params.tokenAddress;
  if (isValidAddress(proxyTarget)) {
    tasks.push(
      (async () => {
        const slotVal = await rpcCall(
          rpcUrl,
          'eth_getStorageAt',
          [proxyTarget, EIP1967_IMPL_SLOT, 'latest'],
          'Check EIP-1967 proxy implementation slot',
          networkLog,
          fetchImpl,
        );
        if (typeof slotVal === 'string' && /^0x[0-9a-fA-F]{64}$/.test(slotVal)) {
          const impl = `0x${slotVal.slice(-40).toLowerCase()}`;
          if (impl !== ZERO_ADDRESS) {
            onChain.targetIsProxy = true;
            onChain.proxyImplementation = impl;
          } else {
            onChain.targetIsProxy = false;
          }
        }
      })(),
    );
  }

  await Promise.all(tasks);
  return { onChain, networkLog };
}
