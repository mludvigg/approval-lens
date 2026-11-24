import { decodeFunctionData, parseAbiItem, type Abi, type AbiFunction, type Hex } from 'viem';
import { isHexString } from './decoders/calldata';
import type { DecodedArgEntry, NetworkLogEntry } from './types';

export interface AbiLookupOutcome {
  source: 'sourcify' | 'fourbyte';
  abiSource: 'sourcify_exact' | 'sourcify_partial' | 'fourbyte_unverified';
  functionSignature: string;
  decodedArgs: DecodedArgEntry[];
  contractName?: string;
  resolvedAddress?: string;
}

export interface CachedAbiEntry {
  abi: Abi | null;
  match?: string;
  contractName?: string;
}

export interface AbiLookupParams {
  abiLookupEnabled: boolean;
  chainId?: number;
  targetContract?: string;
  proxyImplementation?: string | null;
  rawData?: string;
  selector?: string;
  fetchImpl?: typeof fetch;
  cache?: Map<string, CachedAbiEntry | string | null>;
  networkLog: NetworkLogEntry[];
}

function isValidEvmAddress(addr?: string | null): addr is string {
  return typeof addr === 'string' && /^0x[0-9a-fA-F]{40}$/.test(addr);
}

/**
 * Safely converts any decoded viem value (including bigint, arrays, structs) into a plain string
 * so InspectionResult never contains raw bigint values that break JSON / chrome.storage serialization.
 */
export function stringifyArgValue(value: unknown): string {
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) {
    return `[${value.map((item) => stringifyArgValue(item)).join(', ')}]`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).map(
      ([k, v]) => `${k}: ${stringifyArgValue(v)}`,
    );
    return `{ ${entries.join(', ')} }`;
  }
  return String(value);
}

function decodeWithAbi(
  abi: Abi,
  rawData: Hex,
): { signature: string; args: DecodedArgEntry[] } | null {
  try {
    const decoded = decodeFunctionData({ abi, data: rawData });
    const fnName = decoded.functionName;
    const rawArgs = (decoded.args ?? []) as readonly unknown[];

    // Locate matching function definition in ABI for parameter names & canonical types
    const candidates = abi.filter(
      (item): item is AbiFunction => item.type === 'function' && item.name === fnName,
    );
    const matchedFn =
      candidates.find((fn) => (fn.inputs?.length ?? 0) === rawArgs.length) ?? candidates[0];

    const inputTypes = matchedFn?.inputs?.map((inp) => inp.type) ?? [];
    const signature = matchedFn ? `${fnName}(${inputTypes.join(',')})` : fnName;

    const args: DecodedArgEntry[] = rawArgs.map((val, idx) => {
      const inputDef = matchedFn?.inputs?.[idx];
      return {
        name: inputDef?.name && inputDef.name.trim() ? inputDef.name : `arg${idx}`,
        type: inputDef?.type ?? 'unknown',
        value: stringifyArgValue(val),
      };
    });

    return { signature, args };
  } catch {
    return null;
  }
}

async function fetchJsonWithTimeout(
  url: string,
  targetHost: string,
  purpose: string,
  networkLog: NetworkLogEntry[],
  fetchImpl: typeof fetch,
  treat404AsMiss = false,
): Promise<{ status: number; json: unknown | null }> {
  const timestamp = new Date().toISOString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);

  try {
    const res = await fetchImpl(url, {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });

    if (res.status === 404 && treat404AsMiss) {
      networkLog.push({
        timestamp,
        target: targetHost,
        purpose,
        status: 'ok',
        detail: 'Not verified / no match (404)',
      });
      return { status: 404, json: null };
    }

    if (!res.ok) {
      networkLog.push({
        timestamp,
        target: targetHost,
        purpose,
        status: 'error',
        detail: `HTTP ${res.status}`,
      });
      return { status: res.status, json: null };
    }

    const json = await res.json();
    networkLog.push({
      timestamp,
      target: targetHost,
      purpose,
      status: 'ok',
    });
    return { status: res.status, json };
  } catch (err) {
    networkLog.push({
      timestamp,
      target: targetHost,
      purpose,
      status: 'error',
      detail: err instanceof Error ? err.message : 'Network error',
    });
    return { status: 0, json: null };
  } finally {
    clearTimeout(timer);
  }
}

export async function lookupAbiAndDecode(
  params: AbiLookupParams,
): Promise<AbiLookupOutcome | null> {
  const { networkLog } = params;

  if (!params.abiLookupEnabled) {
    networkLog.push({
      timestamp: new Date().toISOString(),
      target: 'local-only',
      purpose: 'Verified ABI lookup (Sourcify/4byte) disabled by user settings (0 bytes sent externally)',
      status: 'skipped',
    });
    return null;
  }

  const rawData = params.rawData;
  if (!rawData || !isHexString(rawData) || rawData.length < 10) {
    return null;
  }

  const fetchImpl = params.fetchImpl ?? fetch;
  const selector = (params.selector ?? rawData.slice(0, 10)).toLowerCase();

  // 1. Try Sourcify API v2 on proxyImplementation first (when known), then targetContract
  if (params.chainId !== undefined && Number.isFinite(params.chainId)) {
    const candidates: string[] = [];
    if (isValidEvmAddress(params.proxyImplementation)) {
      candidates.push(params.proxyImplementation.toLowerCase());
    }
    if (isValidEvmAddress(params.targetContract)) {
      const normTarget = params.targetContract.toLowerCase();
      if (!candidates.includes(normTarget)) {
        candidates.push(normTarget);
      }
    }

    for (const addr of candidates) {
      const cacheKey = `sourcify:${params.chainId}:${addr}`;
      let entry: CachedAbiEntry | null = null;

      if (params.cache?.has(cacheKey)) {
        const cached = params.cache.get(cacheKey);
        entry = cached && typeof cached === 'object' ? cached : null;
        networkLog.push({
          timestamp: new Date().toISOString(),
          target: 'session-cache',
          purpose: `Reused cached Sourcify lookup for ${addr.slice(0, 10)}…`,
          status: 'ok',
        });
      } else {
        const url = `https://sourcify.dev/server/v2/contract/${params.chainId}/${addr}?fields=abi`;
        const { json } = await fetchJsonWithTimeout(
          url,
          'sourcify.dev',
          `Lookup verified contract ABI on Sourcify v2 (${addr.slice(0, 10)}…)`,
          networkLog,
          fetchImpl,
          true,
        );

        if (json && typeof json === 'object') {
          const obj = json as {
            abi?: unknown;
            match?: string;
            name?: string;
            compilation?: { name?: string };
          };
          if (Array.isArray(obj.abi) && obj.abi.length > 0) {
            entry = {
              abi: obj.abi as Abi,
              match: obj.match,
              contractName: obj.compilation?.name ?? obj.name,
            };
          }
        }
        params.cache?.set(cacheKey, entry);
      }

      if (entry?.abi) {
        const decoded = decodeWithAbi(entry.abi, rawData);
        if (decoded) {
          return {
            source: 'sourcify',
            abiSource: entry.match === 'exact_match' ? 'sourcify_exact' : 'sourcify_partial',
            functionSignature: decoded.signature,
            decodedArgs: decoded.args,
            contractName: entry.contractName,
            resolvedAddress: addr,
          };
        }
      }
    }
  }

  // 2. Fallback: Sourcify 4byte Signature Database (unverified selector guess)
  if (/^0x[0-9a-f]{8}$/.test(selector)) {
    const cacheKey = `4byte:${selector}`;
    let matchedSig: string | null = null;

    if (params.cache?.has(cacheKey)) {
      const cached = params.cache.get(cacheKey);
      matchedSig = typeof cached === 'string' ? cached : null;
    } else {
      const url = `https://api.4byte.sourcify.dev/signature-database/v1/lookup?function=${selector}&filter=true`;
      const { json } = await fetchJsonWithTimeout(
        url,
        'api.4byte.sourcify.dev',
        `Fallback 4-byte function selector lookup (${selector})`,
        networkLog,
        fetchImpl,
        true,
      );

      if (json && typeof json === 'object') {
        const fnMap = (
          json as {
            result?: { function?: Record<string, Array<{ name?: string }> | undefined> };
          }
        ).result?.function;
        const hits = fnMap?.[selector] ?? fnMap?.[selector.toLowerCase()];
        if (Array.isArray(hits) && typeof hits[0]?.name === 'string' && hits[0].name.trim()) {
          matchedSig = hits[0].name.trim();
        }
      }
      params.cache?.set(cacheKey, matchedSig);
    }

    if (matchedSig) {
      let decodedArgs: DecodedArgEntry[] = [];
      try {
        const item = parseAbiItem(`function ${matchedSig}`);
        const decoded = decodeWithAbi([item] as Abi, rawData);
        if (decoded) {
          decodedArgs = decoded.args;
        }
      } catch {
        // Complex tuple signature that parseAbi can't parse from 4byte string; still return signature name
      }

      return {
        source: 'fourbyte',
        abiSource: 'fourbyte_unverified',
        functionSignature: matchedSig,
        decodedArgs,
      };
    }
  }

  return null;
}
