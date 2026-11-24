import type { InterceptedMethod, UserDecision } from '../core/types';

export const CHANNEL = 'APPROVAL_LENS_V1';

export const INTERCEPTED_METHODS: ReadonlySet<string> = new Set<InterceptedMethod>([
  'eth_sendTransaction',
  'eth_signTypedData_v4',
  'eth_signTypedData_v3',
  'eth_signTypedData',
  'personal_sign',
  'eth_sign',
]);

export function isInterceptedMethod(method: unknown): method is InterceptedMethod {
  return typeof method === 'string' && INTERCEPTED_METHODS.has(method);
}

export interface InpageInspectMessage {
  channel: typeof CHANNEL;
  direction: 'TO_CONTENT';
  type: 'INSPECT_REQUEST';
  requestId: string;
  method: InterceptedMethod;
  params: unknown[];
  payloadHash: string;
  walletName?: string;
  chainIdHex?: string;
}

export interface ContentDecisionMessage {
  channel: typeof CHANNEL;
  direction: 'TO_INPAGE';
  type: 'INSPECT_DECISION';
  requestId: string;
  decision: UserDecision;
  reason?: string;
}

export type BackgroundMessage =
  | {
      type: 'INSPECT_REQUEST';
      requestId: string;
      method: InterceptedMethod;
      params: unknown[];
      payloadHash: string;
      walletName?: string;
      chainIdHex?: string;
    }
  | {
      type: 'GET_PENDING_INSPECTION';
      requestId: string;
    }
  | {
      type: 'SUBMIT_DECISION';
      requestId: string;
      decision: UserDecision;
    }
  | {
      type: 'GET_STATE';
    }
  | {
      type: 'UPDATE_SETTINGS';
      settings: {
        enabled?: boolean;
        rpcEnrichmentEnabled?: boolean;
        customRpcUrl?: string;
      };
    }
  | {
      type: 'CLEAR_HISTORY';
    };

/**
 * Deterministic canonical JSON stringify (sorted object keys) for TOCTOU hashing.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalJson(item)).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    '{' +
    keys
      .filter((k) => obj[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k]))
      .join(',') +
    '}'
  );
}

export function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      deepFreeze(item);
    }
  } else {
    for (const key of Object.keys(value as Record<string, unknown>)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
  }
  return Object.freeze(value);
}

export function safeClone<T>(value: T): T {
  try {
    return structuredClone(value);
  } catch {
    return JSON.parse(JSON.stringify(value)) as T;
  }
}

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function hashRpcPayload(method: string, params: unknown[]): Promise<string> {
  return sha256Hex(canonicalJson({ method, params }));
}
