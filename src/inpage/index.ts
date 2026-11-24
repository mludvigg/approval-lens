import {
  CHANNEL,
  deepFreeze,
  hashRpcPayload,
  isInterceptedMethod,
  safeClone,
  type ContentDecisionMessage,
  type InpageInspectMessage,
} from '../shared/protocol';
import type { InterceptedMethod, UserDecision } from '../core/types';

interface EIP1193Provider {
  request: (args: { method: string; params?: unknown[] | object }) => Promise<unknown>;
  send?: (...args: unknown[]) => unknown;
  sendAsync?: (
    payload: { method: string; params?: unknown[] },
    cb: (err: unknown, response?: unknown) => void,
  ) => void;
  chainId?: string;
  isMetaMask?: boolean;
  isRabby?: boolean;
  providers?: EIP1193Provider[];
  [key: string]: unknown;
}

interface PendingResolver {
  resolve: (decision: { decision: UserDecision; reason?: string }) => void;
  timer: ReturnType<typeof setTimeout>;
}

const REQUEST_TIMEOUT_MS = 5 * 60 * 1000;
const pendingRequests = new Map<string, PendingResolver>();
const wrappedProviders = new WeakMap<EIP1193Provider, EIP1193Provider>();
const wrappedEventMarker = new WeakSet<Event>();

function generateRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function createBlockedError(reason?: string): Error & { code: number } {
  const err = new Error(reason || 'Transaction blocked by Approval Lens.') as Error & { code: number };
  err.code = 4001; // EIP-1193 User Rejected Request
  return err;
}

function detectWalletName(provider: EIP1193Provider, explicitName?: string): string {
  if (explicitName) return explicitName;
  if (provider.isRabby) return 'Rabby Wallet';
  if (provider.isMetaMask) return 'MetaMask';
  return 'EIP-1193 Wallet';
}

function normalizeParams(params: unknown): unknown[] {
  if (Array.isArray(params)) return params;
  if (params === undefined || params === null) return [];
  return [params];
}

// Listen for decisions relayed from the ISOLATED content script
window.addEventListener('message', (event: MessageEvent) => {
  if (event.source !== window) return;
  const data = event.data as Partial<ContentDecisionMessage> | null;
  if (
    !data ||
    data.channel !== CHANNEL ||
    data.direction !== 'TO_INPAGE' ||
    data.type !== 'INSPECT_DECISION' ||
    typeof data.requestId !== 'string'
  ) {
    return;
  }

  const pending = pendingRequests.get(data.requestId);
  if (!pending) return;

  clearTimeout(pending.timer);
  pendingRequests.delete(data.requestId);
  pending.resolve({
    decision: data.decision === 'ALLOW' ? 'ALLOW' : 'BLOCK',
    reason: typeof data.reason === 'string' ? data.reason : undefined,
  });
});

async function requestInspection(
  method: InterceptedMethod,
  frozenParams: unknown[],
  walletName: string,
  chainIdHex?: string,
): Promise<{ decision: UserDecision; reason?: string }> {
  const requestId = generateRequestId();
  const payloadHash = await hashRpcPayload(method, frozenParams);

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingRequests.delete(requestId);
      resolve({ decision: 'BLOCK', reason: 'Approval Lens inspection timed out (fail-closed).' });
    }, REQUEST_TIMEOUT_MS);

    pendingRequests.set(requestId, { resolve, timer });

    const message: InpageInspectMessage = {
      channel: CHANNEL,
      direction: 'TO_CONTENT',
      type: 'INSPECT_REQUEST',
      requestId,
      method,
      params: frozenParams,
      payloadHash,
      walletName,
      chainIdHex,
    };

    const targetOrigin =
      window.location.origin && window.location.origin !== 'null'
        ? window.location.origin
        : '*';
    window.postMessage(message, targetOrigin);
  });
}

async function resolveChainId(provider: EIP1193Provider): Promise<string | undefined> {
  if (typeof provider.chainId === 'string' && provider.chainId.startsWith('0x')) {
    return provider.chainId;
  }
  try {
    const cid = await provider.request({ method: 'eth_chainId' });
    if (typeof cid === 'string') return cid;
  } catch {
    // Non-fatal
  }
  return undefined;
}

function wrapProvider(provider: EIP1193Provider, explicitWalletName?: string): EIP1193Provider {
  if (!provider || (typeof provider !== 'object' && typeof provider !== 'function')) {
    return provider;
  }
  const existing = wrappedProviders.get(provider);
  if (existing) return existing;

  const walletName = detectWalletName(provider, explicitWalletName);

  const proxy = new Proxy(provider, {
    get(target, prop, receiver) {
      if (prop === 'request') {
        return async (args: { method: string; params?: unknown[] | object }) => {
          if (!args || !isInterceptedMethod(args.method)) {
            return target.request(args);
          }

          // TOCTOU mitigation: deep-clone & freeze params BEFORE inspection
          const frozenParams = deepFreeze(safeClone(normalizeParams(args.params)));
          const chainIdHex = await resolveChainId(target);

          const outcome = await requestInspection(
            args.method,
            frozenParams,
            walletName,
            chainIdHex,
          );

          if (outcome.decision !== 'ALLOW') {
            throw createBlockedError(outcome.reason);
          }

          // Forward the exact frozen snapshot the user reviewed
          return target.request({
            method: args.method,
            params: safeClone(frozenParams),
          });
        };
      }

      if (prop === 'sendAsync' && typeof target.sendAsync === 'function') {
        return (
          payload: { method: string; params?: unknown[] },
          cb: (err: unknown, response?: unknown) => void,
        ) => {
          if (!payload || !isInterceptedMethod(payload.method)) {
            return target.sendAsync!(payload, cb);
          }

          const frozenParams = deepFreeze(safeClone(normalizeParams(payload.params)));
          void resolveChainId(target).then((chainIdHex) =>
            requestInspection(
              payload.method as InterceptedMethod,
              frozenParams,
              walletName,
              chainIdHex,
            ).then((outcome) => {
              if (outcome.decision !== 'ALLOW') {
                cb(createBlockedError(outcome.reason));
                return;
              }
              target.sendAsync!(
                { ...payload, params: safeClone(frozenParams) },
                cb,
              );
            }),
          );
        };
      }

      if (prop === 'providers' && Array.isArray(target.providers)) {
        return target.providers.map((sub) => wrapProvider(sub));
      }

      const value = Reflect.get(target, prop, receiver);
      if (typeof value === 'function') {
        return value.bind(target);
      }
      return value;
    },
  });

  wrappedProviders.set(provider, proxy);
  wrappedProviders.set(proxy, proxy);
  return proxy;
}

// 1. Hook EIP-6963 multi-wallet announcements (MetaMask, Rabby, etc.)
function createWrappedAnnounceEvent(event: CustomEvent): CustomEvent | null {
  if (
    wrappedEventMarker.has(event) ||
    !event.detail ||
    typeof event.detail !== 'object' ||
    !('provider' in event.detail)
  ) {
    return null;
  }
  const detail = event.detail as { info?: { name?: string }; provider: EIP1193Provider };
  const wrapped = wrapProvider(detail.provider, detail.info?.name);
  const wrappedEvent = new CustomEvent('eip6963:announceProvider', {
    detail: Object.freeze({
      ...detail,
      provider: wrapped,
    }),
  });
  wrappedEventMarker.add(wrappedEvent);
  return wrappedEvent;
}

const originalDispatchEvent = window.dispatchEvent.bind(window);
window.dispatchEvent = function patchedDispatchEvent(event: Event): boolean {
  if (event instanceof CustomEvent && event.type === 'eip6963:announceProvider') {
    const wrappedEvent = createWrappedAnnounceEvent(event);
    if (wrappedEvent) {
      return originalDispatchEvent(wrappedEvent);
    }
  }
  return originalDispatchEvent(event);
};

// Capture-phase fallback in case a wallet cached window.dispatchEvent before our script ran
window.addEventListener(
  'eip6963:announceProvider',
  (event: Event) => {
    if (!(event instanceof CustomEvent)) return;
    const wrappedEvent = createWrappedAnnounceEvent(event);
    if (!wrappedEvent) return;
    event.stopImmediatePropagation();
    originalDispatchEvent(wrappedEvent);
  },
  true,
);

// 2. Hook legacy window.ethereum (pre-existing or late-injected)
function installWindowEthereumHook() {
  const win = window as unknown as { ethereum?: EIP1193Provider };
  let currentProvider: EIP1193Provider | undefined = win.ethereum
    ? wrapProvider(win.ethereum)
    : undefined;

  const descriptor = Object.getOwnPropertyDescriptor(window, 'ethereum');
  if (!descriptor || descriptor.configurable) {
    Object.defineProperty(window, 'ethereum', {
      configurable: true,
      enumerable: true,
      get() {
        return currentProvider;
      },
      set(nextProvider: EIP1193Provider | undefined) {
        currentProvider = nextProvider ? wrapProvider(nextProvider) : undefined;
      },
    });
  } else if (win.ethereum) {
    const raw = win.ethereum;
    if (typeof raw.request === 'function') {
      const wrapped = wrapProvider(raw);
      try {
        raw.request = wrapped.request;
      } catch {
        // Non-writable fallback: EIP-6963 hook still protects modern dApps
      }
    }
  }
}

installWindowEthereumHook();
