import type { CachedAbiEntry } from '../core/abiLookup';
import { analyzeRequest } from '../core/analyzer';
import type {
  ExtensionSettings,
  HistoryRecord,
  InspectionRequest,
  InspectionResult,
  UserDecision,
} from '../core/types';
import type { BackgroundMessage } from '../shared/protocol';

const SETTINGS_KEY = 'approvalLensSettings';
const HISTORY_KEY = 'approvalLensHistory';
const PENDING_PREFIX = 'pending:';
const MAX_HISTORY = 30;
const MAX_ABI_CACHE = 100;

const DEFAULT_SETTINGS: ExtensionSettings = {
  enabled: true,
  rpcEnrichmentEnabled: false, // Local-first by default (0 external network calls)
  abiLookupEnabled: false, // Opt-in Sourcify/4byte lookup (OFF by default)
  customRpcUrl: '',
};

const abiSessionCache = new Map<string, CachedAbiEntry | string | null>();

interface PendingEntry {
  resolve: (resp: { decision: UserDecision; reason?: string }) => void;
  result: InspectionResult;
  windowId?: number;
}

const pendingMap = new Map<string, PendingEntry>();

async function getSettings(): Promise<ExtensionSettings> {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  return {
    ...DEFAULT_SETTINGS,
    ...(stored[SETTINGS_KEY] as Partial<ExtensionSettings> | undefined),
  };
}

async function saveSettings(partial: Partial<ExtensionSettings>): Promise<ExtensionSettings> {
  const current = await getSettings();
  const next: ExtensionSettings = { ...current, ...partial };
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

async function getHistory(): Promise<HistoryRecord[]> {
  const stored = await chrome.storage.session.get(HISTORY_KEY);
  return (stored[HISTORY_KEY] as HistoryRecord[] | undefined) ?? [];
}

async function appendHistory(record: HistoryRecord): Promise<void> {
  const current = await getHistory();
  const next = [record, ...current].slice(0, MAX_HISTORY);
  await chrome.storage.session.set({ [HISTORY_KEY]: next });
}

function parseOriginSafe(url?: string): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

async function finalizePending(
  requestId: string,
  decision: UserDecision,
  reason?: string,
) {
  const entry = pendingMap.get(requestId);
  if (!entry) return;
  pendingMap.delete(requestId);

  await chrome.storage.session.remove(`${PENDING_PREFIX}${requestId}`).catch(() => {});

  await appendHistory({
    requestId,
    timestamp: new Date().toISOString(),
    origin: entry.result.request.origin,
    method: entry.result.request.method,
    verdict: entry.result.verdict,
    headline: entry.result.headline,
    decision,
    result: entry.result,
  }).catch(() => {});

  if (entry.windowId !== undefined) {
    chrome.windows.remove(entry.windowId).catch(() => {});
  }

  entry.resolve({ decision, reason });
}

// Fail-closed: closing the isolated review popup window without approving blocks the request
chrome.windows.onRemoved.addListener((closedWindowId) => {
  for (const [requestId, entry] of pendingMap.entries()) {
    if (entry.windowId === closedWindowId) {
      entry.windowId = undefined;
      void finalizePending(
        requestId,
        'BLOCK',
        'Review window closed without approval (fail-closed).',
      );
      break;
    }
  }
});

chrome.runtime.onInstalled.addListener(() => {
  console.info('[Approval Lens] Service worker ready (v0.2.0)');
});

chrome.runtime.onMessage.addListener(
  (
    message: BackgroundMessage,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void,
  ) => {
    if (!message || typeof message !== 'object' || typeof message.type !== 'string') {
      return false;
    }

    if (message.type === 'INSPECT_REQUEST') {
      void (async () => {
        try {
          const settings = await getSettings();
          if (!settings.enabled) {
            sendResponse({ decision: 'ALLOW', reason: 'Approval Lens is paused.' });
            return;
          }

          // Trust Chrome's verified sender.origin, NEVER a URL claimed by the page
          const verifiedOrigin =
            sender.origin || parseOriginSafe(sender.url) || 'unknown-origin';
          const topLevelOrigin = parseOriginSafe(sender.tab?.url);

          const request: InspectionRequest = {
            requestId: message.requestId,
            createdAt: new Date().toISOString(),
            method: message.method,
            params: message.params,
            payloadHash: message.payloadHash,
            origin: verifiedOrigin,
            topLevelOrigin:
              topLevelOrigin && topLevelOrigin !== verifiedOrigin
                ? topLevelOrigin
                : undefined,
            walletName: message.walletName,
            chainIdHex: message.chainIdHex,
          };

          if (abiSessionCache.size > MAX_ABI_CACHE) {
            const oldestKey = abiSessionCache.keys().next().value;
            if (oldestKey !== undefined) abiSessionCache.delete(oldestKey);
          }

          const result = await analyzeRequest(request, {
            rpcEnrichmentEnabled: settings.rpcEnrichmentEnabled,
            abiLookupEnabled: settings.abiLookupEnabled,
            customRpcUrl: settings.customRpcUrl,
            abiCache: abiSessionCache,
          });

          await chrome.storage.session.set({
            [`${PENDING_PREFIX}${request.requestId}`]: result,
          });

          const decisionPromise = new Promise<{
            decision: UserDecision;
            reason?: string;
          }>((resolve) => {
            pendingMap.set(request.requestId, { resolve, result });
          });

          const reviewUrl = chrome.runtime.getURL(
            `review.html?id=${encodeURIComponent(request.requestId)}`,
          );

          const win = await chrome.windows.create({
            url: reviewUrl,
            type: 'popup',
            width: 520,
            height: 760,
            focused: true,
          });

          const pending = pendingMap.get(request.requestId);
          if (pending && win?.id !== undefined) {
            pending.windowId = win.id;
          }

          const outcome = await decisionPromise;
          sendResponse(outcome);
        } catch (err) {
          console.error('[Approval Lens] Inspection failed (fail-closed):', err);
          sendResponse({
            decision: 'BLOCK',
            reason: 'Internal inspection error (fail-closed).',
          });
        }
      })();
      return true;
    }

    if (message.type === 'GET_PENDING_INSPECTION') {
      void (async () => {
        const key = `${PENDING_PREFIX}${message.requestId}`;
        const stored = await chrome.storage.session.get(key);
        sendResponse({ result: stored[key] ?? null });
      })();
      return true;
    }

    if (message.type === 'SUBMIT_DECISION') {
      // Only accept decisions from our own extension pages (review.html)
      if (sender.id !== chrome.runtime.id) {
        sendResponse({ ok: false, error: 'Unauthorized sender' });
        return false;
      }
      void finalizePending(
        message.requestId,
        message.decision === 'ALLOW' ? 'ALLOW' : 'BLOCK',
        message.decision === 'ALLOW'
          ? undefined
          : 'Blocked by user in Approval Lens.',
      ).then(() => sendResponse({ ok: true }));
      return true;
    }

    if (message.type === 'GET_STATE') {
      void Promise.all([getSettings(), getHistory()]).then(([settings, history]) => {
        sendResponse({ settings, history });
      });
      return true;
    }

    if (message.type === 'UPDATE_SETTINGS') {
      if (sender.id !== chrome.runtime.id) {
        sendResponse({ ok: false });
        return false;
      }
      void saveSettings(message.settings).then((settings) => {
        sendResponse({ ok: true, settings });
      });
      return true;
    }

    if (message.type === 'CLEAR_HISTORY') {
      if (sender.id !== chrome.runtime.id) {
        sendResponse({ ok: false });
        return false;
      }
      void chrome.storage.session.set({ [HISTORY_KEY]: [] }).then(() => {
        sendResponse({ ok: true });
      });
      return true;
    }

    return false;
  },
);
