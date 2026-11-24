import {
  CHANNEL,
  isInterceptedMethod,
  type BackgroundMessage,
  type ContentDecisionMessage,
  type InpageInspectMessage,
} from '../shared/protocol';
import type { UserDecision } from '../core/types';

function replyToInpage(requestId: string, decision: UserDecision, reason?: string) {
  const msg: ContentDecisionMessage = {
    channel: CHANNEL,
    direction: 'TO_INPAGE',
    type: 'INSPECT_DECISION',
    requestId,
    decision,
    reason,
  };
  const targetOrigin =
    window.location.origin && window.location.origin !== 'null'
      ? window.location.origin
      : '*';
  window.postMessage(msg, targetOrigin);
}

window.addEventListener('message', (event: MessageEvent) => {
  if (event.source !== window) return;

  const data = event.data as Partial<InpageInspectMessage> | null;
  if (
    !data ||
    data.channel !== CHANNEL ||
    data.direction !== 'TO_CONTENT' ||
    data.type !== 'INSPECT_REQUEST'
  ) {
    return;
  }

  if (
    typeof data.requestId !== 'string' ||
    data.requestId.length < 8 ||
    !isInterceptedMethod(data.method) ||
    !Array.isArray(data.params) ||
    typeof data.payloadHash !== 'string'
  ) {
    return;
  }

  const requestId = data.requestId;
  const bgMessage: BackgroundMessage = {
    type: 'INSPECT_REQUEST',
    requestId,
    method: data.method,
    params: data.params,
    payloadHash: data.payloadHash,
    walletName: typeof data.walletName === 'string' ? data.walletName.slice(0, 64) : undefined,
    chainIdHex: typeof data.chainIdHex === 'string' ? data.chainIdHex.slice(0, 20) : undefined,
  };

  chrome.runtime
    .sendMessage(bgMessage)
    .then((response: { decision?: UserDecision; reason?: string } | undefined) => {
      if (response && response.decision === 'ALLOW') {
        replyToInpage(requestId, 'ALLOW');
      } else {
        replyToInpage(
          requestId,
          'BLOCK',
          response?.reason || 'Request blocked by Approval Lens.',
        );
      }
    })
    .catch(() => {
      // Fail-closed: never pass through if the background worker is unavailable
      replyToInpage(
        requestId,
        'BLOCK',
        'Approval Lens background service was unavailable (fail-closed).',
      );
    });
});
