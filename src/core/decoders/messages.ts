import type { DecodedAction } from '../types';

function tryHexToUtf8(hex: string): string {
  if (!/^0x[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    return hex;
  }
  try {
    const bytes = new Uint8Array((hex.length - 2) / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(2 + i * 2, 4 + i * 2), 16);
    }
    const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    return decoded;
  } catch {
    return hex;
  }
}

export function decodePersonalSign(params: unknown[]): DecodedAction {
  const rawMessage = typeof params[0] === 'string' ? params[0] : '';
  const text = rawMessage.startsWith('0x') ? tryHexToUtf8(rawMessage) : rawMessage;
  const preview = text.length > 260 ? `${text.slice(0, 260)}…` : text;

  return {
    kind: 'PERSONAL_SIGN',
    functionName: 'personal_sign',
    rawPreview: preview || '(empty message)',
    summary: 'Off-chain text signature (typically used for login / Sign-In with Ethereum)',
  };
}

export function decodeRawEthSign(params: unknown[]): DecodedAction {
  const hashHex = typeof params[1] === 'string' ? params[1] : String(params[0] ?? '');
  return {
    kind: 'RAW_ETH_SIGN',
    functionName: 'eth_sign',
    rawPreview: hashHex.slice(0, 120),
    summary: 'DANGEROUS raw hash signing (eth_sign) — can sign arbitrary transactions or approvals blindly',
  };
}
