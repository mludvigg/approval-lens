import type { DecodedAction } from '../types';
import { isUnlimitedAmount, shortAddr } from './calldata';

interface EIP712Domain {
  name?: string;
  version?: string;
  chainId?: string | number;
  verifyingContract?: string;
}

interface ParsedTypedData {
  primaryType?: string;
  domain?: EIP712Domain;
  message?: Record<string, unknown>;
  types?: Record<string, unknown>;
}

export interface TypedDataDecodeOutput {
  decoded: DecodedAction;
  domainChainId?: number;
  verifyingContract?: string;
  domainName?: string;
  primaryType?: string;
}

function parseBigIntSafe(value: unknown): bigint | null {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return BigInt(Math.trunc(value));
  if (typeof value === 'string' && value.trim().length > 0) {
    try {
      return BigInt(value.trim());
    } catch {
      return null;
    }
  }
  return null;
}

function extractTypedDataPayload(params: unknown[]): ParsedTypedData | null {
  // Standard eth_signTypedData_v4 params: [signerAddress, jsonStringOrObject]
  // Some legacy dApps pass [jsonStringOrObject, signerAddress]
  for (const candidate of params) {
    if (typeof candidate === 'string' && candidate.trim().startsWith('{')) {
      try {
        const parsed = JSON.parse(candidate) as ParsedTypedData;
        if (parsed && typeof parsed === 'object') return parsed;
      } catch {
        // Not valid JSON
      }
    } else if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      const obj = candidate as ParsedTypedData;
      if (obj.message || obj.domain || obj.primaryType) {
        return obj;
      }
    }
  }
  return null;
}

export function decodeTypedData(params: unknown[]): TypedDataDecodeOutput {
  const parsed = extractTypedDataPayload(params);
  if (!parsed || !parsed.message || typeof parsed.message !== 'object') {
    return {
      decoded: {
        kind: 'TYPED_DATA_GENERIC',
        summary: 'Malformed or unreadable EIP-712 typed data — cannot decode safely',
      },
    };
  }

  const primaryType = parsed.primaryType ?? '';
  const domain = parsed.domain ?? {};
  const msg = parsed.message;
  const verifyingContract =
    typeof domain.verifyingContract === 'string' ? domain.verifyingContract : undefined;
  const domainName = typeof domain.name === 'string' ? domain.name : undefined;

  let domainChainId: number | undefined;
  if (domain.chainId !== undefined) {
    const cid = Number(domain.chainId);
    if (Number.isFinite(cid)) domainChainId = cid;
  }

  // 1. EIP-2612 Permit (gasless ERC-20 approval)
  if (
    primaryType === 'Permit' &&
    typeof msg.spender === 'string' &&
    (msg.value !== undefined || msg.allowed !== undefined)
  ) {
    const spender = msg.spender;
    const owner = typeof msg.owner === 'string' ? msg.owner : undefined;
    const deadline = msg.deadline !== undefined ? String(msg.deadline) : undefined;

    // DAI-style Permit uses `allowed: true/false` (unlimited if true)
    if (typeof msg.allowed === 'boolean') {
      return {
        domainChainId,
        verifyingContract,
        domainName,
        primaryType,
        decoded: {
          kind: 'EIP2612_PERMIT',
          functionName: 'Permit (DAI-style)',
          targetContract: verifyingContract,
          tokenAddress: verifyingContract,
          owner,
          spender,
          deadline,
          approved: msg.allowed,
          isUnlimited: msg.allowed,
          summary: msg.allowed
            ? `Gasless Permit: grant UNLIMITED spending rights to ${shortAddr(spender)}`
            : `Gasless Permit: revoke spending rights for ${shortAddr(spender)}`,
        },
      };
    }

    const val = parseBigIntSafe(msg.value);
    const unlimited = val !== null ? isUnlimitedAmount(val, 256) : false;
    return {
      domainChainId,
      verifyingContract,
      domainName,
      primaryType,
      decoded: {
        kind: 'EIP2612_PERMIT',
        functionName: 'Permit (EIP-2612)',
        targetContract: verifyingContract,
        tokenAddress: verifyingContract,
        owner,
        spender,
        amountRaw: val !== null ? val.toString() : String(msg.value),
        deadline,
        isUnlimited: unlimited,
        summary: unlimited
          ? `Gasless EIP-2612 Permit: grant UNLIMITED token approval to ${shortAddr(spender)}`
          : `Gasless EIP-2612 Permit: approve ${shortAddr(spender)} for ${val !== null ? val.toString() : String(msg.value)} raw units`,
      },
    };
  }

  // 2. Uniswap Permit2 — PermitSingle
  if (
    primaryType === 'PermitSingle' &&
    typeof msg.spender === 'string' &&
    msg.details &&
    typeof msg.details === 'object'
  ) {
    const details = msg.details as Record<string, unknown>;
    const token = typeof details.token === 'string' ? details.token : undefined;
    const amount = parseBigIntSafe(details.amount);
    const expiration = details.expiration !== undefined ? String(details.expiration) : undefined;
    const sigDeadline = msg.sigDeadline !== undefined ? String(msg.sigDeadline) : expiration;
    const unlimited = amount !== null ? isUnlimitedAmount(amount, 160) : false;

    return {
      domainChainId,
      verifyingContract,
      domainName,
      primaryType,
      decoded: {
        kind: 'PERMIT2_SINGLE',
        functionName: 'Permit2.PermitSingle',
        targetContract: verifyingContract,
        tokenAddress: token,
        spender: msg.spender,
        amountRaw: amount !== null ? amount.toString() : String(details.amount ?? ''),
        deadline: sigDeadline,
        isUnlimited: unlimited,
        summary: unlimited
          ? `Gasless Permit2 signature: grant UNLIMITED allowance on ${shortAddr(token)} to ${shortAddr(msg.spender)}`
          : `Gasless Permit2 signature: approve ${shortAddr(msg.spender)} for ${amount?.toString() ?? 'unknown'} raw units of ${shortAddr(token)}`,
      },
    };
  }

  // 3. Uniswap Permit2 — PermitBatch
  if (
    primaryType === 'PermitBatch' &&
    typeof msg.spender === 'string' &&
    Array.isArray(msg.details)
  ) {
    const items = msg.details as Record<string, unknown>[];
    const hasUnlimited = items.some((d) => {
      const amt = parseBigIntSafe(d?.amount);
      return amt !== null && isUnlimitedAmount(amt, 160);
    });
    const subActions: DecodedAction[] = items.slice(0, 20).map((d) => {
      const token = typeof d?.token === 'string' ? d.token : undefined;
      const amt = parseBigIntSafe(d?.amount);
      const unl = amt !== null && isUnlimitedAmount(amt, 160);
      return {
        kind: 'PERMIT2_SINGLE',
        tokenAddress: token,
        spender: msg.spender as string,
        amountRaw: amt?.toString(),
        isUnlimited: unl,
        summary: unl
          ? `UNLIMITED Permit2 allowance for token ${shortAddr(token)}`
          : `Permit2 allowance (${amt?.toString() ?? '?'} raw units) for token ${shortAddr(token)}`,
      };
    });

    return {
      domainChainId,
      verifyingContract,
      domainName,
      primaryType,
      decoded: {
        kind: 'PERMIT2_BATCH',
        functionName: 'Permit2.PermitBatch',
        targetContract: verifyingContract,
        spender: msg.spender,
        isUnlimited: hasUnlimited,
        deadline: msg.sigDeadline !== undefined ? String(msg.sigDeadline) : undefined,
        subActions,
        summary: `Gasless Permit2 BATCH signature approving ${items.length} token(s) to ${shortAddr(msg.spender)}`,
      },
    };
  }

  // 4. Uniswap Permit2 — PermitTransferFrom / PermitBatchTransferFrom
  if (
    (primaryType === 'PermitTransferFrom' || primaryType === 'PermitBatchTransferFrom') &&
    typeof msg.spender === 'string'
  ) {
    const permitted = msg.permitted as Record<string, unknown> | Record<string, unknown>[] | undefined;
    const token =
      permitted && !Array.isArray(permitted) && typeof permitted.token === 'string'
        ? permitted.token
        : undefined;
    const amount =
      permitted && !Array.isArray(permitted) ? parseBigIntSafe(permitted.amount) : null;

    return {
      domainChainId,
      verifyingContract,
      domainName,
      primaryType,
      decoded: {
        kind: 'PERMIT2_TRANSFER_FROM',
        functionName: `Permit2.${primaryType}`,
        targetContract: verifyingContract,
        tokenAddress: token,
        spender: msg.spender,
        amountRaw: amount?.toString(),
        deadline: msg.deadline !== undefined ? String(msg.deadline) : undefined,
        summary: `Gasless Permit2 signature-based token transfer authorized to ${shortAddr(msg.spender)}`,
      },
    };
  }

  // 5. Seaport / NFT Marketplace OrderComponents (common NFT drainer vector)
  if (primaryType === 'OrderComponents' && Array.isArray(msg.offer)) {
    const offer = msg.offer as Record<string, unknown>[];
    const consideration = Array.isArray(msg.consideration)
      ? (msg.consideration as Record<string, unknown>[])
      : [];
    const offerCount = offer.length;
    const considerationCount = consideration.length;
    const offerer = typeof msg.offerer === 'string' ? msg.offerer : undefined;
    const firstOfferToken =
      typeof offer[0]?.token === 'string' ? (offer[0].token as string) : undefined;
    const endTime = msg.endTime !== undefined ? String(msg.endTime) : undefined;

    const recipientSet = new Set<string>();
    let offererConsiderationCount = 0;

    for (const item of consideration) {
      const rec = typeof item?.recipient === 'string' ? item.recipient : undefined;
      if (rec) recipientSet.add(rec);
      const amt =
        parseBigIntSafe(item?.startAmount) ?? parseBigIntSafe(item?.endAmount) ?? 0n;
      if (amt > 0n) {
        if (!offerer || (rec && rec.toLowerCase() === offerer.toLowerCase())) {
          offererConsiderationCount += 1;
        }
      }
    }

    const recipients = Array.from(recipientSet);
    const zeroConsiderationToOfferer = offerCount > 0 && offererConsiderationCount === 0;
    const externalRecipient = recipients.find(
      (r) => !offerer || r.toLowerCase() !== offerer.toLowerCase(),
    );

    return {
      domainChainId,
      verifyingContract,
      domainName,
      primaryType,
      decoded: {
        kind: 'SEAPORT_ORDER',
        functionName: 'Seaport.OrderComponents',
        targetContract: verifyingContract,
        tokenAddress: firstOfferToken,
        owner: offerer,
        recipient: zeroConsiderationToOfferer ? externalRecipient : undefined,
        deadline: endTime,
        seaportDetails: {
          offerCount,
          considerationCount,
          offererConsiderationCount,
          zeroConsiderationToOfferer,
          recipients,
        },
        summary: zeroConsiderationToOfferer
          ? `DANGER: Seaport order offering ${offerCount} asset(s) with 0 payment returning to your wallet`
          : `Marketplace order offering ${offerCount} asset(s) for ${considerationCount} consideration item(s) — verify price carefully`,
      },
    };
  }

  // 6. Blur NFT Marketplace Orders (single Order & bulk Merkle Root)
  if (
    primaryType === 'Order' &&
    msg.trader !== undefined &&
    msg.collection !== undefined &&
    msg.side !== undefined
  ) {
    const sideNum = Number(msg.side);
    const priceVal = parseBigIntSafe(msg.price);
    const collection = typeof msg.collection === 'string' ? msg.collection : undefined;
    const trader = typeof msg.trader === 'string' ? msg.trader : undefined;
    const expiration =
      msg.expirationTime !== undefined ? String(msg.expirationTime) : undefined;
    const isZeroOrDustSell = sideNum === 1 && (priceVal === null || priceVal <= 1000n);

    return {
      domainChainId,
      verifyingContract,
      domainName,
      primaryType,
      decoded: {
        kind: 'BLUR_ORDER',
        functionName: 'Blur.Order',
        targetContract: verifyingContract,
        tokenAddress: collection,
        owner: trader,
        amountRaw: priceVal !== null ? priceVal.toString() : undefined,
        approved: isZeroOrDustSell,
        deadline: expiration,
        summary: isZeroOrDustSell
          ? `DANGER: Blur sell order listing NFT from ${shortAddr(collection)} for 0 / dust price`
          : `Blur marketplace ${sideNum === 1 ? 'sell listing' : 'buy bid'} on collection ${shortAddr(collection)}`,
      },
    };
  }

  if (primaryType === 'Root' && msg.root !== undefined) {
    return {
      domainChainId,
      verifyingContract,
      domainName,
      primaryType,
      decoded: {
        kind: 'BLUR_ORDER',
        functionName: 'Blur.BulkOrderRoot',
        targetContract: verifyingContract,
        rawPreview: String(msg.root).slice(0, 74),
        summary:
          'Blur bulk Merkle root signature — signs multiple hidden NFT orders inside a single root hash',
      },
    };
  }

  // 7. Generic / Unrecognized EIP-712 typed data
  return {
    domainChainId,
    verifyingContract,
    domainName,
    primaryType,
    decoded: {
      kind: 'TYPED_DATA_GENERIC',
      functionName: primaryType ? `EIP-712: ${primaryType}` : 'EIP-712 Typed Data',
      targetContract: verifyingContract,
      rawPreview: JSON.stringify(msg).slice(0, 240),
      summary: `Unrecognized EIP-712 signature (${primaryType || 'unknown primaryType'}) — review fields manually`,
    },
  };
}
