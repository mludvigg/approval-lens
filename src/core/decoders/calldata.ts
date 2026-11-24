import { decodeFunctionData, parseAbi, type Hex } from 'viem';
import type { DecodedAction } from '../types';

const MAX_CALLDATA_CHARS = 256_000;
const MAX_MULTICALL_DEPTH = 3;

// >= 2^255 is treated as effectively unlimited for ERC-20 uint256 allowances
export const UNLIMITED_UINT256_THRESHOLD = 1n << 255n;

const KNOWN_ABI = parseAbi([
  // ERC-20
  'function approve(address spender, uint256 amount)',
  'function increaseAllowance(address spender, uint256 addedValue)',
  'function decreaseAllowance(address spender, uint256 subtractedValue)',
  'function transfer(address to, uint256 amount)',
  'function transferFrom(address from, address to, uint256 amount)',
  // ERC-721 / ERC-1155
  'function setApprovalForAll(address operator, bool approved)',
  'function safeTransferFrom(address from, address to, uint256 tokenId)',
  'function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes data)',
  // Permit2 on-chain approve
  'function approve(address token, address spender, uint160 amount, uint48 expiration)',
  // Multicall variants (OpenZeppelin / Uniswap V3 / SwapRouter02)
  'function multicall(bytes[] data)',
  'function multicall(uint256 deadline, bytes[] data)',
  'function multicall(bytes32 previousBlockhash, bytes[] data)',
  // Multicall3 cross-contract batching (0xcA11bde05977b3631167028862bE2a173976CA11)
  'function aggregate((address target, bytes callData)[] calls)',
  'function aggregate3((address target, bool allowFailure, bytes callData)[] calls)',
  'function aggregate3Value((address target, bool allowFailure, uint256 value, bytes callData)[] calls)',
  'function tryAggregate(bool requireSuccess, (address target, bytes callData)[] calls)',
]);

export const UNLIMITED_UINT160_THRESHOLD = 1n << 159n;

export function isHexString(value: unknown): value is Hex {
  return typeof value === 'string' && /^0x[0-9a-fA-F]*$/.test(value);
}

export function shortAddr(addr?: string): string {
  if (!addr || addr.length < 12) return addr || 'unknown';
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

export function isUnlimitedAmount(amount: bigint, bits: 256 | 160 = 256): boolean {
  return bits === 160
    ? amount >= UNLIMITED_UINT160_THRESHOLD
    : amount >= UNLIMITED_UINT256_THRESHOLD;
}

export interface TxLike {
  to?: string;
  from?: string;
  data?: string;
  input?: string;
  value?: string;
}

export function decodeTransaction(tx: TxLike): DecodedAction {
  const data = tx.data ?? tx.input ?? '0x';
  const target = typeof tx.to === 'string' ? tx.to : undefined;

  if (!data || data === '0x' || data === '0x0') {
    const valBigInt = parseHexBigInt(tx.value);
    return {
      kind: 'NATIVE_TRANSFER',
      targetContract: target,
      recipient: target,
      owner: typeof tx.from === 'string' ? tx.from : undefined,
      amountRaw: valBigInt.toString(),
      summary: target
        ? `Send native currency (${valBigInt.toString()} wei) to ${shortAddr(target)}`
        : 'Contract creation or empty transaction',
    };
  }

  return decodeCalldata(data, target, 0);
}

export function decodeCalldata(
  rawData: string,
  targetContract?: string,
  depth = 0,
): DecodedAction {
  if (!isHexString(rawData) || rawData.length < 10) {
    return {
      kind: 'UNKNOWN_CALLDATA',
      targetContract,
      rawPreview: typeof rawData === 'string' ? rawData.slice(0, 66) : '',
      summary: 'Malformed or truncated calldata (cannot be decoded)',
    };
  }

  if (rawData.length > MAX_CALLDATA_CHARS) {
    return {
      kind: 'UNKNOWN_CALLDATA',
      targetContract,
      selector: rawData.slice(0, 10),
      rawPreview: `${rawData.slice(0, 66)}… (${rawData.length} chars)`,
      summary: `Oversized calldata (${Math.floor((rawData.length - 2) / 2)} bytes) exceeded safe decoding limit`,
    };
  }

  const selector = rawData.slice(0, 10).toLowerCase();

  try {
    const decoded = decodeFunctionData({
      abi: KNOWN_ABI,
      data: rawData,
    });

    const args = decoded.args ?? [];

    switch (decoded.functionName) {
      case 'approve': {
        // Distinguish ERC-20 approve(address,uint256) vs Permit2 approve(address,address,uint160,uint48)
        if (args.length === 2) {
          const spender = String(args[0]);
          const amount = BigInt(args[1] as bigint);
          const unlimited = isUnlimitedAmount(amount, 256);
          return {
            kind: 'ERC20_APPROVE',
            functionName: 'approve(address,uint256)',
            selector,
            targetContract,
            tokenAddress: targetContract,
            spender,
            amountRaw: amount.toString(),
            isUnlimited: unlimited,
            summary:
              amount === 0n
                ? `Revoke ERC-20 allowance for ${shortAddr(spender)}`
                : unlimited
                  ? `Grant UNLIMITED ERC-20 spending approval to ${shortAddr(spender)}`
                  : `Approve ${shortAddr(spender)} to spend ${amount.toString()} raw token units`,
          };
        }
        if (args.length === 4) {
          const token = String(args[0]);
          const spender = String(args[1]);
          const amount = BigInt(args[2] as bigint);
          const expiration = BigInt(args[3] as number | bigint);
          const unlimited = isUnlimitedAmount(amount, 160);
          return {
            kind: 'ERC20_APPROVE',
            functionName: 'approve(address,address,uint160,uint48)',
            selector,
            targetContract,
            tokenAddress: token,
            spender,
            amountRaw: amount.toString(),
            deadline: expiration.toString(),
            isUnlimited: unlimited,
            summary: unlimited
              ? `Grant UNLIMITED Permit2 on-chain approval for ${shortAddr(token)} to ${shortAddr(spender)}`
              : `Approve Permit2 on-chain allowance (${amount.toString()} raw units) for ${shortAddr(token)} to ${shortAddr(spender)}`,
          };
        }
        break;
      }

      case 'increaseAllowance': {
        const spender = String(args[0]);
        const amount = BigInt(args[1] as bigint);
        const unlimited = isUnlimitedAmount(amount, 256);
        return {
          kind: 'ERC20_INCREASE_ALLOWANCE',
          functionName: 'increaseAllowance(address,uint256)',
          selector,
          targetContract,
          tokenAddress: targetContract,
          spender,
          amountRaw: amount.toString(),
          isUnlimited: unlimited,
          summary: unlimited
            ? `Increase ERC-20 allowance by an UNLIMITED amount for ${shortAddr(spender)}`
            : `Increase ERC-20 allowance for ${shortAddr(spender)} by ${amount.toString()} raw units`,
        };
      }

      case 'decreaseAllowance': {
        const spender = String(args[0]);
        const amount = BigInt(args[1] as bigint);
        return {
          kind: 'ERC20_DECREASE_ALLOWANCE',
          functionName: 'decreaseAllowance(address,uint256)',
          selector,
          targetContract,
          tokenAddress: targetContract,
          spender,
          amountRaw: amount.toString(),
          isUnlimited: false,
          summary: `Decrease ERC-20 allowance for ${shortAddr(spender)} by ${amount.toString()} raw units`,
        };
      }

      case 'transfer': {
        const recipient = String(args[0]);
        const amount = BigInt(args[1] as bigint);
        return {
          kind: 'ERC20_TRANSFER',
          functionName: 'transfer(address,uint256)',
          selector,
          targetContract,
          tokenAddress: targetContract,
          recipient,
          amountRaw: amount.toString(),
          summary: `Transfer ${amount.toString()} raw token units to ${shortAddr(recipient)}`,
        };
      }

      case 'transferFrom': {
        const owner = String(args[0]);
        const recipient = String(args[1]);
        const amount = BigInt(args[2] as bigint);
        return {
          kind: 'ERC20_TRANSFER_FROM',
          functionName: 'transferFrom(address,address,uint256)',
          selector,
          targetContract,
          tokenAddress: targetContract,
          owner,
          recipient,
          amountRaw: amount.toString(),
          summary: `Transfer ${amount.toString()} raw units from ${shortAddr(owner)} to ${shortAddr(recipient)}`,
        };
      }

      case 'setApprovalForAll': {
        const operator = String(args[0]);
        const approved = Boolean(args[1]);
        return {
          kind: 'NFT_SET_APPROVAL_FOR_ALL',
          functionName: 'setApprovalForAll(address,bool)',
          selector,
          targetContract,
          tokenAddress: targetContract,
          spender: operator,
          approved,
          isUnlimited: approved,
          summary: approved
            ? `Grant FULL collection transfer rights (setApprovalForAll) to ${shortAddr(operator)}`
            : `Revoke collection transfer rights from ${shortAddr(operator)}`,
        };
      }

      case 'safeTransferFrom': {
        const owner = String(args[0]);
        const recipient = String(args[1]);
        const tokenId = BigInt(args[2] as bigint);
        return {
          kind: 'NFT_TRANSFER',
          functionName:
            args.length === 5
              ? 'safeTransferFrom(address,address,uint256,uint256,bytes)'
              : 'safeTransferFrom(address,address,uint256)',
          selector,
          targetContract,
          tokenAddress: targetContract,
          owner,
          recipient,
          amountRaw: tokenId.toString(),
          summary: `Transfer NFT #${tokenId.toString()} from ${shortAddr(owner)} to ${shortAddr(recipient)}`,
        };
      }

      case 'multicall': {
        const callsArg = (args.length === 2 ? args[1] : args[0]) as readonly string[];
        if (depth >= MAX_MULTICALL_DEPTH) {
          return {
            kind: 'UNKNOWN_CALLDATA',
            functionName: 'multicall',
            selector,
            targetContract,
            summary: `Nested multicall exceeded max depth (${MAX_MULTICALL_DEPTH}); remaining calls unanalyzed`,
          };
        }
        const subActions = callsArg
          .slice(0, 25)
          .map((subCall) => decodeCalldata(subCall, targetContract, depth + 1));

        return {
          kind: 'MULTICALL',
          functionName:
            args.length === 2 ? 'multicall(deadline/hash,bytes[])' : 'multicall(bytes[])',
          selector,
          targetContract,
          subActions,
          summary: `Batched multicall containing ${callsArg.length} inner call(s)`,
        };
      }

      case 'aggregate':
      case 'aggregate3':
      case 'aggregate3Value':
      case 'tryAggregate': {
        if (depth >= MAX_MULTICALL_DEPTH) {
          return {
            kind: 'UNKNOWN_CALLDATA',
            functionName: `Multicall3.${decoded.functionName}`,
            selector,
            targetContract,
            summary: `Nested Multicall3 exceeded max depth (${MAX_MULTICALL_DEPTH}); remaining calls unanalyzed`,
          };
        }

        const rawTuples = (
          decoded.functionName === 'tryAggregate' ? args[1] : args[0]
        ) as ReadonlyArray<{
          target?: string;
          callData?: string;
          value?: bigint | number;
        }>;

        const subActions: DecodedAction[] = rawTuples.slice(0, 25).map((item) => {
          const subTarget = typeof item?.target === 'string' ? item.target : targetContract;
          const subData = typeof item?.callData === 'string' ? item.callData : '0x';
          const subValue =
            item?.value !== undefined ? BigInt(item.value as bigint | number) : 0n;

          if ((!subData || subData === '0x' || subData === '0x0') && subValue > 0n) {
            return {
              kind: 'NATIVE_TRANSFER',
              targetContract: subTarget,
              recipient: subTarget,
              amountRaw: subValue.toString(),
              summary: `Send native currency (${subValue.toString()} wei) to ${shortAddr(subTarget)}`,
            };
          }
          return decodeCalldata(subData, subTarget, depth + 1);
        });

        return {
          kind: 'MULTICALL',
          functionName: `Multicall3.${decoded.functionName}`,
          selector,
          targetContract,
          subActions,
          summary: `Multicall3 batch (${decoded.functionName}) containing ${rawTuples.length} cross-contract call(s)`,
        };
      }
    }
  } catch {
    // Unknown selector or malformed ABI encoding -> honest UNANALYZED fallback
  }

  return {
    kind: 'UNKNOWN_CALLDATA',
    selector,
    targetContract,
    rawPreview: rawData.length > 74 ? `${rawData.slice(0, 74)}…` : rawData,
    summary: `Unrecognized contract call (selector ${selector}) — cannot decode safely`,
  };
}

function parseHexBigInt(val?: string): bigint {
  if (!val || typeof val !== 'string') return 0n;
  try {
    return BigInt(val);
  } catch {
    return 0n;
  }
}
