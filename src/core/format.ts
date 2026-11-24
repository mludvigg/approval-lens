import { formatUnits } from 'viem';
import { shortAddr } from './decoders/calldata';
import { checkMaliciousAddress, lookupKnownContract } from './reputation';
import type { InspectionResult, RiskFinding, Severity } from './types';

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function sortFindingsBySeverity(findings: RiskFinding[]): RiskFinding[] {
  return [...findings].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99),
  );
}

export function formatTokenAmount(
  raw?: string,
  decimals?: number,
  symbol?: string,
  isUnlimited?: boolean,
  includeRaw = false,
): string {
  if (isUnlimited) {
    const base = `Unlimited${symbol ? ` ${symbol}` : ''}`;
    return includeRaw && raw ? `${base} (raw: ${raw})` : base;
  }
  if (!raw) return '—';
  if (decimals !== undefined) {
    try {
      const formatted = formatUnits(BigInt(raw), decimals);
      const clean = addThousandsSeparators(formatted);
      const base = `${clean}${symbol ? ` ${symbol}` : ''}`;
      return includeRaw ? `${base} (raw: ${raw})` : base;
    } catch {
      return raw;
    }
  }
  return `${raw} raw units`;
}

function addThousandsSeparators(numStr: string): string {
  const [intPart, fracPart] = numStr.split('.');
  const formattedInt = intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  if (!fracPart) return formattedInt;
  const trimmedFrac = fracPart.slice(0, 6).replace(/0+$/, '');
  return trimmedFrac ? `${formattedInt}.${trimmedFrac}` : formattedInt;
}

const YEAR_2100_UNIX_SECONDS = 4102444800n;

export function formatDeadline(deadline?: string): string {
  if (!deadline || !deadline.trim()) return '—';
  const trimmed = deadline.trim();
  try {
    const val = BigInt(trimmed);
    if (val <= 0n) return 'Immediate / Expired';
    // Treat milliseconds vs seconds
    const seconds = val > 1_000_000_000_000n && val < 4_102_444_800_000n ? val / 1000n : val;
    if (seconds >= YEAR_2100_UNIX_SECONDS) {
      return 'Never expires';
    }
    const date = new Date(Number(seconds) * 1000);
    if (Number.isNaN(date.getTime())) return trimmed;
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: 'UTC',
    }).format(date);
  } catch {
    return trimmed;
  }
}

function describeActor(address?: string): string {
  if (!address) return 'an unknown address';
  const bad = checkMaliciousAddress(address);
  if (bad) return `${bad.label} (${shortAddr(address)})`;
  const known = lookupKnownContract(address);
  if (known) return `${known.name} (${shortAddr(address)})`;
  return shortAddr(address);
}

export function buildPlainEnglishSummary(result: InspectionResult): string {
  const { decoded, onChain } = result;
  const symbol = onChain.tokenSymbol;
  const decimals = onChain.tokenDecimals;
  const formattedAmt = formatTokenAmount(
    decoded.amountRaw,
    decimals,
    symbol,
    decoded.isUnlimited,
    false,
  );
  const actor = describeActor(decoded.spender ?? decoded.recipient ?? decoded.targetContract);
  const expiry = decoded.deadline ? formatDeadline(decoded.deadline) : null;
  const expiryClause =
    expiry && expiry !== '—'
      ? expiry === 'Never expires'
        ? ' with no expiration date'
        : ` until ${expiry}`
      : '';

  switch (decoded.kind) {
    case 'ERC20_APPROVE':
      if (decoded.amountRaw === '0') {
        return `You are revoking ${actor}'s permission to spend your ${symbol ?? 'tokens'}.`;
      }
      return decoded.isUnlimited
        ? `You are giving ${actor} permission to take your ENTIRE ${symbol ?? 'token'} balance (now and in the future)${expiryClause} without asking again.`
        : `You are allowing ${actor} to spend up to ${formattedAmt} from your wallet${expiryClause} without asking again.`;

    case 'ERC20_INCREASE_ALLOWANCE':
      return decoded.isUnlimited
        ? `You are increasing ${actor}'s spending limit to your ENTIRE ${symbol ?? 'token'} balance without asking again.`
        : `You are increasing ${actor}'s spending allowance by ${formattedAmt} from your wallet.`;

    case 'ERC20_DECREASE_ALLOWANCE':
      return `You are reducing ${actor}'s token spending allowance by ${formattedAmt}.`;

    case 'ERC20_TRANSFER':
    case 'ERC20_TRANSFER_FROM':
      return `You are immediately sending ${formattedAmt} directly to ${describeActor(decoded.recipient)}.`;

    case 'NFT_SET_APPROVAL_FOR_ALL':
      return decoded.approved
        ? `You are giving ${actor} full control to transfer ALL of your NFTs in collection ${shortAddr(decoded.targetContract)} whenever they want.`
        : `You are revoking ${actor}'s access to transfer your NFTs in collection ${shortAddr(decoded.targetContract)}.`;

    case 'NFT_TRANSFER':
      return `You are transferring NFT #${decoded.amountRaw ?? '?'} directly to ${describeActor(decoded.recipient)}.`;

    case 'EIP2612_PERMIT':
      return decoded.isUnlimited
        ? `You are signing a gasless permit that lets ${actor} spend your ENTIRE ${symbol ?? 'token'} balance${expiryClause} without paying gas now.`
        : `You are signing a gasless permit allowing ${actor} to spend up to ${formattedAmt} from your wallet${expiryClause}.`;

    case 'PERMIT2_SINGLE':
      return decoded.isUnlimited
        ? `You are signing a gasless Permit2 approval giving ${actor} UNLIMITED access to pull your ${symbol ?? 'tokens'}${expiryClause}.`
        : `You are signing a gasless Permit2 approval allowing ${actor} to pull up to ${formattedAmt}${expiryClause}.`;

    case 'PERMIT2_BATCH':
      return `You are signing a gasless Permit2 batch approval giving ${actor} spending rights across ${decoded.subActions?.length ?? 'multiple'} tokens at once${expiryClause}.`;

    case 'PERMIT2_TRANSFER_FROM':
      return `You are authorizing ${actor} to immediately pull ${formattedAmt} from your wallet via a gasless Permit2 signature.`;

    case 'SEAPORT_ORDER':
      if (decoded.seaportDetails?.zeroConsiderationToOfferer) {
        return `DANGER: You are offering ${decoded.seaportDetails.offerCount} asset(s) in a Seaport order that pays 0 back to your wallet — this matches a zero-price NFT phishing drain.`;
      }
      return `You are signing an off-chain marketplace order offering ${decoded.seaportDetails?.offerCount ?? 'your'} asset(s) for ${decoded.seaportDetails?.considerationCount ?? 'specified'} consideration item(s). Verify the payment returning to your wallet.`;

    case 'BLUR_ORDER':
      if (decoded.functionName === 'Blur.BulkOrderRoot') {
        return `You are signing a Blur bulk Merkle root authorizing multiple NFT listings at once. Individual NFT prices are hidden inside the root hash and cannot be verified here.`;
      }
      if (decoded.approved) {
        return `DANGER: You are signing a Blur sell order listing your NFT from ${shortAddr(decoded.tokenAddress)} for 0 (or dust) — an attacker can sweep it virtually for free.`;
      }
      return `You are signing an off-chain Blur marketplace order on collection ${shortAddr(decoded.tokenAddress)}. Verify the price and order side carefully.`;

    case 'SOURCIFY_DECODED':
      return `You are calling verified function ${decoded.functionName ?? 'unknown'} on ${
        decoded.contractName
          ? `${decoded.contractName} (${shortAddr(decoded.targetContract)})`
          : describeActor(decoded.targetContract)
      }. Review the decoded parameters below before signing.`;

    case 'MULTICALL':
      return `You are executing a bundled batch of ${decoded.subActions?.length ?? 'multiple'} operations in a single transaction. Check every nested step for hidden approvals.`;

    case 'NATIVE_TRANSFER':
      return decoded.amountRaw && decoded.amountRaw !== '0'
        ? `You are sending ${formatTokenAmount(decoded.amountRaw, 18, 'ETH')} directly to ${describeActor(decoded.recipient)}.`
        : `You are sending a transaction with 0 ETH to ${describeActor(decoded.targetContract)}.`;

    case 'PERSONAL_SIGN':
      return `You are signing a readable text message to prove wallet ownership (typically for logging in). It cannot directly move tokens on-chain unless it matches a protocol order.`;

    case 'RAW_ETH_SIGN':
      return `DANGER: You are signing a raw, unreadable 32-byte hash (eth_sign) that can authorize arbitrary transactions and completely drain your wallet.`;

    case 'TYPED_DATA_GENERIC':
      return `You are signing an unrecognized structured message (${decoded.functionName ?? 'EIP-712'}). Because its schema is not in the local verified set, verify the website and fields carefully.`;

    case 'UNKNOWN_CALLDATA':
    default:
      return `You are calling an unrecognized contract function (${decoded.selector ?? 'unknown selector'}) on ${describeActor(decoded.targetContract)}. Approval Lens cannot verify what this code will do on-chain.`;
  }
}
