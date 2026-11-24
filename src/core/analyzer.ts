import { decodeTransaction, shortAddr, type TxLike } from './decoders/calldata';
import { decodePersonalSign, decodeRawEthSign } from './decoders/messages';
import { decodeTypedData } from './decoders/typedData';
import { formatTokenAmount, sortFindingsBySeverity } from './format';
import {
  checkMaliciousAddress,
  checkMaliciousDomain,
  getReputationVersion,
  lookupKnownContract,
} from './reputation';
import { fetchOnChainContext } from './rpc';
import type {
  DecodedAction,
  InspectionRequest,
  InspectionResult,
  RiskFinding,
  Verdict,
} from './types';

export interface AnalyzeOptions {
  rpcEnrichmentEnabled?: boolean;
  customRpcUrl?: string;
  fetchImpl?: typeof fetch;
}

function parseChainIdHex(hex?: string): number | undefined {
  if (!hex || typeof hex !== 'string') return undefined;
  const parsed = Number.parseInt(hex, 16);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function flattenActions(action: DecodedAction): DecodedAction[] {
  const out: DecodedAction[] = [action];
  if (action.subActions) {
    for (const sub of action.subActions) {
      out.push(...flattenActions(sub));
    }
  }
  return out;
}

function extractOwner(request: InspectionRequest, decoded: DecodedAction): string | undefined {
  if (decoded.owner) return decoded.owner;
  if (request.method === 'eth_sendTransaction') {
    const tx = request.params[0] as TxLike | undefined;
    if (tx && typeof tx.from === 'string') return tx.from;
  }
  if (request.method.startsWith('eth_signTypedData')) {
    const first = request.params[0];
    if (typeof first === 'string' && /^0x[0-9a-fA-F]{40}$/.test(first)) {
      return first;
    }
  }
  return undefined;
}

export async function analyzeRequest(
  request: InspectionRequest,
  options: AnalyzeOptions = {},
): Promise<InspectionResult> {
  const findings: RiskFinding[] = [];
  const limitations: string[] = [
    'Approval Lens does not execute full EVM state simulation or audit arbitrary contract bytecode.',
    'Absence of known risk flags does NOT guarantee that a website or contract is safe.',
  ];

  const activeChainId = parseChainIdHex(request.chainIdHex);

  // 1. Decode payload according to RPC method
  let decoded: DecodedAction;
  let domainChainId: number | undefined;

  if (request.method === 'eth_sendTransaction') {
    const tx = (request.params[0] ?? {}) as TxLike;
    decoded = decodeTransaction(tx);
  } else if (
    request.method === 'eth_signTypedData_v4' ||
    request.method === 'eth_signTypedData_v3' ||
    request.method === 'eth_signTypedData'
  ) {
    const typed = decodeTypedData(request.params);
    decoded = typed.decoded;
    domainChainId = typed.domainChainId;
  } else if (request.method === 'personal_sign') {
    decoded = decodePersonalSign(request.params);
  } else {
    decoded = decodeRawEthSign(request.params);
  }

  const allActions = flattenActions(decoded);
  const primarySpender = allActions.find((a) => a.spender)?.spender;
  const primaryToken = allActions.find((a) => a.tokenAddress)?.tokenAddress;
  const primaryTarget = decoded.targetContract ?? primaryToken;
  const owner = extractOwner(request, decoded);

  // 2. Origin & iframe checks (Chrome-verified origin)
  const badDomain = checkMaliciousDomain(request.origin);
  if (badDomain) {
    findings.push({
      id: 'KNOWN_MALICIOUS_ORIGIN',
      severity: 'CRITICAL',
      title: `Known malicious origin: ${badDomain.label}`,
      explanation: `${badDomain.reason} Matched origin: ${request.origin}`,
      source: 'local_reputation',
      details: { origin: request.origin, domain: badDomain.domain },
    });
  }

  if (request.topLevelOrigin && request.topLevelOrigin !== request.origin) {
    findings.push({
      id: 'CROSS_ORIGIN_IFRAME',
      severity: 'HIGH',
      title: 'Wallet request initiated from a cross-origin iframe',
      explanation: `Embedded frame (${request.origin}) triggered a signing prompt inside top-level page (${request.topLevelOrigin}). Verify you trust both origins.`,
      source: 'browser_context',
      details: {
        frameOrigin: request.origin,
        topLevelOrigin: request.topLevelOrigin,
      },
    });
  }

  // 3. Domain chainId mismatch on EIP-712 signatures
  if (
    domainChainId !== undefined &&
    activeChainId !== undefined &&
    domainChainId !== activeChainId
  ) {
    findings.push({
      id: 'EIP712_CHAIN_MISMATCH',
      severity: 'HIGH',
      title: 'Signature chain ID does not match active wallet network',
      explanation: `Your wallet is connected to chain ${activeChainId}, but the signed message specifies chain ${domainChainId}. Attackers sometimes request Mainnet permits while you think you are on a testnet.`,
      source: 'local_decoder',
      details: { activeChainId, domainChainId },
    });
  }

  // 4. Local address reputation checks (check target, spender, recipient, token across all sub-actions)
  // Deduplicate by normalized address so identical targetContract & tokenAddress (e.g. USDC) never emit duplicate [INFO] cards.
  const checkedAddresses = new Set<string>();
  for (const act of allActions) {
    const sameTokenAndTarget =
      Boolean(act.tokenAddress) &&
      Boolean(act.targetContract) &&
      act.tokenAddress!.toLowerCase() === act.targetContract!.toLowerCase();

    const candidates: Array<{ role: string; address?: string }> = [
      { role: 'spender', address: act.spender },
      { role: 'recipient', address: act.recipient },
      { role: sameTokenAndTarget ? 'token' : 'token', address: act.tokenAddress },
      { role: 'target contract', address: act.targetContract },
    ];
    for (const { role, address } of candidates) {
      if (!address) continue;
      const normalizedAddr = address.toLowerCase();
      if (checkedAddresses.has(normalizedAddr)) continue;
      checkedAddresses.add(normalizedAddr);

      const badAddr = checkMaliciousAddress(address);
      if (badAddr) {
        findings.push({
          id: 'KNOWN_MALICIOUS_ADDRESS',
          severity: 'CRITICAL',
          title: `Malicious ${role}: ${badAddr.label}`,
          explanation: `${badAddr.reason} (${shortAddr(address)})`,
          source: 'local_reputation',
          details: { role, address },
        });
      }

      const known = lookupKnownContract(address);
      if (known) {
        findings.push({
          id: 'KNOWN_CONTRACT_LABEL',
          severity: 'INFO',
          title: `Recognized ${role}: ${known.name}`,
          explanation: known.note,
          source: 'local_reputation',
          details: { role, address, name: known.name },
        });
      }
    }
  }

  // 5. Permission & signature risk rules across decoded action tree
  const isMulticall = decoded.kind === 'MULTICALL';
  for (const act of allActions) {
    const nestedNote =
      isMulticall && act !== decoded
        ? ' This permission was discovered nested inside a multicall batch.'
        : '';

    if (act.kind === 'RAW_ETH_SIGN') {
      findings.push({
        id: 'RAW_ETH_SIGN',
        severity: 'CRITICAL',
        title: 'Dangerous blind signature (eth_sign)',
        explanation:
          'eth_sign signs an opaque 32-byte hash without human-readable structure. Legitimate modern dApps rarely require raw eth_sign because it can authorize arbitrary transactions.',
        source: 'local_decoder',
      });
    }

    if (
      (act.kind === 'ERC20_APPROVE' || act.kind === 'ERC20_INCREASE_ALLOWANCE') &&
      act.isUnlimited
    ) {
      findings.push({
        id: isMulticall ? 'MULTICALL_HIDDEN_UNLIMITED_APPROVAL' : 'UNLIMITED_ERC20_APPROVAL',
        severity: 'HIGH',
        title: isMulticall
          ? 'Unlimited ERC-20 approval hidden inside multicall'
          : 'Unlimited ERC-20 token approval requested',
        explanation: `Grants ${shortAddr(act.spender)} permission to spend your ENTIRE balance (now and in the future) of this token until revoked.${nestedNote}`,
        source: 'local_decoder',
        details: { spender: act.spender ?? null, amountRaw: act.amountRaw ?? null },
      });
    }

    if (act.kind === 'NFT_SET_APPROVAL_FOR_ALL' && act.approved) {
      findings.push({
        id: 'NFT_APPROVAL_FOR_ALL',
        severity: 'HIGH',
        title: 'Full NFT collection transfer approval (setApprovalForAll)',
        explanation: `Allows ${shortAddr(act.spender)} to transfer EVERY NFT you hold in collection ${shortAddr(act.targetContract)} without further confirmation.${nestedNote}`,
        source: 'local_decoder',
        details: { operator: act.spender ?? null, collection: act.targetContract ?? null },
      });
    }

    if (act.kind === 'EIP2612_PERMIT') {
      findings.push({
        id: act.isUnlimited ? 'GASLESS_PERMIT_UNLIMITED' : 'GASLESS_PERMIT',
        severity: act.isUnlimited ? 'HIGH' : 'MEDIUM',
        title: act.isUnlimited
          ? 'Gasless EIP-2612 Permit grants UNLIMITED approval'
          : 'Gasless EIP-2612 Permit grants token spending rights',
        explanation: `Even though this is an off-chain signature (no gas fee now), anyone holding it can submit it on-chain to let ${shortAddr(act.spender)} spend your tokens.`,
        source: 'local_decoder',
        details: {
          spender: act.spender ?? null,
          amountRaw: act.amountRaw ?? null,
          deadline: act.deadline ?? null,
        },
      });
    }

    if (
      act.kind === 'PERMIT2_SINGLE' ||
      act.kind === 'PERMIT2_BATCH' ||
      act.kind === 'PERMIT2_TRANSFER_FROM'
    ) {
      // Avoid duplicating per sub-action when parent is PERMIT2_BATCH
      if (!(decoded.kind === 'PERMIT2_BATCH' && act !== decoded)) {
        findings.push({
          id: act.isUnlimited ? 'PERMIT2_UNLIMITED' : 'PERMIT2_SIGNATURE',
          severity: 'HIGH',
          title:
            act.kind === 'PERMIT2_BATCH'
              ? 'Gasless Permit2 BATCH approval across multiple tokens'
              : act.isUnlimited
                ? 'Gasless Permit2 signature grants UNLIMITED token allowance'
                : 'Gasless Permit2 signature authorizes token spending',
          explanation: `Permit2 signatures let ${shortAddr(act.spender)} pull tokens you previously approved to Uniswap Permit2 without paying gas up front. Confirm the spender address carefully.`,
          source: 'local_decoder',
          details: {
            spender: act.spender ?? null,
            deadline: act.deadline ?? null,
          },
        });
      }
    }

    if (act.kind === 'SEAPORT_ORDER') {
      findings.push({
        id: 'SEAPORT_ORDER_SIGNATURE',
        severity: 'HIGH',
        title: 'Off-chain NFT marketplace order (Seaport)',
        explanation:
          'Signing a Seaport order can list or transfer your NFTs for whatever consideration is specified in the payload (including 0 ETH in phishing drains). Verify consideration items carefully.',
        source: 'local_decoder',
      });
    }

    if (act.kind === 'UNKNOWN_CALLDATA') {
      findings.push({
        id: 'OPAQUE_CALLDATA',
        severity: 'MEDIUM',
        title: 'Calldata could not be decoded locally',
        explanation: `Function selector ${act.selector ?? '(none)'} is not in Approval Lens's verified ABI set. Approval Lens refuses to guess what this contract call will do.${nestedNote}`,
        source: 'local_decoder',
        details: { selector: act.selector ?? null },
      });
    }
  }

  // 6. Optional on-chain RPC enrichment (explicitly logged)
  const { onChain, networkLog } = await fetchOnChainContext({
    rpcEnabled: Boolean(options.rpcEnrichmentEnabled),
    customRpcUrl: options.customRpcUrl,
    chainId: activeChainId,
    tokenAddress: primaryToken,
    targetContract: primaryTarget,
    owner,
    spender: primarySpender,
    fetchImpl: options.fetchImpl,
  });

  // Fallback to known local token metadata (0 network calls) when RPC metadata is absent
  const knownToken = lookupKnownContract(primaryToken ?? primaryTarget);
  if (knownToken) {
    if (!onChain.tokenSymbol && knownToken.symbol) {
      onChain.tokenSymbol = knownToken.symbol;
    }
    if (onChain.tokenDecimals === undefined && knownToken.decimals !== undefined) {
      onChain.tokenDecimals = knownToken.decimals;
    }
  }

  // Upgrade raw token unit strings in decoded.summary when decimals/symbol are known
  if (
    decoded.amountRaw &&
    !decoded.isUnlimited &&
    onChain.tokenDecimals !== undefined
  ) {
    const humanAmount = formatTokenAmount(
      decoded.amountRaw,
      onChain.tokenDecimals,
      onChain.tokenSymbol,
      false,
    );
    decoded.summary = decoded.summary
      .replace(`${decoded.amountRaw} raw token units`, humanAmount)
      .replace(`${decoded.amountRaw} raw units`, humanAmount);
  } else if (decoded.isUnlimited && onChain.tokenSymbol) {
    decoded.summary = decoded.summary
      .replace('UNLIMITED ERC-20', `UNLIMITED ${onChain.tokenSymbol}`)
      .replace('UNLIMITED token', `UNLIMITED ${onChain.tokenSymbol}`);
  }

  if (!options.rpcEnrichmentEnabled) {
    limitations.push(
      'Local-only mode active: on-chain token metadata, existing allowance, EOA/contract checks, and EIP-1967 proxy resolution were not fetched.',
    );
  } else {
    if (onChain.spenderIsContract === false) {
      findings.push({
        id: 'EOA_SPENDER_DETECTED',
        severity: 'HIGH',
        title: 'Spender is a regular wallet (EOA), not a smart contract',
        explanation: `Spender ${shortAddr(primarySpender)} has no deployed contract bytecode. Legitimate DeFi protocols almost always use audited smart contracts as spenders — approving an EOA is a major phishing signal.`,
        source: 'rpc_read',
        details: { spender: primarySpender ?? null },
      });
    }

    if (onChain.targetIsProxy) {
      findings.push({
        id: 'EIP1967_PROXY_CONTRACT',
        severity: 'MEDIUM',
        title: 'Target contract uses an upgradeable EIP-1967 proxy',
        explanation: `Implementation contract resolves to ${onChain.proxyImplementation}. Proxy contracts can change behavior if their admin upgrades the implementation.`,
        source: 'rpc_read',
        details: { implementation: onChain.proxyImplementation ?? null },
      });
    }
  }

  if (decoded.kind === 'TYPED_DATA_GENERIC' || decoded.kind === 'UNKNOWN_CALLDATA') {
    limitations.push(
      'Payload schema or ABI was unrecognized; risk assessment is partial and marked UNANALYZED.',
    );
  }

  // 7. Determine honest Verdict (never claims "Safe")
  const hasCritical = findings.some((f) => f.severity === 'CRITICAL');
  const hasHigh = findings.some((f) => f.severity === 'HIGH');
  const hasMedium = findings.some((f) => f.severity === 'MEDIUM');
  const isUnanalyzed =
    decoded.kind === 'UNKNOWN_CALLDATA' ||
    decoded.kind === 'TYPED_DATA_GENERIC' ||
    allActions.some((a) => a.kind === 'UNKNOWN_CALLDATA');

  let verdict: Verdict;
  let headline: string;

  if (
    findings.some(
      (f) => f.id === 'KNOWN_MALICIOUS_ORIGIN' || f.id === 'KNOWN_MALICIOUS_ADDRESS',
    )
  ) {
    verdict = 'KNOWN_MALICIOUS';
    headline = 'Matched known malicious indicator in local threat intelligence';
  } else if (hasCritical || hasHigh) {
    verdict = 'HIGH_RISK';
    headline = decoded.summary;
  } else if (isUnanalyzed) {
    verdict = 'UNANALYZED';
    headline = 'Unrecognized contract call or signature — cannot verify intent';
  } else if (hasMedium) {
    verdict = 'REVIEW_NEEDED';
    headline = decoded.summary;
  } else {
    verdict = 'UNDERSTOOD';
    headline = `${decoded.summary} (no known risk flags matched)`;
  }

  const sortedFindings = sortFindingsBySeverity(findings);

  return {
    request,
    verdict,
    headline,
    decoded,
    findings: sortedFindings,
    limitations,
    onChain,
    networkLog,
    reputationVersion: getReputationVersion(),
  };
}
