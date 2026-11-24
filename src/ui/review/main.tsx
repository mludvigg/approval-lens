import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  buildPlainEnglishSummary,
  formatDeadline,
  formatTokenAmount,
  sortFindingsBySeverity,
} from '../../core/format';
import { checkMaliciousAddress, lookupKnownContract } from '../../core/reputation';
import { buildSanitizedReport, renderHtmlReport } from '../../core/report';
import type { DecodedAction, InspectionResult, Severity, UserDecision } from '../../core/types';
import {
  CheckIcon,
  ChevronIcon,
  CopyIcon,
  LockPrivacyIcon,
  OpticalCrestBrandmark,
  OpticalCrestCombo,
  SeverityIcon,
  ThemeToggleIcon,
  useTheme,
  VerdictIcon,
} from '../brand';
import '../styles.css';

const SEVERITY_LABELS: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High risk',
  MEDIUM: 'Review',
  LOW: 'Low risk',
  INFO: 'Verified local',
};

function getHumanRequestHeader(
  decoded: DecodedAction,
  originHost: string,
): { title: string; subtitle: string } {
  switch (decoded.kind) {
    case 'ERC20_APPROVE':
    case 'ERC20_INCREASE_ALLOWANCE':
      return {
        title: 'Spending cap request',
        subtitle: `${originHost} wants permission to withdraw your tokens`,
      };
    case 'ERC20_DECREASE_ALLOWANCE':
      return {
        title: 'Update spending cap',
        subtitle: `${originHost} is reducing an existing token allowance`,
      };
    case 'ERC20_TRANSFER':
    case 'ERC20_TRANSFER_FROM':
    case 'NATIVE_TRANSFER':
      return {
        title: 'Asset transfer request',
        subtitle: `${originHost} is requesting a direct transfer from your wallet`,
      };
    case 'NFT_SET_APPROVAL_FOR_ALL':
      return {
        title: 'NFT collection access request',
        subtitle: `${originHost} wants operator control over every NFT in this collection`,
      };
    case 'NFT_TRANSFER':
      return {
        title: 'NFT transfer request',
        subtitle: `${originHost} wants to transfer a specific NFT`,
      };
    case 'EIP2612_PERMIT':
    case 'PERMIT2_SINGLE':
    case 'PERMIT2_BATCH':
    case 'PERMIT2_TRANSFER_FROM':
      return {
        title: 'Gasless spending permit',
        subtitle: `${originHost} is requesting an off-chain token spending signature`,
      };
    case 'SEAPORT_ORDER':
      return {
        title: 'Marketplace listing signature',
        subtitle: `${originHost} is requesting an off-chain Seaport order authorizing asset transfers`,
      };
    case 'BLUR_ORDER':
      return {
        title:
          decoded.functionName === 'Blur.BulkOrderRoot'
            ? 'Bulk marketplace root signature'
            : 'Marketplace listing signature',
        subtitle: `${originHost} is requesting an off-chain Blur NFT order signature`,
      };
    case 'SOURCIFY_DECODED':
      return {
        title: 'Verified contract interaction',
        subtitle: `${originHost} is calling ${decoded.functionName ?? 'a verified function'} (decoded via Sourcify)`,
      };
    case 'MULTICALL':
      return {
        title: 'Bundled batch request',
        subtitle: `${originHost} is bundling ${decoded.subActions?.length ?? 'multiple'} operations in one call`,
      };
    case 'RAW_ETH_SIGN':
      return {
        title: 'Blind signature request',
        subtitle: `${originHost} is requesting an unformatted 32-byte hash signature`,
      };
    case 'PERSONAL_SIGN':
      return {
        title: 'Message signature request',
        subtitle: `${originHost} is requesting a text signature to verify ownership`,
      };
    case 'TYPED_DATA_GENERIC':
      return {
        title: 'Structured data signature',
        subtitle: `${originHost} is requesting an EIP-712 signature with a custom schema`,
      };
    case 'UNKNOWN_CALLDATA':
    default:
      return {
        title: 'Unverified contract request',
        subtitle: `${originHost} is calling a contract function that could not be decoded locally`,
      };
  }
}

function getImpactBannerHeadline(result: InspectionResult, riskCount: number): string {
  switch (result.verdict) {
    case 'KNOWN_MALICIOUS':
      return `${riskCount} ${riskCount === 1 ? 'risk' : 'risks'} detected · Known malicious indicator`;
    case 'HIGH_RISK':
      return `${riskCount} ${riskCount === 1 ? 'risk' : 'risks'} detected · High-risk permission`;
    case 'REVIEW_NEEDED':
      return `${riskCount} ${riskCount === 1 ? 'warning' : 'warnings'} detected · Review carefully`;
    case 'UNANALYZED':
      return 'Unverified contract call · Cannot confirm intent';
    case 'UNDERSTOOD':
    default:
      return 'Understood · No known risk flags matched';
  }
}

function downloadFile(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Split-Contrast Anti-Poisoning Address Display:
 * Emphasizes the leading 6 chars (0xBAd0) and trailing 4 chars (0Bad) in tabular monospace
 */
function SplitAddress({
  address,
  danger = false,
}: {
  address: string;
  danger?: boolean;
}) {
  if (!address || address.length < 12) {
    return <span className="addr-split">{address || '—'}</span>;
  }
  const edgeClass = danger ? 'addr-edge-danger' : 'addr-edge';
  return (
    <span className="addr-split" title={address}>
      <span className={edgeClass}>{address.slice(0, 6)}</span>
      <span className="addr-mid">…</span>
      <span className={edgeClass}>{address.slice(-4)}</span>
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1100);
  };

  return (
    <button
      type="button"
      className="copy-inline-btn"
      onClick={handleCopy}
      title={`Copy ${text}`}
    >
      {copied ? <CheckIcon size={11} /> : <CopyIcon size={11} />}
    </button>
  );
}

function ReviewApp() {
  const [theme, toggleTheme] = useTheme();
  const [result, setResult] = useState<InspectionResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [acknowledgedDanger, setAcknowledgedDanger] = useState(false);
  const [showTechDrawer, setShowTechDrawer] = useState(false);

  const requestId = new URLSearchParams(window.location.search).get('id') ?? '';

  useEffect(() => {
    if (!requestId) {
      setLoading(false);
      return;
    }
    chrome.runtime
      .sendMessage({ type: 'GET_PENDING_INSPECTION', requestId })
      .then((resp: { result?: InspectionResult | null } | undefined) => {
        setResult(resp?.result ?? null);
      })
      .finally(() => setLoading(false));
  }, [requestId]);

  const submitDecision = async (decision: UserDecision) => {
    if (!requestId || submitting) return;
    setSubmitting(true);
    await chrome.runtime.sendMessage({
      type: 'SUBMIT_DECISION',
      requestId,
      decision,
    });
    window.close();
  };

  if (loading) {
    return (
      <main className="app-shell">
        <div className="inspection-sheet">
          <header className="header">
            <OpticalCrestCombo markSize={22} wordScale={0.74} />
          </header>
          <p className="muted" style={{ margin: 0 }}>
            Inspecting wallet request locally…
          </p>
        </div>
      </main>
    );
  }

  if (!result) {
    return (
      <main className="app-shell">
        <div className="inspection-sheet">
          <header className="header">
            <OpticalCrestCombo markSize={22} wordScale={0.74} />
            <button
              type="button"
              className="icon-btn"
              onClick={toggleTheme}
              title="Switch Pastel Light / Dark theme"
            >
              <ThemeToggleIcon theme={theme} />
            </button>
          </header>
          <div className="card">
            <h1 style={{ fontSize: 15, marginTop: 0 }}>No active inspection found</h1>
            <p className="muted" style={{ marginBottom: 0 }}>
              This inspection has already completed or expired (fail-closed protection).
            </p>
          </div>
        </div>
      </main>
    );
  }

  const { request, decoded, limitations, onChain, networkLog } = result;
  const sortedFindings = sortFindingsBySeverity(result.findings);
  const riskCount = sortedFindings.filter((f) => f.severity !== 'INFO').length;
  const isUnderstood = result.verdict === 'UNDERSTOOD';
  const requiresDangerAck =
    result.verdict === 'KNOWN_MALICIOUS' ||
    sortedFindings.some((f) => f.severity === 'CRITICAL');

  const originHost = request.origin.replace(/^https?:\/\//, '');
  const reqHeader = getHumanRequestHeader(decoded, originHost);
  const impactHeadline = getImpactBannerHeadline(result, riskCount);
  const plainEnglishSummary = buildPlainEnglishSummary(result);

  const humanPermission = formatTokenAmount(
    decoded.amountRaw,
    onChain.tokenDecimals,
    onChain.tokenSymbol,
    decoded.isUnlimited,
    false,
  );
  const formattedExpiry = decoded.deadline ? formatDeadline(decoded.deadline) : null;

  const counterpartyAddr = decoded.spender ?? decoded.recipient;
  const badCounterparty = checkMaliciousAddress(counterpartyAddr);
  const knownCounterparty = lookupKnownContract(counterpartyAddr);

  const contractAddr = decoded.tokenAddress ?? decoded.targetContract;
  const knownContract = lookupKnownContract(contractAddr);

  const sameTargetAndToken =
    Boolean(decoded.targetContract) &&
    Boolean(decoded.tokenAddress) &&
    decoded.targetContract!.toLowerCase() === decoded.tokenAddress!.toLowerCase();

  const handleExportJson = () => {
    const report = buildSanitizedReport(result);
    downloadFile(
      `approval-lens-${request.requestId.slice(0, 8)}.json`,
      JSON.stringify(report, null, 2),
      'application/json',
    );
  };

  const handleExportHtml = () => {
    const report = buildSanitizedReport(result);
    downloadFile(
      `approval-lens-${request.requestId.slice(0, 8)}.html`,
      renderHtmlReport(report),
      'text/html',
    );
  };

  const renderForensicKeyValueGrid = () => (
    <>
      <div className="kv-grid" style={{ marginBottom: 10 }}>
        <span className="kv-label">Verified origin</span>
        <span className="kv-val mono">{request.origin}</span>

        {request.topLevelOrigin && (
          <>
            <span className="kv-label">Top-level page</span>
            <span className="kv-val mono">{request.topLevelOrigin}</span>
          </>
        )}

        <span className="kv-label">RPC method</span>
        <span className="kv-val mono">{request.method}</span>

        <span className="kv-label">Decoded ABI</span>
        <span className="kv-val mono">{decoded.functionName ?? decoded.kind}</span>

        {decoded.targetContract && (
          <>
            <span className="kv-label">
              {sameTargetAndToken ? 'Token & target' : 'Target contract'}
            </span>
            <span className="kv-val mono">{decoded.targetContract}</span>
          </>
        )}

        {decoded.tokenAddress && !sameTargetAndToken && (
          <>
            <span className="kv-label">Token contract</span>
            <span className="kv-val mono">{decoded.tokenAddress}</span>
          </>
        )}

        {decoded.spender && (
          <>
            <span className="kv-label">Spender address</span>
            <span className="kv-val mono">{decoded.spender}</span>
          </>
        )}

        {decoded.recipient && (
          <>
            <span className="kv-label">Recipient address</span>
            <span className="kv-val mono">{decoded.recipient}</span>
          </>
        )}

        {decoded.amountRaw !== undefined && (
          <>
            <span className="kv-label">Raw token units</span>
            <span className="kv-val mono">{decoded.amountRaw}</span>
          </>
        )}

        {decoded.deadline && (
          <>
            <span className="kv-label">Raw deadline</span>
            <span className="kv-val mono">
              {decoded.deadline} ({formatDeadline(decoded.deadline)})
            </span>
          </>
        )}

        <span className="kv-label">Frozen SHA-256</span>
        <span className="kv-val mono">{request.payloadHash}</span>
      </div>

      {decoded.rawPreview && (
        <div style={{ marginBottom: 10 }}>
          <div className="muted" style={{ fontSize: 11, marginBottom: 3 }}>
            Payload preview
          </div>
          <code>{decoded.rawPreview}</code>
        </div>
      )}

      <div className="section-header-row" style={{ marginTop: 8 }}>
        <span className="section-eyebrow">
          Network &amp; privacy audit ({networkLog.length})
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          <button type="button" className="btn-ghost" onClick={handleExportJson}>
            Export JSON
          </button>
          <button type="button" className="btn-ghost" onClick={handleExportHtml}>
            Export HTML
          </button>
        </div>
      </div>

      <ul className="list-plain">
        {networkLog.map((entry, idx) => (
          <li key={idx}>
            <code>[{entry.status}]</code> <code>{entry.target}</code> — {entry.purpose}
            {entry.detail ? ` (${entry.detail})` : ''}
          </li>
        ))}
      </ul>

      <div
        style={{
          marginTop: 10,
          paddingTop: 8,
          borderTop: '1px solid var(--divider)',
        }}
      >
        <div className="section-eyebrow" style={{ marginBottom: 4 }}>
          What Was NOT Analyzed
        </div>
        <ul className="list-plain">
          {limitations.map((item, idx) => (
            <li key={idx}>{item}</li>
          ))}
        </ul>
      </div>
    </>
  );

  return (
    <main className="app-shell">
      <div className="inspection-sheet">
        {/* Top Bar with Optical Crest Combination Mark */}
        <header className="header">
          <OpticalCrestCombo markSize={22} wordScale={0.74} />
          <div className="header-controls">
            <span className="pill pill-brand" title="Local static analysis by default">
              <LockPrivacyIcon size={11} />
              {onChain.rpcEnabled && decoded.abiSource
                ? 'RPC + ABI Lookup'
                : onChain.rpcEnabled
                  ? 'RPC Enriched'
                  : decoded.abiSource
                    ? 'Sourcify Lookup'
                    : 'Local · 0 RPC'}
            </span>
            <span className="pill">{request.walletName ?? 'EIP-1193'}</span>
            <button
              type="button"
              className="icon-btn"
              onClick={toggleTheme}
              title={`Switch to ${theme === 'dark' ? 'Pastel Light' : 'Pastel Dark'} mode`}
            >
              <ThemeToggleIcon theme={theme} />
            </button>
          </div>
        </header>

        {/* Request Intent Title + Primary Permission Badge */}
        <div className="request-title-bar">
          <div>
            <h1 className="request-title-main">{reqHeader.title}</h1>
            <p className="request-title-sub">{reqHeader.subtitle}</p>
          </div>
          {humanPermission !== '—' ? (
            <div
              className={`amount-badge ${
                result.verdict === 'KNOWN_MALICIOUS'
                  ? 'amount-badge-danger'
                  : decoded.isUnlimited
                    ? 'amount-badge-high'
                    : ''
              }`}
            >
              <OpticalCrestBrandmark size={15} />
              <span>{humanPermission}</span>
            </div>
          ) : (
            <OpticalCrestBrandmark size={26} />
          )}
        </div>

        {/* Responsive Workspace Grid: 1-Col in Compact Popup, 2-Col Workbench in Expanded Mode */}
        <div className="workspace-grid">
          {/* LEFT COLUMN: Unified Decision Card + Borderless Findings List */}
          <div className="workspace-col">
            <section className={`decision-card verdict-${result.verdict}`}>
              {/* Tinted Verdict & Consequence Strip */}
              <div className="impact-strip">
                <div className="crest-watermark">
                  <OpticalCrestBrandmark size={84} monochrome />
                </div>
                <div className="impact-header">
                  <VerdictIcon verdict={result.verdict} size={15} />
                  <span>{impactHeadline}</span>
                </div>
                <p className="impact-body">{plainEnglishSummary}</p>
              </div>

              {/* Hairline Key-Value Ledger Inside the Same Unified Card */}
              <div className="detail-ledger">
                {counterpartyAddr && (
                  <div className="detail-row">
                    <span className="detail-label">
                      {decoded.spender ? 'Spender' : 'Recipient'}
                    </span>
                    <span className="detail-val">
                      {badCounterparty ? (
                        <span className="inline-flag">Malicious drainer</span>
                      ) : knownCounterparty ? (
                        <span>{knownCounterparty.name.split(' (')[0]}</span>
                      ) : null}
                      <SplitAddress
                        address={counterpartyAddr}
                        danger={Boolean(badCounterparty)}
                      />
                      <CopyButton text={counterpartyAddr} />
                    </span>
                  </div>
                )}

                {contractAddr && (
                  <div className="detail-row">
                    <span className="detail-label">
                      {onChain.tokenSymbol ? 'Token contract' : 'Interacting with'}
                    </span>
                    <span className="detail-val">
                      {knownContract && <OpticalCrestBrandmark size={14} />}
                      {knownContract && <span>{knownContract.name.split(' (')[0]}</span>}
                      <SplitAddress address={contractAddr} />
                      <CopyButton text={contractAddr} />
                    </span>
                  </div>
                )}

                {formattedExpiry && (
                  <div className="detail-row">
                    <span className="detail-label">Deadline / Expiry</span>
                    <span className="detail-val">{formattedExpiry}</span>
                  </div>
                )}

                {decoded.seaportDetails && (
                  <div className="detail-row">
                    <span className="detail-label">Order balance</span>
                    <span className="detail-val">
                      {decoded.seaportDetails.zeroConsiderationToOfferer ? (
                        <span className="inline-flag">
                          You give {decoded.seaportDetails.offerCount} · Receive 0
                        </span>
                      ) : (
                        <span>
                          Offer {decoded.seaportDetails.offerCount} · Receive{' '}
                          {decoded.seaportDetails.offererConsiderationCount}
                        </span>
                      )}
                    </span>
                  </div>
                )}
              </div>
            </section>

            {/* Dynamically Decoded Arguments (Sourcify v2 / 4byte) */}
            {decoded.decodedArgs && decoded.decodedArgs.length > 0 && (
              <section className="findings-section">
                <div className="section-header-row">
                  <h2 className="section-eyebrow">
                    Decoded parameters ({decoded.decodedArgs.length})
                  </h2>
                </div>
                {decoded.decodedArgs.map((arg, idx) => (
                  <div className="sub-call" key={idx}>
                    <strong>{arg.name}</strong>{' '}
                    <span className="muted" style={{ fontSize: 11 }}>
                      ({arg.type})
                    </span>
                    : <span className="mono">{arg.value}</span>
                  </div>
                ))}
              </section>
            )}

            {/* Nested Multicall / Batch Operations (when applicable) */}
            {decoded.subActions && decoded.subActions.length > 0 && (
              <section className="findings-section">
                <div className="section-header-row">
                  <h2 className="section-eyebrow">
                    Nested operations ({decoded.subActions.length})
                  </h2>
                </div>
                {decoded.subActions.map((sub, idx) => (
                  <div className="sub-call" key={idx}>
                    <strong>#{idx + 1}</strong> {sub.summary}
                  </div>
                ))}
              </section>
            )}

            {/* Borderless Security Findings Ledger */}
            <section className="findings-section">
              <div className="section-header-row">
                <h2 className="section-eyebrow">
                  Security evidence ({sortedFindings.length})
                </h2>
                <button
                  type="button"
                  className="text-link-btn compact-only"
                  onClick={() => setShowTechDrawer((prev) => !prev)}
                  aria-expanded={showTechDrawer}
                >
                  <span>
                    {showTechDrawer ? 'Hide technical proof' : 'Technical proof & scope'}
                  </span>
                  <ChevronIcon open={showTechDrawer} size={13} />
                </button>
              </div>

              {sortedFindings.length === 0 ? (
                <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                  No local risk rules matched. Always verify the website domain and recipient
                  before signing.
                </p>
              ) : (
                <div className="findings-stack">
                  {sortedFindings.map((f, i) => (
                    <div className={`finding-row finding-${f.severity}`} key={`${f.id}-${i}`}>
                      <div className="finding-head">
                        <div className="finding-title-wrap">
                          <SeverityIcon severity={f.severity} size={15} />
                          <span className="finding-title">{f.title}</span>
                        </div>
                        <span className="sev-label">{SEVERITY_LABELS[f.severity]}</span>
                      </div>
                      <p className="finding-desc">{f.explanation}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* Compact Mode: Spatially Continuous CSS-Grid Drawer + Quiet 1-Line Scope Summary */}
              <div className="compact-only">
                <div className={`drawer-grid ${showTechDrawer ? 'open' : ''}`}>
                  <div className="drawer-inner">
                    <div className="forensic-ledger" style={{ marginTop: 8 }}>
                      {renderForensicKeyValueGrid()}
                    </div>
                  </div>
                </div>
                {!showTechDrawer && (
                  <div className="compact-scope-line" title={limitations.join(' ')}>
                    <span>⊘ No EVM simulation</span>
                    <span>·</span>
                    <span>⊘ Never 100% safe</span>
                    <span>·</span>
                    <span>
                      {onChain.rpcEnabled ? '🌐 Opt-in RPC active' : '🔒 0 network calls'}
                    </span>
                  </div>
                )}
              </div>
            </section>
          </div>

          {/* RIGHT COLUMN (Expanded Mode >= 720px): Always-Open Forensic Evidence & Scope Ledger */}
          <div className="workspace-col expanded-only">
            <section className="forensic-ledger">
              <div className="forensic-header">
                <h2 className="forensic-title">Forensic Evidence &amp; Scope Ledger</h2>
                <span className="mono" style={{ fontSize: 11, color: 'var(--brand)' }}>
                  SHA-256 Frozen
                </span>
              </div>
              {renderForensicKeyValueGrid()}
            </section>
          </div>
        </div>

        {/* Context-Aware Decision Footer */}
        <footer className="actions-bar">
          {requiresDangerAck && (
            <label className="ack-box">
              <input
                type="checkbox"
                checked={acknowledgedDanger}
                onChange={(e) => setAcknowledgedDanger(e.target.checked)}
              />
              <span>
                I understand this request triggered a critical warning and may drain my assets
                if signed.
              </span>
            </label>
          )}
          <div className="btn-row">
            <button
              type="button"
              className={isUnderstood ? 'btn-block-calm' : 'btn-block-danger'}
              disabled={submitting}
              onClick={() => submitDecision('BLOCK')}
            >
              {isUnderstood ? 'Block request' : 'Block request (Recommended)'}
            </button>
            <button
              type="button"
              className={isUnderstood ? 'btn-allow-brand' : 'btn-allow-cautious'}
              disabled={submitting || (requiresDangerAck && !acknowledgedDanger)}
              onClick={() => submitDecision('ALLOW')}
            >
              Proceed to wallet
            </button>
          </div>
        </footer>
      </div>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ReviewApp />
  </React.StrictMode>,
);
