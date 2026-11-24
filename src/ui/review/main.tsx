import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  buildPlainEnglishSummary,
  formatDeadline,
  formatTokenAmount,
  sortFindingsBySeverity,
} from '../../core/format';
import {
  getLocalizedImpactHeadline,
  getLocalizedRequestHeader,
  getMessages,
  localizeFinding,
  localizeLimitation,
} from '../../core/i18n';
import { checkMaliciousAddress, lookupKnownContract } from '../../core/reputation';
import { buildSanitizedReport, renderHtmlReport } from '../../core/report';
import type { InspectionResult, UserDecision } from '../../core/types';
import {
  CheckIcon,
  ChevronIcon,
  CopyIcon,
  LocaleSwitcher,
  LockPrivacyIcon,
  OpticalCrestBrandmark,
  OpticalCrestCombo,
  SeverityIcon,
  ThemeToggleIcon,
  useLocale,
  useTheme,
  VerdictIcon,
} from '../brand';
import '../styles.css';

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

function CopyButton({ text, title }: { text: string; title: string }) {
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
      title={title}
    >
      {copied ? <CheckIcon size={11} /> : <CopyIcon size={11} />}
    </button>
  );
}

function ReviewApp() {
  const [theme, toggleTheme] = useTheme();
  const [locale, setLocale] = useLocale();
  const msg = getMessages(locale);

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
            <div className="header-controls">
              <LocaleSwitcher locale={locale} onChange={setLocale} />
            </div>
          </header>
          <p className="muted" style={{ margin: 0 }}>
            {msg.loadingInspection}
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
            <div className="header-controls">
              <LocaleSwitcher locale={locale} onChange={setLocale} />
              <button
                type="button"
                className="icon-btn"
                onClick={toggleTheme}
                title={msg.themeSwitchTitle(theme === 'dark' ? 'light' : 'dark')}
              >
                <ThemeToggleIcon theme={theme} />
              </button>
            </div>
          </header>
          <div className="card">
            <h1 style={{ fontSize: 15, marginTop: 0 }}>{msg.expiredTitle}</h1>
            <p className="muted" style={{ marginBottom: 0 }}>
              {msg.expiredDesc}
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
  const reqHeader = getLocalizedRequestHeader(decoded, originHost, locale);
  const impactHeadline = getLocalizedImpactHeadline(result, riskCount, locale);
  const plainEnglishSummary = buildPlainEnglishSummary(result, locale);

  const humanPermission = formatTokenAmount(
    decoded.amountRaw,
    onChain.tokenDecimals,
    onChain.tokenSymbol,
    decoded.isUnlimited,
    false,
    locale,
  );
  const formattedExpiry = decoded.deadline ? formatDeadline(decoded.deadline, locale) : null;

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
        <span className="kv-label">{msg.kvVerifiedOrigin}</span>
        <span className="kv-val mono">{request.origin}</span>

        {request.topLevelOrigin && (
          <>
            <span className="kv-label">{msg.kvTopLevelPage}</span>
            <span className="kv-val mono">{request.topLevelOrigin}</span>
          </>
        )}

        <span className="kv-label">{msg.kvRpcMethod}</span>
        <span className="kv-val mono">{request.method}</span>

        <span className="kv-label">{msg.kvDecodedAbi}</span>
        <span className="kv-val mono">{decoded.functionName ?? decoded.kind}</span>

        {decoded.targetContract && (
          <>
            <span className="kv-label">
              {sameTargetAndToken ? msg.kvTokenAndTarget : msg.kvTargetContract}
            </span>
            <span className="kv-val mono">{decoded.targetContract}</span>
          </>
        )}

        {decoded.tokenAddress && !sameTargetAndToken && (
          <>
            <span className="kv-label">{msg.kvTokenContract}</span>
            <span className="kv-val mono">{decoded.tokenAddress}</span>
          </>
        )}

        {decoded.spender && (
          <>
            <span className="kv-label">{msg.kvSpenderAddress}</span>
            <span className="kv-val mono">{decoded.spender}</span>
          </>
        )}

        {decoded.recipient && (
          <>
            <span className="kv-label">{msg.kvRecipientAddress}</span>
            <span className="kv-val mono">{decoded.recipient}</span>
          </>
        )}

        {decoded.amountRaw !== undefined && (
          <>
            <span className="kv-label">{msg.kvRawUnits}</span>
            <span className="kv-val mono">{decoded.amountRaw}</span>
          </>
        )}

        {decoded.deadline && (
          <>
            <span className="kv-label">{msg.kvRawDeadline}</span>
            <span className="kv-val mono">
              {decoded.deadline} ({formatDeadline(decoded.deadline, locale)})
            </span>
          </>
        )}

        <span className="kv-label">{msg.kvFrozenSha256}</span>
        <span className="kv-val mono">{request.payloadHash}</span>
      </div>

      {decoded.rawPreview && (
        <div style={{ marginBottom: 10 }}>
          <div className="muted" style={{ fontSize: 11, marginBottom: 3 }}>
            {msg.payloadPreview}
          </div>
          <code>{decoded.rawPreview}</code>
        </div>
      )}

      <div className="section-header-row" style={{ marginTop: 8 }}>
        <span className="section-eyebrow">
          {msg.networkAuditHeading(networkLog.length)}
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          <button type="button" className="btn-ghost" onClick={handleExportJson}>
            {msg.exportJson}
          </button>
          <button type="button" className="btn-ghost" onClick={handleExportHtml}>
            {msg.exportHtml}
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
          {msg.notAnalyzedHeading}
        </div>
        <ul className="list-plain">
          {limitations.map((item, idx) => (
            <li key={idx}>{localizeLimitation(item, locale)}</li>
          ))}
        </ul>
      </div>
    </>
  );

  const privacyBadgeLabel =
    onChain.rpcEnabled && decoded.abiSource
      ? msg.rpcAndAbiPill
      : onChain.rpcEnabled
        ? msg.rpcEnrichedPill
        : decoded.abiSource
          ? msg.sourcifyLookupPill
          : msg.localZeroRpcPill;

  return (
    <main className="app-shell">
      <div className="inspection-sheet">
        {/* Top Bar with Optical Crest Combination Mark & Live EN / PT / ES Switcher */}
        <header className="header">
          <OpticalCrestCombo markSize={22} wordScale={0.72} />
          <div className="header-controls">
            <LocaleSwitcher locale={locale} onChange={setLocale} />
            <span className="pill pill-brand" title={msg.heroLocalSubtitle}>
              <LockPrivacyIcon size={11} />
              {privacyBadgeLabel}
            </span>
            <span className="pill">{request.walletName ?? 'EIP-1193'}</span>
            <button
              type="button"
              className="icon-btn"
              onClick={toggleTheme}
              title={msg.themeSwitchTitle(theme === 'dark' ? 'light' : 'dark')}
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
                      {decoded.spender ? msg.spenderLabel : msg.recipientLabel}
                    </span>
                    <span className="detail-val">
                      {badCounterparty ? (
                        <span className="inline-flag">{msg.maliciousDrainerFlag}</span>
                      ) : knownCounterparty ? (
                        <span>{knownCounterparty.name.split(' (')[0]}</span>
                      ) : null}
                      <SplitAddress
                        address={counterpartyAddr}
                        danger={Boolean(badCounterparty)}
                      />
                      <CopyButton
                        text={counterpartyAddr}
                        title={msg.copyTitle(counterpartyAddr)}
                      />
                    </span>
                  </div>
                )}

                {contractAddr && (
                  <div className="detail-row">
                    <span className="detail-label">
                      {onChain.tokenSymbol ? msg.tokenContractLabel : msg.interactingWithLabel}
                    </span>
                    <span className="detail-val">
                      {knownContract && <OpticalCrestBrandmark size={14} />}
                      {knownContract && <span>{knownContract.name.split(' (')[0]}</span>}
                      <SplitAddress address={contractAddr} />
                      <CopyButton text={contractAddr} title={msg.copyTitle(contractAddr)} />
                    </span>
                  </div>
                )}

                {formattedExpiry && (
                  <div className="detail-row">
                    <span className="detail-label">{msg.deadlineLabel}</span>
                    <span className="detail-val">{formattedExpiry}</span>
                  </div>
                )}

                {decoded.seaportDetails && (
                  <div className="detail-row">
                    <span className="detail-label">{msg.orderBalanceLabel}</span>
                    <span className="detail-val">
                      {decoded.seaportDetails.zeroConsiderationToOfferer ? (
                        <span className="inline-flag">
                          {msg.seaportZeroBadge(decoded.seaportDetails.offerCount)}
                        </span>
                      ) : (
                        <span>
                          {msg.seaportPaidBadge(
                            decoded.seaportDetails.offerCount,
                            decoded.seaportDetails.offererConsiderationCount,
                          )}
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
                    {msg.decodedParamsHeading(decoded.decodedArgs.length)}
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
                    {msg.nestedOpsHeading(decoded.subActions.length)}
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
                  {msg.securityEvidenceHeading(sortedFindings.length)}
                </h2>
                <button
                  type="button"
                  className="text-link-btn compact-only"
                  onClick={() => setShowTechDrawer((prev) => !prev)}
                  aria-expanded={showTechDrawer}
                >
                  <span>{showTechDrawer ? msg.hideTechProof : msg.showTechProof}</span>
                  <ChevronIcon open={showTechDrawer} size={13} />
                </button>
              </div>

              {sortedFindings.length === 0 ? (
                <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                  {msg.noRiskRulesMatched}
                </p>
              ) : (
                <div className="findings-stack">
                  {sortedFindings.map((f, i) => {
                    const locFinding = localizeFinding(f, locale);
                    return (
                      <div className={`finding-row finding-${f.severity}`} key={`${f.id}-${i}`}>
                        <div className="finding-head">
                          <div className="finding-title-wrap">
                            <SeverityIcon severity={f.severity} size={15} />
                            <span className="finding-title">{locFinding.title}</span>
                          </div>
                          <span className="sev-label">{msg.severityLabels[f.severity]}</span>
                        </div>
                        <p className="finding-desc">{locFinding.explanation}</p>
                      </div>
                    );
                  })}
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
                  <div
                    className="compact-scope-line"
                    title={limitations.map((l) => localizeLimitation(l, locale)).join(' ')}
                  >
                    <span>{msg.scopeNoSim}</span>
                    <span>·</span>
                    <span>{msg.scopeNeverSafe}</span>
                    <span>·</span>
                    <span>
                      {onChain.rpcEnabled ? msg.scopeOptInRpc : msg.scopeZeroCalls}
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
                <h2 className="forensic-title">{msg.forensicHeading}</h2>
                <span className="mono" style={{ fontSize: 11, color: 'var(--brand)' }}>
                  {msg.sha256Frozen}
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
              <span>{msg.dangerAckCheckbox}</span>
            </label>
          )}
          <div className="btn-row">
            <button
              type="button"
              className={isUnderstood ? 'btn-block-calm' : 'btn-block-danger'}
              disabled={submitting}
              onClick={() => submitDecision('BLOCK')}
            >
              {isUnderstood ? msg.blockRequestCalm : msg.blockRequestRecommended}
            </button>
            <button
              type="button"
              className={isUnderstood ? 'btn-allow-brand' : 'btn-allow-cautious'}
              disabled={submitting || (requiresDangerAck && !acknowledgedDanger)}
              onClick={() => submitDecision('ALLOW')}
            >
              {msg.proceedToWallet}
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
