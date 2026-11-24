import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { formatUnits } from 'viem';
import { buildSanitizedReport, renderHtmlReport } from '../../core/report';
import type { InspectionResult, UserDecision } from '../../core/types';
import '../styles.css';

const VERDICT_LABELS: Record<InspectionResult['verdict'], string> = {
  KNOWN_MALICIOUS: 'Known Malicious Indicator',
  HIGH_RISK: 'High-Risk Permission',
  REVIEW_NEEDED: 'Review Needed',
  UNANALYZED: 'Unanalyzed / Opaque Payload',
  UNDERSTOOD: 'Understood — No Known Flags',
};

function formatAmount(raw?: string, decimals?: number, symbol?: string, isUnlimited?: boolean): string {
  if (isUnlimited) {
    return `UNLIMITED${symbol ? ` ${symbol}` : ''} (raw: ${raw ?? 'MAX'})`;
  }
  if (!raw) return '—';
  if (decimals !== undefined) {
    try {
      const formatted = formatUnits(BigInt(raw), decimals);
      return `${formatted}${symbol ? ` ${symbol}` : ''} (raw: ${raw})`;
    } catch {
      return raw;
    }
  }
  return `${raw} raw units`;
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

function ReviewApp() {
  const [result, setResult] = useState<InspectionResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [acknowledgedDanger, setAcknowledgedDanger] = useState(false);

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
        <p className="muted">Analyzing wallet request…</p>
      </main>
    );
  }

  if (!result) {
    return (
      <main className="app-shell">
        <div className="card">
          <h1 style={{ fontSize: 15, marginTop: 0 }}>No active inspection found</h1>
          <p className="muted">
            This inspection may have already completed or expired (fail-closed).
          </p>
        </div>
      </main>
    );
  }

  const { request, decoded, findings, limitations, onChain, networkLog } = result;
  const requiresDangerAck =
    result.verdict === 'KNOWN_MALICIOUS' ||
    findings.some((f) => f.severity === 'CRITICAL');

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

  return (
    <main className="app-shell">
      <header className="header">
        <div className="brand">
          <span className="brand-dot" />
          <h1>Approval Lens</h1>
        </div>
        <span className="pill">{request.walletName ?? 'EIP-1193'}</span>
      </header>

      <section className={`verdict-banner verdict-${result.verdict}`}>
        <div className="verdict-tag">{VERDICT_LABELS[result.verdict]}</div>
        <p className="verdict-headline">{result.headline}</p>
      </section>

      <section className="card">
        <h2 className="card-title">Request Context</h2>
        <div className="kv-grid">
          <span className="kv-label">Verified Origin</span>
          <span className="kv-val mono">{request.origin}</span>

          {request.topLevelOrigin && (
            <>
              <span className="kv-label">Top-Level Page</span>
              <span className="kv-val mono">{request.topLevelOrigin}</span>
            </>
          )}

          <span className="kv-label">RPC Method</span>
          <span className="kv-val mono">{request.method}</span>

          <span className="kv-label">Action Type</span>
          <span className="kv-val mono">
            {decoded.functionName ?? decoded.kind}
          </span>

          {decoded.targetContract && (
            <>
              <span className="kv-label">Target Contract</span>
              <span className="kv-val mono">{decoded.targetContract}</span>
            </>
          )}

          {decoded.tokenAddress && decoded.tokenAddress !== decoded.targetContract && (
            <>
              <span className="kv-label">Token</span>
              <span className="kv-val mono">{decoded.tokenAddress}</span>
            </>
          )}

          {decoded.spender && (
            <>
              <span className="kv-label">Spender / Operator</span>
              <span className="kv-val mono">{decoded.spender}</span>
            </>
          )}

          {decoded.recipient && (
            <>
              <span className="kv-label">Recipient</span>
              <span className="kv-val mono">{decoded.recipient}</span>
            </>
          )}

          {(decoded.amountRaw !== undefined || decoded.isUnlimited) && (
            <>
              <span className="kv-label">New Permission</span>
              <span className="kv-val">
                {formatAmount(
                  decoded.amountRaw,
                  onChain.tokenDecimals,
                  onChain.tokenSymbol,
                  decoded.isUnlimited,
                )}
              </span>
            </>
          )}

          {onChain.currentAllowanceRaw !== undefined && (
            <>
              <span className="kv-label">Previous Allowance</span>
              <span className="kv-val">
                {formatAmount(
                  onChain.currentAllowanceRaw,
                  onChain.tokenDecimals,
                  onChain.tokenSymbol,
                  false,
                )}
              </span>
            </>
          )}

          {decoded.deadline && (
            <>
              <span className="kv-label">Deadline / Expiry</span>
              <span className="kv-val mono">{decoded.deadline}</span>
            </>
          )}

          <span className="kv-label">Frozen SHA-256</span>
          <span className="kv-val mono">{request.payloadHash.slice(0, 24)}…</span>
        </div>
      </section>

      {decoded.subActions && decoded.subActions.length > 0 && (
        <section className="card">
          <h2 className="card-title">
            Nested Operations ({decoded.subActions.length})
          </h2>
          {decoded.subActions.map((sub, idx) => (
            <div className="sub-call" key={idx}>
              <div>
                <strong>#{idx + 1}</strong> <code>{sub.functionName ?? sub.kind}</code>
              </div>
              <div className="muted">{sub.summary}</div>
              {sub.spender && (
                <div>
                  Spender: <code>{sub.spender}</code>
                </div>
              )}
            </div>
          ))}
        </section>
      )}

      {decoded.rawPreview && (
        <section className="card">
          <h2 className="card-title">Payload Preview</h2>
          <code>{decoded.rawPreview}</code>
        </section>
      )}

      {onChain.rpcEnabled && (
        <section className="card">
          <h2 className="card-title">On-Chain Context</h2>
          <div className="kv-grid">
            <span className="kv-label">Token Metadata</span>
            <span className="kv-val">
              {onChain.tokenSymbol
                ? `${onChain.tokenSymbol} (${onChain.tokenDecimals ?? '?'} decimals)`
                : 'Not resolved'}
            </span>
            <span className="kv-label">Spender Type</span>
            <span className="kv-val">
              {onChain.spenderIsContract === true
                ? 'Smart Contract'
                : onChain.spenderIsContract === false
                  ? 'EOA (Regular Wallet — Unusual Spender)'
                  : 'Not checked'}
            </span>
            <span className="kv-label">EIP-1967 Proxy</span>
            <span className="kv-val mono">
              {onChain.targetIsProxy
                ? `Yes -> ${onChain.proxyImplementation}`
                : onChain.targetIsProxy === false
                  ? 'No EIP-1967 proxy slot'
                  : 'Not checked'}
            </span>
          </div>
        </section>
      )}

      <section className="card">
        <h2 className="card-title">Findings &amp; Evidence ({findings.length})</h2>
        {findings.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>
            No local risk rules matched. Still verify the website URL and recipient before signing.
          </p>
        ) : (
          findings.map((f, i) => (
            <div className={`finding-item finding-${f.severity}`} key={`${f.id}-${i}`}>
              <div className="finding-head">
                <span className="finding-title">
                  [{f.severity}] {f.title}
                </span>
                <span className="source-chip">{f.source}</span>
              </div>
              <p className="finding-desc">{f.explanation}</p>
            </div>
          ))
        )}
      </section>

      <section className="card">
        <h2 className="card-title">What Was NOT Analyzed</h2>
        <ul className="list-plain">
          {limitations.map((item, idx) => (
            <li key={idx}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="card">
        <div className="header" style={{ marginBottom: 6 }}>
          <h2 className="card-title" style={{ margin: 0 }}>
            Network &amp; Privacy Log ({networkLog.length})
          </h2>
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="btn-ghost" onClick={handleExportJson}>
              Export JSON
            </button>
            <button className="btn-ghost" onClick={handleExportHtml}>
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
        <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
          Local intel bundle: <code>{result.reputationVersion}</code>
        </div>
      </section>

      <footer className="actions-bar">
        {requiresDangerAck && (
          <label className="ack-box">
            <input
              type="checkbox"
              checked={acknowledgedDanger}
              onChange={(e) => setAcknowledgedDanger(e.target.checked)}
            />
            <span>
              I understand this request triggered a <strong>CRITICAL</strong> warning and
              may drain my assets if signed.
            </span>
          </label>
        )}
        <div className="btn-row">
          <button
            className="btn-block"
            disabled={submitting}
            onClick={() => submitDecision('BLOCK')}
          >
            Block Request
          </button>
          <button
            className="btn-allow"
            disabled={submitting || (requiresDangerAck && !acknowledgedDanger)}
            onClick={() => submitDecision('ALLOW')}
          >
            Proceed to Wallet
          </button>
        </div>
      </footer>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ReviewApp />
  </React.StrictMode>,
);
