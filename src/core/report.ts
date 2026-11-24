import type { InspectionResult, UserDecision } from './types';

export interface SanitizedReport {
  schema: 'approval-lens-report/v1';
  generatedAt: string;
  reputationVersion: string;
  decision?: UserDecision;
  verdict: InspectionResult['verdict'];
  headline: string;
  origin: string;
  topLevelOrigin?: string;
  walletName?: string;
  method: InspectionResult['request']['method'];
  chainIdHex?: string;
  payloadHash: string;
  decoded: InspectionResult['decoded'];
  findings: InspectionResult['findings'];
  limitations: string[];
  onChain: InspectionResult['onChain'];
  networkLog: InspectionResult['networkLog'];
  redactionNotice: string;
}

function redactAddress(addr?: string): string | undefined {
  if (!addr || !/^0x[0-9a-fA-F]{40}$/.test(addr)) return addr;
  return `${addr.slice(0, 6)}...${addr.slice(-4)} (redacted)`;
}

function sanitizeOrigin(urlOrOrigin: string): string {
  try {
    return new URL(urlOrOrigin).origin;
  } catch {
    return urlOrOrigin.split('?')[0].split('#')[0];
  }
}

export function buildSanitizedReport(
  result: InspectionResult,
  decision?: UserDecision,
): SanitizedReport {
  const sanitizedDecoded = {
    ...result.decoded,
    owner: redactAddress(result.decoded.owner),
  };

  return {
    schema: 'approval-lens-report/v1',
    generatedAt: new Date().toISOString(),
    reputationVersion: result.reputationVersion,
    decision,
    verdict: result.verdict,
    headline: result.headline,
    origin: sanitizeOrigin(result.request.origin),
    topLevelOrigin: result.request.topLevelOrigin
      ? sanitizeOrigin(result.request.topLevelOrigin)
      : undefined,
    walletName: result.request.walletName,
    method: result.request.method,
    chainIdHex: result.request.chainIdHex,
    payloadHash: result.request.payloadHash,
    decoded: sanitizedDecoded,
    findings: result.findings,
    limitations: result.limitations,
    onChain: result.onChain,
    networkLog: result.networkLog,
    redactionNotice:
      'User wallet address (owner) redacted and URL query/fragment parameters stripped by default.',
  };
}

export function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function renderHtmlReport(report: SanitizedReport): string {
  const findingsHtml =
    report.findings.length === 0
      ? '<p>No risk rules triggered.</p>'
      : `<ul>${report.findings
          .map(
            (f) =>
              `<li><strong>[${escapeHtml(f.severity)}] ${escapeHtml(f.title)}</strong> (${escapeHtml(f.source)})<br/><span>${escapeHtml(f.explanation)}</span></li>`,
          )
          .join('')}</ul>`;

  const limitationsHtml = `<ul>${report.limitations
    .map((l) => `<li>${escapeHtml(l)}</li>`)
    .join('')}</ul>`;

  const networkHtml = `<ul>${report.networkLog
    .map(
      (n) =>
        `<li><code>${escapeHtml(n.status)}</code> ${escapeHtml(n.target)} — ${escapeHtml(n.purpose)}</li>`,
    )
    .join('')}</ul>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Approval Lens Report — ${escapeHtml(report.verdict)}</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #0b1120; color: #e2e8f0; max-width: 820px; margin: 32px auto; padding: 0 20px; line-height: 1.5; }
  .card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 16px 20px; margin-bottom: 16px; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 13px; background: #1e293b; color: #38bdf8; }
  code { background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 12px; word-break: break-all; }
  h1, h2 { margin-top: 0; }
  li { margin-bottom: 8px; }
</style>
</head>
<body>
  <h1>Approval Lens — Sanitized Inspection Report</h1>
  <div class="card">
    <div class="badge">${escapeHtml(report.verdict)}</div>
    <p><strong>${escapeHtml(report.headline)}</strong></p>
    <p>Origin: <code>${escapeHtml(report.origin)}</code> | Method: <code>${escapeHtml(report.method)}</code> | Decision: <code>${escapeHtml(report.decision ?? 'PENDING')}</code></p>
    <p>Payload SHA-256: <code>${escapeHtml(report.payloadHash)}</code></p>
    <p>Generated: ${escapeHtml(report.generatedAt)} | Local Intel: <code>${escapeHtml(report.reputationVersion)}</code></p>
  </div>
  <div class="card">
    <h2>Decoded Action</h2>
    <p>Kind: <code>${escapeHtml(report.decoded.kind)}</code></p>
    <p>${escapeHtml(report.decoded.summary)}</p>
    ${report.decoded.spender ? `<p>Spender: <code>${escapeHtml(report.decoded.spender)}</code></p>` : ''}
    ${report.decoded.targetContract ? `<p>Target Contract: <code>${escapeHtml(report.decoded.targetContract)}</code></p>` : ''}
    ${report.decoded.amountRaw ? `<p>Amount (raw): <code>${escapeHtml(report.decoded.amountRaw)}</code></p>` : ''}
  </div>
  <div class="card">
    <h2>Risk Findings &amp; Evidence</h2>
    ${findingsHtml}
  </div>
  <div class="card">
    <h2>What Was NOT Analyzed</h2>
    ${limitationsHtml}
  </div>
  <div class="card">
    <h2>Network &amp; Privacy Log</h2>
    ${networkHtml}
    <p style="color:#94a3b8;font-size:12px;">${escapeHtml(report.redactionNotice)}</p>
  </div>
</body>
</html>`;
}
