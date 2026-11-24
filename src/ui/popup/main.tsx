import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { buildSanitizedReport, renderHtmlReport } from '../../core/report';
import type { ExtensionSettings, HistoryRecord } from '../../core/types';
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

function PopupApp() {
  const [settings, setSettings] = useState<ExtensionSettings>({
    enabled: true,
    rpcEnrichmentEnabled: false,
    customRpcUrl: '',
  });
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [rpcDraft, setRpcDraft] = useState('');
  const [savedNotice, setSavedNotice] = useState(false);

  const loadState = () => {
    chrome.runtime
      .sendMessage({ type: 'GET_STATE' })
      .then((resp: { settings?: ExtensionSettings; history?: HistoryRecord[] } | undefined) => {
        if (resp?.settings) {
          setSettings(resp.settings);
          setRpcDraft(resp.settings.customRpcUrl);
        }
        if (resp?.history) {
          setHistory(resp.history);
        }
      });
  };

  useEffect(() => {
    loadState();
  }, []);

  const updateSettings = async (patch: Partial<ExtensionSettings>) => {
    const resp = (await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: patch,
    })) as { settings?: ExtensionSettings } | undefined;
    if (resp?.settings) {
      setSettings(resp.settings);
      setSavedNotice(true);
      setTimeout(() => setSavedNotice(false), 1200);
    }
  };

  const clearHistory = async () => {
    await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' });
    setHistory([]);
  };

  return (
    <main className="popup-shell">
      <header className="header">
        <div className="brand">
          <span
            className="brand-dot"
            style={{
              background: settings.enabled ? '#38bdf8' : '#64748b',
              boxShadow: settings.enabled ? '0 0 10px rgba(56,189,248,0.6)' : 'none',
            }}
          />
          <h1>Approval Lens</h1>
        </div>
        <span className="pill">{settings.enabled ? 'Active' : 'Paused'}</span>
      </header>

      <section className="card">
        <h2 className="card-title">Protection &amp; Privacy Controls</h2>

        <label className="toggle-row">
          <span>
            <strong>Intercept wallet requests</strong>
            <div className="muted" style={{ fontSize: 11 }}>
              Inspect approvals &amp; signatures before MetaMask/Rabby opens
            </div>
          </span>
          <input
            type="checkbox"
            checked={settings.enabled}
            onChange={(e) => updateSettings({ enabled: e.target.checked })}
          />
        </label>

        <label className="toggle-row">
          <span>
            <strong>On-chain RPC enrichment</strong>
            <div className="muted" style={{ fontSize: 11 }}>
              Off = 100% local (0 network requests). On = reads allowance, token info &amp; proxy slot.
            </div>
          </span>
          <input
            type="checkbox"
            checked={settings.rpcEnrichmentEnabled}
            onChange={(e) =>
              updateSettings({ rpcEnrichmentEnabled: e.target.checked })
            }
          />
        </label>

        {settings.rpcEnrichmentEnabled && (
          <div style={{ marginTop: 6 }}>
            <div className="muted" style={{ fontSize: 11 }}>
              Optional custom RPC URL (leave blank for publicnode defaults)
            </div>
            <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
              <input
                className="input-text"
                style={{ marginTop: 0 }}
                type="url"
                placeholder="https://ethereum-sepolia-rpc.publicnode.com"
                value={rpcDraft}
                onChange={(e) => setRpcDraft(e.target.value)}
              />
              <button
                className="btn-ghost"
                onClick={() => updateSettings({ customRpcUrl: rpcDraft.trim() })}
              >
                Save
              </button>
            </div>
          </div>
        )}

        {savedNotice && (
          <div style={{ color: '#38bdf8', fontSize: 11, marginTop: 6 }}>
            Settings updated.
          </div>
        )}
      </section>

      <section className="card" style={{ marginBottom: 0 }}>
        <div className="header" style={{ marginBottom: 8 }}>
          <h2 className="card-title" style={{ margin: 0 }}>
            Session History ({history.length})
          </h2>
          {history.length > 0 && (
            <button className="btn-ghost" onClick={clearHistory}>
              Clear
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>
            No requests inspected in this browser session yet. Trigger a transaction or
            signature on any dApp (or the local Attack Test Lab) to inspect it here.
          </p>
        ) : (
          history.slice(0, 8).map((item) => {
            const report = buildSanitizedReport(item.result, item.decision);
            return (
              <div className="history-item" key={item.requestId}>
                <div className="history-top">
                  <span className="pill">{item.verdict}</span>
                  <span
                    className="pill"
                    style={{
                      color: item.decision === 'BLOCK' ? '#fca5a5' : '#7dd3fc',
                    }}
                  >
                    {item.decision}
                  </span>
                </div>
                <div style={{ fontSize: 12, marginBottom: 4 }}>{item.headline}</div>
                <div className="muted mono" style={{ fontSize: 10.5, marginBottom: 6 }}>
                  {item.origin} · {item.method}
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    className="btn-ghost"
                    onClick={() =>
                      downloadFile(
                        `approval-lens-${item.requestId.slice(0, 8)}.json`,
                        JSON.stringify(report, null, 2),
                        'application/json',
                      )
                    }
                  >
                    JSON
                  </button>
                  <button
                    className="btn-ghost"
                    onClick={() =>
                      downloadFile(
                        `approval-lens-${item.requestId.slice(0, 8)}.html`,
                        renderHtmlReport(report),
                        'text/html',
                      )
                    }
                  >
                    HTML
                  </button>
                </div>
              </div>
            );
          })
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <PopupApp />
  </React.StrictMode>,
);
