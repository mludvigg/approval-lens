import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { buildPlainEnglishSummary } from '../../core/format';
import { getMessages } from '../../core/i18n';
import { buildSanitizedReport, renderHtmlReport } from '../../core/report';
import type { ExtensionSettings, HistoryRecord } from '../../core/types';
import {
  LocaleSwitcher,
  LockPrivacyIcon,
  OpticalCrestBrandmark,
  OpticalCrestCombo,
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

function PopupApp() {
  const [theme, toggleTheme] = useTheme();
  const [locale, setLocale] = useLocale();
  const msg = getMessages(locale);

  const [settings, setSettings] = useState<ExtensionSettings>({
    enabled: true,
    rpcEnrichmentEnabled: false,
    abiLookupEnabled: false,
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

  const activeNetFeatures = [
    settings.rpcEnrichmentEnabled ? msg.featureRpc : null,
    settings.abiLookupEnabled ? msg.featureSourcify : null,
  ]
    .filter(Boolean)
    .join(' + ');

  return (
    <main className="popup-shell">
      <header className="header">
        <OpticalCrestCombo markSize={22} wordScale={0.72} />
        <div className="header-controls">
          <LocaleSwitcher locale={locale} onChange={setLocale} />
          <span className={`pill ${settings.enabled ? 'pill-brand' : ''}`}>
            {settings.enabled ? msg.active : msg.paused}
          </span>
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

      {/* Hero Status Banner */}
      <section className={`status-banner ${settings.enabled ? '' : 'paused'}`}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <OpticalCrestBrandmark size={26} monochrome={!settings.enabled} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 12.5 }}>
              {settings.enabled ? msg.heroIntercepting : msg.heroPaused}
            </div>
            <div className="muted" style={{ fontSize: 11 }}>
              {activeNetFeatures
                ? msg.heroOptInSubtitle(activeNetFeatures)
                : msg.heroLocalSubtitle}
            </div>
          </div>
        </div>
        <span className="pill" style={{ fontSize: 10 }}>
          <LockPrivacyIcon size={11} />
          {activeNetFeatures ? msg.optInNetPill : msg.localPill}
        </span>
      </section>

      <section className="card">
        <h2 className="card-title">{msg.controlsTitle}</h2>

        <label className="toggle-row">
          <span>
            <strong style={{ fontSize: 12.5 }}>{msg.toggleInterceptTitle}</strong>
            <div className="muted" style={{ fontSize: 11 }}>
              {msg.toggleInterceptDesc}
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
            <strong style={{ fontSize: 12.5 }}>{msg.toggleRpcTitle}</strong>
            <div className="muted" style={{ fontSize: 11 }}>
              {msg.toggleRpcDesc}
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
          <div style={{ marginTop: 8 }}>
            <div className="muted" style={{ fontSize: 11 }}>
              {msg.customRpcHint}
            </div>
            <div style={{ display: 'flex', gap: 6, marginTop: 5 }}>
              <input
                className="input-text"
                type="url"
                placeholder="https://ethereum-sepolia-rpc.publicnode.com"
                value={rpcDraft}
                onChange={(e) => setRpcDraft(e.target.value)}
              />
              <button
                type="button"
                className="btn-ghost"
                onClick={() => updateSettings({ customRpcUrl: rpcDraft.trim() })}
              >
                {msg.saveBtn}
              </button>
            </div>
          </div>
        )}

        <label className="toggle-row">
          <span>
            <strong style={{ fontSize: 12.5 }}>{msg.toggleSourcifyTitle}</strong>
            <div className="muted" style={{ fontSize: 11 }}>
              {msg.toggleSourcifyDesc}
            </div>
          </span>
          <input
            type="checkbox"
            checked={settings.abiLookupEnabled}
            onChange={(e) =>
              updateSettings({ abiLookupEnabled: e.target.checked })
            }
          />
        </label>

        {savedNotice && (
          <div style={{ color: 'var(--brand)', fontSize: 11, marginTop: 6, fontWeight: 600 }}>
            {msg.settingsUpdated}
          </div>
        )}
      </section>

      <section className="card" style={{ marginBottom: 0 }}>
        <div className="card-title-row" style={{ marginBottom: 8 }}>
          <h2 className="card-title" style={{ margin: 0 }}>
            {msg.historyTitle(history.length)}
          </h2>
          {history.length > 0 && (
            <button type="button" className="btn-ghost" onClick={clearHistory}>
              {msg.clearBtn}
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <p className="muted" style={{ margin: 0, fontSize: 11.5 }}>
            {msg.historyEmpty}
          </p>
        ) : (
          history.slice(0, 8).map((item) => {
            const report = buildSanitizedReport(item.result, item.decision);
            const localizedSummary = buildPlainEnglishSummary(item.result, locale);
            return (
              <div className="history-item" key={item.requestId}>
                <div className="history-top">
                  <span
                    className="pill"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      fontSize: 10.5,
                    }}
                  >
                    <VerdictIcon verdict={item.verdict} size={12} />
                    {msg.verdictLabels[item.verdict]}
                  </span>
                  <span
                    className="pill"
                    style={{
                      fontSize: 10,
                      color:
                        item.decision === 'BLOCK' ? 'var(--critical)' : 'var(--understood)',
                    }}
                  >
                    {item.decision}
                  </span>
                </div>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 3 }}>
                  {localizedSummary}
                </div>
                <div className="muted mono" style={{ fontSize: 10.5, marginBottom: 6 }}>
                  {item.origin.replace(/^https?:\/\//, '')} · {item.method}
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    type="button"
                    className="btn-ghost"
                    onClick={() =>
                      downloadFile(
                        `approval-lens-${item.requestId.slice(0, 8)}.json`,
                        JSON.stringify(report, null, 2),
                        'application/json',
                      )
                    }
                  >
                    {msg.exportJson}
                  </button>
                  <button
                    type="button"
                    className="btn-ghost"
                    onClick={() =>
                      downloadFile(
                        `approval-lens-${item.requestId.slice(0, 8)}.html`,
                        renderHtmlReport(report),
                        'text/html',
                      )
                    }
                  >
                    {msg.exportHtml}
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
