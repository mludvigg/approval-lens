import { useEffect, useState } from 'react';
import {
  detectDefaultLocale,
  isSupportedLocale,
  SUPPORTED_LOCALES,
} from '../core/i18n';
import type { Locale, Severity, Verdict } from '../core/types';

export type ThemeMode = 'dark' | 'light';

const THEME_STORAGE_KEY = 'approval_lens_theme';
const LOCALE_STORAGE_KEY = 'approval_lens_locale';

export function useLocale(): [Locale, (next: Locale) => void] {
  const [locale, setLocaleState] = useState<Locale>(() => {
    try {
      const saved = localStorage.getItem(LOCALE_STORAGE_KEY);
      if (isSupportedLocale(saved)) return saved;
    } catch {
      // Fallback
    }
    return detectDefaultLocale(typeof navigator !== 'undefined' ? navigator.language : 'en');
  });

  useEffect(() => {
    document.documentElement.lang = locale;
    try {
      localStorage.setItem(LOCALE_STORAGE_KEY, locale);
    } catch {
      // Ignore storage errors
    }
  }, [locale]);

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === LOCALE_STORAGE_KEY && isSupportedLocale(e.newValue)) {
        setLocaleState(e.newValue);
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const setLocale = (next: Locale) => {
    setLocaleState(next);
    try {
      chrome?.runtime?.sendMessage?.({
        type: 'UPDATE_SETTINGS',
        settings: { locale: next },
      });
    } catch {
      // Ignore outside extension context
    }
  };

  return [locale, setLocale];
}

export function LocaleSwitcher({
  locale,
  onChange,
}: {
  locale: Locale;
  onChange: (next: Locale) => void;
}) {
  return (
    <div className="locale-seg" role="group" aria-label="Language">
      {SUPPORTED_LOCALES.map((opt) => (
        <button
          key={opt.code}
          type="button"
          className={`locale-seg-btn ${locale === opt.code ? 'active' : ''}`}
          onClick={() => onChange(opt.code)}
          title={opt.label}
          aria-pressed={locale === opt.code}
        >
          {opt.shortLabel}
        </button>
      ))}
    </div>
  );
}

export function useTheme(): [ThemeMode, () => void] {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved === 'light' || saved === 'dark') return saved;
    } catch {
      // Fallback
    }
    return 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Ignore storage errors
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  return [theme, toggleTheme];
}

/**
 * A. Standalone Brandmark — The Optical Crest
 * Unified outer shield silhouette flowing into a 45° loupe handle while framing
 * a circular optical lens aperture with a concave focal reflection arc.
 */
export function OpticalCrestBrandmark({
  size = 24,
  monochrome = false,
}: {
  size?: number;
  monochrome?: boolean;
}) {
  const sw = size <= 18 ? 2.0 : 1.75;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      aria-hidden="true"
      className="brandmark-svg"
    >
      <path
        d="M15.5 3.5L25.5 7.5V15.2C25.5 21.8 21.1 26.6 15.5 28.5C9.9 26.6 5.5 21.8 5.5 15.2V7.5L15.5 3.5Z"
        fill={monochrome ? 'none' : 'var(--brand-soft)'}
        stroke={monochrome ? 'currentColor' : 'var(--brand)'}
        strokeWidth={sw}
        strokeLinejoin="round"
      />
      <circle
        cx="15.5"
        cy="15.2"
        r="5.5"
        stroke={monochrome ? 'currentColor' : 'var(--brand)'}
        strokeWidth={sw}
      />
      <path
        d="M13.2 13.2C14.3 12.1 16.2 12.1 17.5 13.2"
        stroke={monochrome ? 'currentColor' : 'var(--brand)'}
        strokeWidth={sw}
        strokeLinecap="round"
      />
      <path
        d="M19.6 19.3L26.5 26.2"
        stroke={monochrome ? 'currentColor' : 'var(--brand)'}
        strokeWidth={sw + 0.35}
        strokeLinecap="round"
      />
    </svg>
  );
}

/**
 * B. Standalone Custom Wordmark — APPROVAL LENS
 * Custom 'A' features the concave optical lens-arc crossbar and 'O' mirrors the inner aperture ring.
 */
export function OpticalCrestWordmark({
  scale = 0.82,
  monochrome = false,
}: {
  scale?: number;
  monochrome?: boolean;
}) {
  const w = Math.round(188 * scale);
  const h = Math.round(24 * scale);
  const ink = monochrome ? 'currentColor' : 'var(--text)';
  const accent = monochrome ? 'currentColor' : 'var(--brand)';

  return (
    <svg
      width={w}
      height={h}
      viewBox="0 0 188 24"
      fill="none"
      aria-label="Approval Lens"
      className="wordmark-svg"
    >
      {/* Custom 'A' with concave optical lens-arc crossbar */}
      <path
        d="M3 19L9 5L15 19"
        stroke={ink}
        strokeWidth="2.1"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M5.5 14C7.8 15.6 10.2 15.6 12.5 14"
        stroke={accent}
        strokeWidth="2"
        strokeLinecap="round"
      />
      <text
        x="17.5"
        y="18.5"
        fill={ink}
        fontFamily="-apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif"
        fontWeight="700"
        fontSize="14.5"
        letterSpacing="1.2"
      >
        PPR
      </text>
      {/* Custom Optical Aperture 'O' */}
      <circle cx="62.5" cy="13.2" r="5.3" stroke={accent} strokeWidth="2" />
      <path
        d="M60.5 11.4C61.6 10.4 63.4 10.4 64.5 11.4"
        stroke={accent}
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <text
        x="71"
        y="18.5"
        fill={ink}
        fontFamily="-apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif"
        fontWeight="700"
        fontSize="14.5"
        letterSpacing="1.2"
      >
        VAL
      </text>
      <text
        x="112"
        y="18.5"
        fill={accent}
        fontFamily="-apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif"
        fontWeight="600"
        fontSize="14.5"
        letterSpacing="2.4"
      >
        LENS
      </text>
    </svg>
  );
}

/**
 * C. Primary Combination Mark — Brandmark + Custom Wordmark Lockup
 */
export function OpticalCrestCombo({
  markSize = 24,
  wordScale = 0.78,
}: {
  markSize?: number;
  wordScale?: number;
}) {
  return (
    <div className="brand-lockup" title="Approval Lens">
      <OpticalCrestBrandmark size={markSize} />
      <OpticalCrestWordmark scale={wordScale} />
    </div>
  );
}

/* ============================================================================
 * Monoline (1.5px stroke) Vector Icon System
 * ========================================================================== */

export function VerdictIcon({ verdict, size = 18 }: { verdict: Verdict; size?: number }) {
  switch (verdict) {
    case 'KNOWN_MALICIOUS':
      return (
        <svg
          width={size}
          height={size}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
          <line x1="12" y1="8" x2="12" y2="12.5" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      );
    case 'HIGH_RISK':
      return (
        <svg
          width={size}
          height={size}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      );
    case 'REVIEW_NEEDED':
      return (
        <svg
          width={size}
          height={size}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M12 2L22 12L12 22L2 12L12 2Z" />
          <line x1="12" y1="8.5" x2="12" y2="12.5" />
          <line x1="12" y1="15.5" x2="12.01" y2="15.5" />
        </svg>
      );
    case 'UNANALYZED':
      return (
        <svg
          width={size}
          height={size}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
          <path d="M9.5 9.5a2.5 2.5 0 0 1 4.6 1.3c0 1.7-2.1 2-2.1 3.2" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      );
    case 'UNDERSTOOD':
    default:
      return (
        <svg
          width={size}
          height={size}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="11" cy="11" r="7.5" />
          <line x1="20.5" y1="20.5" x2="16.3" y2="16.3" />
          <path d="M8.5 11l1.8 1.8 3.6-3.6" />
        </svg>
      );
  }
}

export function SeverityIcon({ severity, size = 15 }: { severity: Severity; size?: number }) {
  switch (severity) {
    case 'CRITICAL':
      return <VerdictIcon verdict="KNOWN_MALICIOUS" size={size} />;
    case 'HIGH':
      return <VerdictIcon verdict="HIGH_RISK" size={size} />;
    case 'MEDIUM':
    case 'LOW':
      return <VerdictIcon verdict="REVIEW_NEEDED" size={size} />;
    case 'INFO':
    default:
      // Use the Approval Lens Optical Crest Brandmark for recognized/verified INFO items
      return <OpticalCrestBrandmark size={size + 3} />;
  }
}

export function GlobeIcon({ size = 13 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="9.5" />
      <line x1="2.5" y1="12" x2="21.5" y2="12" />
      <path d="M12 2.5a14.5 14.5 0 0 1 0 19 14.5 14.5 0 0 1 0-19" />
    </svg>
  );
}

export function CoinIcon({ size = 13 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="9.5" />
      <path d="M14.5 9.5c-.5-1-1.4-1.5-2.5-1.5-1.5 0-2.5.9-2.5 2s1 1.6 2.5 2 2.5.9 2.5 2-1 2-2.5 2c-1.1 0-2-.5-2.5-1.5" />
      <line x1="12" y1="6.5" x2="12" y2="17.5" />
    </svg>
  );
}

export function KeySpenderIcon({ size = 13 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="M10.7 12.3L21 2" />
      <path d="M17 6l3 3" />
    </svg>
  );
}

export function ClockExpiryIcon({ size = 13 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="9.5" />
      <polyline points="12 7 12 12 15.5 14" />
    </svg>
  );
}

export function LockPrivacyIcon({ size = 13 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}

export function CopyIcon({ size = 12 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

export function CheckIcon({ size = 12 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

export function ChevronIcon({
  open,
  size = 14,
}: {
  open: boolean;
  size?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{
        transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
        transition: 'transform 0.15s ease',
      }}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

export function ThemeToggleIcon({ theme, size = 14 }: { theme: ThemeMode; size?: number }) {
  if (theme === 'dark') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="12" cy="12" r="4.5" />
        <line x1="12" y1="2" x2="12" y2="4" />
        <line x1="12" y1="20" x2="12" y2="22" />
        <line x1="4.93" y1="4.93" x2="6.34" y2="6.34" />
        <line x1="17.66" y1="17.66" x2="19.07" y2="19.07" />
        <line x1="2" y1="12" x2="4" y2="12" />
        <line x1="20" y1="12" x2="22" y2="12" />
        <line x1="4.93" y1="19.07" x2="6.34" y2="17.66" />
        <line x1="17.66" y1="6.34" x2="19.07" y2="4.93" />
      </svg>
    );
  }
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}
