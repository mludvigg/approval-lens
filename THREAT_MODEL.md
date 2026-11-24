# Threat Model — Approval Lens

> **Scope:** Approval Lens v0.1 (Chrome Manifest V3, EVM / EIP-1193 & EIP-6963)  
> **Security Philosophy:** Local-first, non-custodial, fail-closed, transparent about uncertainty.

---

## 1. Security Goals

Approval Lens helps users understand **what permissions a Web3 request grants** before their wallet prompts them to sign:

1. **Explainability over magic scores:** Show decoded method calls, target contracts, spenders, token amounts (including unlimited `MAX_UINT256`), and EIP-712 `Permit` / `Permit2` scopes alongside exact evidence sources.
2. **Honest uncertainty:** Explicitly surface `UNANALYZED` when calldata, typed data, or contract metadata cannot be decoded or verified. Never label an unknown or clean-looking transaction "100% Safe."
3. **Zero custody:** Never request, read, store, or transmit private keys, seed phrases, or wallet passwords. Never sign transactions on the user's behalf.
4. **Minimal trust & minimal data egress:** Core decoding and rule checks execute 100% locally inside the browser. Optional on-chain RPC reads are opt-in and logged visibly for the user.

---

## 2. Assets & Trust Boundaries

```text
+-------------------------------------------------------------------+
| UNTRUSTED: Web Page / dApp ("MAIN" World)                         |
|  - Malicious JS, compromised frontends, phishing iframes          |
|  - Can read/mutate JS objects, spoof DOM, forge postMessage       |
+-------------------------------|-----------------------------------+
                                | window.postMessage (untrusted input)
                                v
+-------------------------------------------------------------------+
| SEMI-TRUSTED BRIDGE: Content Script ("ISOLATED" World)            |
|  - Separate JS heap from the page                                 |
|  - Validates message schema & relays to Background Service Worker |
+-------------------------------|-----------------------------------+
                                | chrome.runtime.sendMessage
                                v
+-------------------------------------------------------------------+
| TRUSTED EXTENSION CORE: Background Service Worker + Extension UI  |
|  - Chrome-verified sender.origin / sender.tab.url                 |
|  - Pure decoding engine, local reputation cache, risk rules       |
|  - Dedicated chrome-extension:// Review Popup Window              |
+-------------------------------------------------------------------+
```

### Trust Assumptions
* **Trusted:** Chrome extension sandbox, the user's underlying wallet extension (MetaMask / Rabby), and local Approval Lens code.
* **Untrusted:** Every web page, dApp frontend, iframe, contract metadata string (token names/symbols can contain spoofing characters or XSS payloads), and raw calldata/EIP-712 fields.

---

## 3. Threats & Mitigations

| ID | Threat | Attack Vector | Mitigation in Approval Lens |
|----|--------|---------------|-----------------------------|
| **T1** | **UI Spoofing / Clickjacking** | A malicious dApp injects CSS/HTML to cover, restyle, or fake an in-page approval modal. | Review UI renders inside an isolated **`chrome-extension://` popup window**, never inside the untrusted page DOM. |
| **T2** | **Bait-and-Switch (TOCTOU)** | A dApp passes benign tx parameters to Approval Lens, then mutates the JS object before the real wallet signs it. | `inpage.ts` deep-clones and freezes the exact JSON-RPC payload at interception time, computes a canonical SHA-256 digest, and forwards **only the frozen snapshot** to the wallet if allowed. |
| **T3** | **Origin Spoofing** | A phishing site sends a forged `postMessage` claiming to be `https://app.uniswap.org`. | The Background Service Worker ignores any origin string supplied by the page and reads **`sender.origin`** directly from Chrome's trusted `MessageSender`. |
| **T4** | **Iframe Bypass** | A malicious site embeds a hidden/cross-origin `<iframe>` to invoke `window.ethereum` outside the top-level hook. | Content scripts run with `"all_frames": true`, capturing both `frameOrigin` and top-level origin mismatches. |
| **T5** | **Extension XSS / Injection** | Malicious token symbols, EIP-712 strings, or domain names contain `<script>` or HTML payloads rendered in the Review UI or exported HTML report. | React auto-escaping in UI, strict MV3 CSP (`script-src 'self'; object-src 'none'`), and strict HTML entity escaping in exported HTML reports. |
| **T6** | **Fail-Open Bypass** | The user closes the Review Window or the service worker encounters an error, and the request accidentally passes through to the wallet. | **Fail-closed by default:** closing the popup, timing out, or hitting an internal error rejects the request (`4001: Blocked by Approval Lens`). |
| **T7** | **Recursive `multicall` DoS** | Attacker crafts deeply nested or huge calldata to freeze the browser tab or decoder. | Hard limits on `multicall` recursion depth (max 3) and calldata byte length; oversized payloads safely fall back to `UNANALYZED`. |
| **T8** | **Privacy Leakage via Reports** | User shares an exported report that accidentally leaks their wallet address or sensitive URL query tokens. | Exported reports redact the user's address (prefix/suffix only) and strip URL query strings/hashes by default. |

---

## 4. Explicit Limitations & Non-Goals (MVP v0.1)

Approval Lens **does not**:
* Perform full EVM transaction simulation or state-diff execution (unlike hosted B2B simulators).
* Audit arbitrary smart contract bytecode or prove a contract is free of rug-pull logic.
* Detect zero-day phishing domains that are not in the local reputation cache.
* Protect against attacks outside the browser (e.g., mobile WalletConnect QR codes, compromised hardware wallets, or OS-level malware).
* Guarantee that a transaction marked `UNDERSTOOD` is safe—only that its decoded permission structure matched no known risk rules.
