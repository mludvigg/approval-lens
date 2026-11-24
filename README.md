# Approval Lens

**Approval Lens** is an open-source, local-first Chrome Manifest V3 extension that intercepts EVM wallet approval and signature requests *before* MetaMask, Rabby, or any `EIP-1193` / `EIP-6963` wallet prompts you—translating raw hex permissions into plain language (`EN` / `PT-BR` / `ES`) and surfacing transparent, evidence-backed risk verdicts.

> Built to prioritize **explainability, local-first privacy (`0` outbound network calls by default), honest uncertainty, and minimal Chrome privileges (`["storage"]` only)**—never opaque "100% Safe" scores and never requesting custody of keys.

---

## Why Approval Lens?

Most Web3 wallet drains happen through misunderstood permissions rather than direct ETH transfers:
* Unlimited ERC-20 `approve` / `increaseAllowance` (`MAX_UINT256`) & EOA spenders
* Collection-wide NFT `setApprovalForAll`
* Gasless off-chain `EIP-712` signatures (`EIP-2612 Permit`, Uniswap `Permit2`, cross-chain `chainId` traps)
* Zero-consideration **Seaport** & zero/dust-price **Blur** NFT marketplace phishing orders
* Hidden approvals nested inside `multicall` and cross-contract **`Multicall3`** batches
* TOCTOU ("Time-of-Check to Time-of-Use") in-memory transaction mutation attacks
* Raw blind signing (`eth_sign`) or unverified opaque calldata

Approval Lens classifies every intercepted request into **five honest verdicts**:
1. **`KNOWN_MALICIOUS`** — Matched a versioned local threat indicator (phishing domain or drainer address).
2. **`HIGH_RISK`** — Decoded a dangerous permission pattern (unlimited approval, `setApprovalForAll`, zero-ETH Seaport/Blur drain, `Permit2`, raw `eth_sign`, cross-origin iframe, EOA spender).
3. **`REVIEW_NEEDED`** — Surfaced contextual or structural risk (upgradeable EIP-1967 / Beacon proxy, Sourcify-decoded custom contract function, capped gasless `Permit`).
4. **`UNDERSTOOD`** — Cleanly decoded with no matched risk rules (explicitly lists what was *not* checked).
5. **`UNANALYZED`** — Calldata or typed data could not be verified safely; refuses to guess.

---

## Detection & Coverage Matrix

| Threat / Capability | Local Mode (`0` Net Calls) | Opt-In RPC / Sourcify | Notes & Honest Limits |
|---|---|---|---|
| **ERC-20 `approve` / `increaseAllowance` / revokes** | Yes | Adds live allowance & symbol/decimals | Local decimals bundled for major tokens (`USDC`, `USDT`, `WETH`, `DAI`, `WBTC`). |
| **NFT `setApprovalForAll` & transfers** | Yes | — | Flags full collection operator grants (`HIGH_RISK` / `KNOWN_MALICIOUS`). |
| **Gasless `EIP-2612 Permit` & `Permit2` (Single/Batch/TransferFrom)** | Yes | — | Catches `MAX_UINT256`/`MAX_UINT160` and cross-chain `domain.chainId` mismatches. |
| **Seaport (`OrderComponents`) & Blur (`Order` / `Root`)** | Yes | — | Flags `0`-return Seaport drains & `0`/dust Blur listings as `CRITICAL`; warns on blind Blur Merkle roots. |
| **Nested `multicall` & Cross-Contract `Multicall3`** | Yes (up to depth 3) | — | Unpacks `aggregate`, `aggregate3`, `aggregate3Value`, `tryAggregate` with per-call `target` inspection. |
| **TOCTOU Bait-and-Switch Payload Freezing** | Yes | — | Deep-clones, `Object.freeze`s, and SHA-256 fingerprints payloads before inspection. |
| **EOA Spender & Proxy Detection (`EIP-1967` / Beacon / `EIP-1167`)** | Skipped (`0` calls) | Yes (logged) | Flags personal-wallet (`EOA`) spenders (`HIGH`) and upgradeable proxies (`MEDIUM`). |
| **Custom Contract Decoding (`Sourcify v2` + `4byte`)** | Honest `UNANALYZED` | Yes (logged) | Sourcify verified ABIs land at `REVIEW_NEEDED`; 4byte-only matches warn of selector collision risk. |
| **Full EVM Bytecode / State Simulation** | Not performed | Not performed | Explicitly disclosed in every inspection window under *What Was NOT Analyzed*. |

---

## Reproducible Evaluation Benchmark (`v0.3.0`)

Run `npm run benchmark` to evaluate the analysis engine offline across **64 labeled ground-truth fixtures** (**32 malicious/drainer vectors** + **32 benign Web3 interactions**). Full methodology and per-fixture logs live in **[BENCHMARK.md](./BENCHMARK.md)**:

* **Silent Misses on Attack Fixtures:** **`0 / 32` (`0.0%`)** — zero malicious/dangerous fixtures misclassified as `UNDERSTOOD`
* **Protective Intercept Recall:** **`32 / 32` (`100.0%`)** (`30/30` known drainer patterns flagged `KNOWN_MALICIOUS` / `HIGH_RISK`; `2/2` opaque/beacon evasion fixtures surfaced as `UNANALYZED` / `REVIEW_NEEDED`)
* **Standard Benign False-Alarm Rate:** **`0 / 26` (`0.0%`)** across capped approvals, revokes, direct transfers, safe multicalls, and SIWE `personal_sign` logins
* **Sub-Millisecond Engine Latency:** **p50 `< 0.1 ms` · p95 `< 1.0 ms`** offline

---

## Multi-Language (`i18n`) & Open-Source Threat Intelligence

* **Instant Local `i18n` (`EN` · `PT-BR` · `ES`):** Switch live between **English**, **Português (BR)**, and **Español** inside both the Toolbar Popup and the isolated Review Window (`0` network calls).
* **Open-Source Attribution:**
  * Offline phishing blocklist snapshot (`src/data/community-domains.json`) is derived from **[MetaMask/eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect)** under **DBADPL-1.2** via `npm run sync:intel` (SHA-256 verified at build time; `0` runtime calls). Controlled Attack Test Lab vanity fixtures (`0xbad0…0bad`, `0xdeaf…cafe`, `*.example`) are explicitly marked `"isTestFixture": true` in `src/data/reputation.json`.
  * Opt-in verified ABI resolution uses **[Sourcify API v2](https://sourcify.dev)** and `api.4byte.sourcify.dev`.

---

## Security Architecture

See **[THREAT_MODEL.md](./THREAT_MODEL.md)** and **[ARCHITECTURE.md](./ARCHITECTURE.md)** for trust boundaries, TOCTOU payload freezing, isolated `chrome-extension://` review window design, fail-closed guarantees, and documented limitations.

---

## Development

```bash
npm install
npm run typecheck
npm test          # runs all unit + i18n + 64-fixture benchmark tests
npm run benchmark # regenerates BENCHMARK.md & benchmarks/latest-results.json
npm run build     # builds Chrome MV3 extension into dist/
npm run lab       # launches local 11-scenario Attack Test Lab on http://127.0.0.1:4173
```

### Load in Chrome
1. Run `npm run build`.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Click **Load unpacked** and select the `dist/` directory.
4. Connect MetaMask or Rabby on **Sepolia testnet** and test against `http://127.0.0.1:4173`.
