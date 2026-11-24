# Architecture — Approval Lens

## High-Level Flow

1. **Interception (`src/inpage/index.ts` — `MAIN` world)**
   - Wraps `window.ethereum` (EIP-1193) and listens for `eip6963:announceProvider` (EIP-6963) so modern multi-wallet setups (MetaMask, Rabby, etc.) are covered.
   - Intercepts `eth_sendTransaction`, `eth_signTypedData_v4` (and v3/legacy), `personal_sign`, and `eth_sign`.
   - Deep-clones and freezes the payload before forwarding to the isolated bridge.
2. **Bridge (`src/content/index.ts` — `ISOLATED` world)**
   - Validates `window.postMessage` envelopes from `inpage.ts`.
   - Relays inspection requests to the Background Service Worker via `chrome.runtime.sendMessage`.
3. **Background Orchestrator (`src/background/index.ts`)**
   - Reads the Chrome-verified origin (`sender.origin`).
   - Runs the pure **Core Analysis Engine** (`src/core/`).
   - Stores pending inspection records in `chrome.storage.session`.
   - Opens the isolated Review Window (`review.html?id=<requestId>`).
   - Resolves `ALLOW` or `BLOCK` (fail-closed if window is closed).
4. **Core Analysis Engine (`src/core/`)**
   - Pure TypeScript modules with zero Chrome API dependencies (100% unit-testable in Vitest):
     - `types.ts` — Domain models, verdicts, findings, and report schema.
     - `decoders/` — Calldata (ERC-20, ERC-721/1155, `multicall`), EIP-712 (`Permit`, `Permit2`, Seaport), and message signing decoders.
     - `rules.ts` — Deterministic risk rule evaluation with cited evidence and explicit limitations.
     - `reputation.ts` — Versioned local threat intelligence matcher (`src/data/reputation.json`).
     - `rpc.ts` — Opt-in read-only RPC enrichment (token symbol/decimals, current allowance, EOA vs. contract check, EIP-1967 proxy resolution) with full network logging.
     - `report.ts` — Sanitized JSON & HTML audit report generator.
5. **Extension UI (`src/ui/`)**
   - `popup.html` / `src/ui/popup/` — Toolbar status, pause toggle, local-only vs. RPC settings, session history.
   - `review.html` / `src/ui/review/` — Dedicated pre-signature inspection window.
6. **Attack Test Lab (`test-lab/`)**
   - Local interactive test dApp that connects to your real MetaMask/Rabby wallet (on Sepolia testnet) to safely demonstrate benign vs. malicious approval scenarios.

## Directory Structure

```text
approval-lens/
├── public/
│   ├── manifest.json          # Chrome Manifest V3 configuration
│   └── icons/                 # Extension icons (16, 48, 128)
├── scripts/
│   └── build.mjs              # Multi-entry Vite build for MV3
├── src/
│   ├── background/            # MV3 Service Worker
│   ├── content/               # Isolated content script bridge
│   ├── inpage/                # MAIN world EIP-1193 / EIP-6963 hook
│   ├── core/                  # Pure decoding, rules, RPC & reporting engine
│   ├── data/                  # Versioned local reputation dataset
│   └── ui/
│       ├── popup/             # Toolbar popup React UI
│       └── review/            # Isolated review window React UI
├── tests/                     # Vitest unit & adversarial test suite
├── test-lab/                  # Local interactive Web3 attack demo page
├── ARCHITECTURE.md
└── THREAT_MODEL.md
```
