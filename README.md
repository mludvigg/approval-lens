# Approval Lens

**Approval Lens** is an open-source, local-first Chrome Manifest V3 extension that intercepts EVM wallet approval and signature requests *before* your wallet prompts you, decodes what permission is actually being requested, and surfaces transparent, evidence-backed risk findings.

> Built to prioritize **explainability, honest uncertainty, and minimal privileges**—never opaque "100% Safe" scores and never requesting custody of keys.

## Why Approval Lens?

Most Web3 wallet drains happen through misunderstood permissions rather than direct ETH transfers:
* Unlimited ERC-20 `approve` / `increaseAllowance` (`MAX_UINT256`)
* Collection-wide NFT `setApprovalForAll`
* Gasless off-chain EIP-712 signatures (`Permit` / `Permit2`)
* Hidden approvals nested inside `multicall` batches
* Raw blind signing (`eth_sign`) or unverified opaque calldata

Approval Lens separates verdicts into five honest states:
1. **`KNOWN_MALICIOUS`** — Matched a versioned local threat indicator (domain or address).
2. **`HIGH_RISK`** — Decoded a dangerous permission pattern (unlimited approval, `setApprovalForAll`, `Permit2`, raw `eth_sign`, EOA spender, etc.).
3. **`REVIEW_NEEDED`** — Flagged contextual or structural risk (upgradeable proxy contract, cross-origin iframe, or generic EIP-712 typed data) that requires closer inspection.
4. **`UNDERSTOOD`** — Cleanly decoded with no matched risk rules (explicitly notes what was *not* checked).
5. **`UNANALYZED`** — Calldata or typed data could not be decoded safely; refuses to guess.

## Security Architecture

See [THREAT_MODEL.md](./THREAT_MODEL.md) and [ARCHITECTURE.md](./ARCHITECTURE.md) for trust boundaries, TOCTOU payload freezing, isolated `chrome-extension://` review window design, and documented limitations.

## Development

```bash
npm install
npm run typecheck
npm run build
npm test
npm run lab # launches local Attack Test Lab on http://127.0.0.1:4173
```

### Load in Chrome
1. Run `npm run build`.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Click **Load unpacked** and select the `dist/` directory.
4. Connect MetaMask or Rabby on a testnet (e.g., Sepolia) and test against the local `test-lab/` page.
