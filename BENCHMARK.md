# Approval Lens — Reproducible Security Evaluation Benchmark (`v0.3.0`)

> Reproducible offline evaluation across **64 labeled EVM transaction & signature fixtures** (**32 malicious/drainer vectors** + **32 benign Web3 interactions**).
> Re-run anytime with `npm run benchmark`.

---

## Executive Scorecard

| Security & Usability Metric | Result | Notes |
|---|---|---|
| **Silent Misses on Attack Fixtures** | **0 / 32 (`0.0%`)** | **Zero** malicious or dangerous fixtures were misclassified as `UNDERSTOOD`. |
| **Protective Warning / Refusal Recall** | **32 / 32 (`100%`)** | Every attack fixture triggered `KNOWN_MALICIOUS`, `HIGH_RISK`, `REVIEW_NEEDED`, or honest `UNANALYZED` refusal. |
| **Explicit High/Critical Threat Detection** | **30 / 32 (`93.75%`)** | 30/30 known drainer & signature vectors caught as `KNOWN_MALICIOUS` / `HIGH_RISK`; 2 adversarial evasion fixtures surfaced as `UNANALYZED` / `REVIEW_NEEDED`. |
| **Standard Benign False-Alarm Rate** | **0 / 26 (`0%`)** | Capped approvals, revokes (`approve(0)`), transfers, safe multicalls, and SIWE `personal_sign` logins pass cleanly as `UNDERSTOOD`. |
| **Intentional Defensive Friction (All Benign)** | **6 / 32 (`18.75%`)** | Off-chain marketplace orders (Seaport), gasless `Permit`/`Permit2` signatures, and unverified custom selectors intentionally prompt review rather than claiming safety. |
| **Schema / ABI Decode Coverage** | **61 / 64 (`95.31%`)** | Remaining 3 custom/opaque payloads are explicitly labeled `UNANALYZED` (refusing to guess). |
| **Inspection Engine Latency** | **p50: `0.03 ms` · p95: `0.54 ms`** | Mean: `0.15 ms` · Max: `2.1 ms` (100% offline deterministic execution). |

---

## Breakdown by Threat & Interaction Category

| Category | Class | Total | `KNOWN_MALICIOUS` | `HIGH_RISK` | `REVIEW_NEEDED` | `UNDERSTOOD` | `UNANALYZED` |
|---|---|---:|---:|---:|---:|---:|---:|
| **ERC-20 Token Drainers** | `ATTACK` | 6 | 2 | 4 | 0 | 0 | 0 |
| **NFT & Seaport Drainers** | `ATTACK` | 4 | 2 | 2 | 0 | 0 | 0 |
| **Blur Marketplace Drains** | `ATTACK` | 3 | 0 | 3 | 0 | 0 | 0 |
| **Gasless Permit & Permit2** | `ATTACK` | 6 | 1 | 5 | 0 | 0 | 0 |
| **Multicall Obfuscation** | `ATTACK` | 5 | 1 | 4 | 0 | 0 | 0 |
| **Phishing & Blind Signing** | `ATTACK` | 6 | 3 | 3 | 0 | 0 | 0 |
| **Adversarial Evasion** | `ATTACK` | 2 | 0 | 0 | 1 | 0 | 1 |
| **Capped Approvals & Revokes** | `BENIGN` | 10 | 0 | 0 | 0 | 10 | 0 |
| **NFT Revokes & Direct Transfers** | `BENIGN` | 8 | 0 | 0 | 0 | 8 | 0 |
| **Benign Batches & SIWE Logins** | `BENIGN` | 8 | 0 | 0 | 0 | 8 | 0 |
| **Complex Protocol Actions (Defensive Friction)** | `BENIGN` | 6 | 0 | 2 | 2 | 0 | 2 |

---

## Methodology & Honest Limitations

1. **Why Separate "Standard Benign" vs. "Intentional Defensive Friction"?**
   Security tools that claim `0%` friction on *every* Web3 action inevitably stay silent on gasless `Permit2` signatures, off-chain `Seaport` NFT listings, or unverified contract selectors — the exact vectors real drainers abuse. Approval Lens passes all **26/26** everyday capped approvals, revokes, transfers, and SIWE logins as `UNDERSTOOD`, while deliberately raising `REVIEW_NEEDED`, `HIGH_RISK`, or `UNANALYZED` on the **6** complex off-chain/custom-ABI fixtures.
2. **Adversarial Evasion Transparency (`ATK-31` & `ATK-32`):**
   * `ATK-31` sends an unrecognized custom function selector (`0x99887766`, e.g., a fake `claimRewards()` drainer) with `0 ETH`. Without full EVM state simulation, static decoding cannot prove malicious state changes — so Approval Lens refuses to guess and marks it **`UNANALYZED`** instead of silently passing it.
   * `ATK-32` targets an upgradeable **EIP-1967 Beacon Proxy**, surfacing **`REVIEW_NEEDED`** via opt-in RPC slot inspection because a beacon admin can swap implementation logic post-approval.

---

## Complete 64-Fixture Evaluation Log

| ID | Category | Scenario | Verdict | Primary Finding | Latency |
|---|---|---|---|---|---:|
| `ATK-01` | ERC-20 Token Drainers | Unlimited USDC approve(MAX_UINT256) to unknown spender | `HIGH_RISK` | `UNLIMITED_ERC20_APPROVAL` | 1.31 ms |
| `ATK-02` | ERC-20 Token Drainers | Unlimited USDC approve to known malicious drainer (0xbad0…0bad) | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ADDRESS` | 0.09 ms |
| `ATK-03` | ERC-20 Token Drainers | Near-unlimited USDT increaseAllowance(2^255) | `HIGH_RISK` | `UNLIMITED_ERC20_APPROVAL` | 0.05 ms |
| `ATK-04` | ERC-20 Token Drainers | ERC-20 approve directed to burn address (0x0000…dead) | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ADDRESS` | 0.17 ms |
| `ATK-05` | ERC-20 Token Drainers | Capped ERC-20 approve to personal EOA wallet (RPC EOA check) | `HIGH_RISK` | `EOA_SPENDER_DETECTED` | 2.10 ms |
| `ATK-06` | ERC-20 Token Drainers | On-chain Permit2 approve(token, spender, MAX_UINT160, expiration) | `HIGH_RISK` | `UNLIMITED_ERC20_APPROVAL` | 0.40 ms |
| `ATK-07` | NFT & Seaport Drainers | ERC-721 setApprovalForAll(true) to known NFT drainer | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ADDRESS` | 0.31 ms |
| `ATK-08` | NFT & Seaport Drainers | ERC-1155 setApprovalForAll(true) to unverified operator | `HIGH_RISK` | `NFT_APPROVAL_FOR_ALL` | 0.05 ms |
| `ATK-09` | NFT & Seaport Drainers | Seaport 1.6 OrderComponents offering 1 NFT for empty consideration | `HIGH_RISK` | `SEAPORT_ZERO_CONSIDERATION_DRAIN` | 0.26 ms |
| `ATK-10` | NFT & Seaport Drainers | Seaport 1.5 multi-NFT sweep routing 100% of consideration to drainer | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ADDRESS` | 0.05 ms |
| `ATK-11` | Blur Marketplace Drains | Blur Order selling NFT for 0 ETH | `HIGH_RISK` | `BLUR_ZERO_PRICE_DRAIN` | 0.03 ms |
| `ATK-12` | Blur Marketplace Drains | Blur Order selling NFT for 500 wei dust | `HIGH_RISK` | `BLUR_ZERO_PRICE_DRAIN` | 0.02 ms |
| `ATK-13` | Blur Marketplace Drains | Blur BulkOrderRoot blind Merkle tree signature | `HIGH_RISK` | `BLUR_BULK_ROOT_SIGNATURE` | 0.02 ms |
| `ATK-14` | Gasless Permit & Permit2 | EIP-2612 Permit unlimited USDC allowance | `HIGH_RISK` | `GASLESS_PERMIT_UNLIMITED` | 0.04 ms |
| `ATK-15` | Gasless Permit & Permit2 | DAI-style Permit (allowed: true) unlimited approval | `HIGH_RISK` | `GASLESS_PERMIT_UNLIMITED` | 0.02 ms |
| `ATK-16` | Gasless Permit & Permit2 | EIP-2612 Permit chainId mismatch (Mainnet signature while on Sepolia) | `HIGH_RISK` | `EIP712_CHAIN_MISMATCH` | 0.03 ms |
| `ATK-17` | Gasless Permit & Permit2 | Permit2 PermitSingle unlimited allowance to drainer | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ADDRESS` | 0.02 ms |
| `ATK-18` | Gasless Permit & Permit2 | Permit2 PermitBatch multi-token sweep (USDC + USDT + WETH) | `HIGH_RISK` | `PERMIT2_UNLIMITED` | 0.06 ms |
| `ATK-19` | Gasless Permit & Permit2 | Permit2 PermitTransferFrom immediate signature sweep | `HIGH_RISK` | `PERMIT2_SIGNATURE` | 0.03 ms |
| `ATK-20` | Multicall Obfuscation | multicall(bytes[]) hiding unlimited ERC-20 approve behind small transfer | `HIGH_RISK` | `MULTICALL_HIDDEN_UNLIMITED_APPROVAL` | 0.19 ms |
| `ATK-21` | Multicall Obfuscation | multicall(deadline,bytes[]) hiding NFT setApprovalForAll(true) | `HIGH_RISK` | `NFT_APPROVAL_FOR_ALL` | 0.15 ms |
| `ATK-22` | Multicall Obfuscation | Multicall3.aggregate3 cross-contract hidden drainer approval | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ADDRESS` | 0.22 ms |
| `ATK-23` | Multicall Obfuscation | Multicall3.aggregate3Value mixing ETH payment + unlimited increaseAllowance | `HIGH_RISK` | `MULTICALL_HIDDEN_UNLIMITED_APPROVAL` | 0.11 ms |
| `ATK-24` | Multicall Obfuscation | 2-layer nested multicall inside Multicall3.aggregate hiding unlimited approve | `HIGH_RISK` | `MULTICALL_HIDDEN_UNLIMITED_APPROVAL` | 0.10 ms |
| `ATK-25` | Phishing & Blind Signing | Community phishing domain (MetaMask eth-phishing-detect exact match) | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ORIGIN` | 0.03 ms |
| `ATK-26` | Phishing & Blind Signing | Subdomain of community phishing domain (claim.<domain>) | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ORIGIN` | 0.01 ms |
| `ATK-27` | Phishing & Blind Signing | Curated impersonation phishing origin (uniswap-v4-claim.example) | `KNOWN_MALICIOUS` | `KNOWN_MALICIOUS_ORIGIN` | 0.01 ms |
| `ATK-28` | Phishing & Blind Signing | Cross-origin malicious iframe embedded inside news page | `HIGH_RISK` | `CROSS_ORIGIN_IFRAME` | 0.01 ms |
| `ATK-29` | Phishing & Blind Signing | Deprecated raw eth_sign 32-byte blind hash trap | `HIGH_RISK` | `RAW_ETH_SIGN` | 0.03 ms |
| `ATK-30` | Phishing & Blind Signing | Raw eth_sign arbitrary payload signature trap | `HIGH_RISK` | `RAW_ETH_SIGN` | 0.01 ms |
| `ATK-31` | Adversarial Evasion | Custom unverified selector (0x99887766 — fake claimRewards) refused as UNANALYZED | `UNANALYZED` | `OPAQUE_CALLDATA` | 0.20 ms |
| `ATK-32` | Adversarial Evasion | Upgradeable EIP-1967 Beacon proxy contract flagged as REVIEW_NEEDED | `REVIEW_NEEDED` | `EIP1967_BEACON_PROXY` | 0.78 ms |
| `BEN-01` | Capped Approvals & Revokes | Capped 50 USDC approve on Mainnet | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.04 ms |
| `BEN-02` | Capped Approvals & Revokes | Capped 250 USDT approve on Mainnet | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.02 ms |
| `BEN-03` | Capped Approvals & Revokes | Capped 1.5 WETH approve on Mainnet | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.03 ms |
| `BEN-04` | Capped Approvals & Revokes | Capped 1,000 DAI approve on Mainnet | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.02 ms |
| `BEN-05` | Capped Approvals & Revokes | Capped 0.25 WBTC approve on Mainnet | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.03 ms |
| `BEN-06` | Capped Approvals & Revokes | Capped 100 USDC approve on Sepolia Testnet | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.02 ms |
| `BEN-07` | Capped Approvals & Revokes | Revoke USDC allowance via approve(spender, 0) | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.02 ms |
| `BEN-08` | Capped Approvals & Revokes | Revoke WETH allowance via approve(spender, 0) | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.02 ms |
| `BEN-09` | Capped Approvals & Revokes | ERC-20 decreaseAllowance by 50 USDC | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.02 ms |
| `BEN-10` | Capped Approvals & Revokes | Capped ERC-20 increaseAllowance by 25 DAI | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.02 ms |
| `BEN-11` | NFT Revokes & Direct Transfers | Revoke NFT collection operator setApprovalForAll(operator, false) | `UNDERSTOOD` | `—` | 0.03 ms |
| `BEN-12` | NFT Revokes & Direct Transfers | Direct ERC-20 transfer of 20 USDC | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.02 ms |
| `BEN-13` | NFT Revokes & Direct Transfers | Direct ERC-20 transferFrom of 10 DAI | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.03 ms |
| `BEN-14` | NFT Revokes & Direct Transfers | Direct ERC-721 safeTransferFrom(from, to, tokenId) | `UNDERSTOOD` | `—` | 0.03 ms |
| `BEN-15` | NFT Revokes & Direct Transfers | Direct ERC-1155 safeTransferFrom(from, to, id, value, data) | `UNDERSTOOD` | `—` | 0.03 ms |
| `BEN-16` | NFT Revokes & Direct Transfers | Native ETH transfer of 0.05 ETH | `UNDERSTOOD` | `—` | 0.01 ms |
| `BEN-17` | NFT Revokes & Direct Transfers | Native ETH transfer of 1.0 ETH to WETH contract | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.01 ms |
| `BEN-18` | NFT Revokes & Direct Transfers | Capped on-chain Permit2 approve(USDC, router, 100 USDC, expiry) | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.03 ms |
| `BEN-19` | Benign Batches & SIWE Logins | multicall(bytes[]) bundling transfer + allowance revoke | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.08 ms |
| `BEN-20` | Benign Batches & SIWE Logins | Multicall3.aggregate3 bundling two safe token transfers | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.09 ms |
| `BEN-21` | Benign Batches & SIWE Logins | Multicall3.aggregate3Value sending ETH + capped 50 USDC approve | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.08 ms |
| `BEN-22` | Benign Batches & SIWE Logins | Standard Sign-In with Ethereum (SIWE) personal_sign message | `UNDERSTOOD` | `—` | 0.08 ms |
| `BEN-23` | Benign Batches & SIWE Logins | Plain-text wallet ownership login via personal_sign | `UNDERSTOOD` | `—` | 0.00 ms |
| `BEN-24` | Benign Batches & SIWE Logins | Readable off-chain governance snapshot vote via personal_sign | `UNDERSTOOD` | `—` | 0.03 ms |
| `BEN-25` | Benign Batches & SIWE Logins | Capped USDC approve verified via RPC (contract spender, non-proxy) | `UNDERSTOOD` | `KNOWN_CONTRACT_LABEL` | 0.27 ms |
| `BEN-26` | Benign Batches & SIWE Logins | Capped approve on EIP-1167 minimal clone contract (INFO clone note) | `UNDERSTOOD` | `EIP1167_MINIMAL_PROXY` | 0.22 ms |
| `BEN-27` | Complex Protocol Actions (Defensive Friction) | Paid Seaport NFT listing returning 1.5 ETH to offerer | `HIGH_RISK` | `SEAPORT_ORDER_SIGNATURE` | 0.03 ms |
| `BEN-28` | Complex Protocol Actions (Defensive Friction) | Capped EIP-2612 Permit (50 USDC on matching chain) | `REVIEW_NEEDED` | `GASLESS_PERMIT` | 0.02 ms |
| `BEN-29` | Complex Protocol Actions (Defensive Friction) | Capped Permit2 PermitSingle (25 USDC on matching chain) | `HIGH_RISK` | `PERMIT2_SIGNATURE` | 0.02 ms |
| `BEN-30` | Complex Protocol Actions (Defensive Friction) | Sourcify-verified custom stake(uint256,address) call | `REVIEW_NEEDED` | `SOURCIFY_CUSTOM_FUNCTION_REVIEW` | 0.48 ms |
| `BEN-31` | Complex Protocol Actions (Defensive Friction) | Custom DEX router selector in local-only mode (honest UNANALYZED) | `UNANALYZED` | `OPAQUE_CALLDATA` | 0.54 ms |
| `BEN-32` | Complex Protocol Actions (Defensive Friction) | Custom DAO ballot EIP-712 typed data (honest UNANALYZED) | `UNANALYZED` | `—` | 0.03 ms |
