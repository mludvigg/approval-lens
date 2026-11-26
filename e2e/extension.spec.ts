import { chromium, expect, test, type BrowserContext, type Page } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIST_PATH = path.resolve(__dirname, '../dist');
const LAB_URL = 'http://127.0.0.1:4173';

interface ForwardedWalletCall {
  method: string;
  params: unknown[];
}

declare global {
  interface Window {
    __walletForwardedRequests?: ForwardedWalletCall[];
  }
}

/**
 * Injects a deterministic EIP-1193 + EIP-6963 Sepolia wallet into dApp pages.
 * Records every signing request that actually reaches the underlying wallet in
 * window.__walletForwardedRequests so E2E tests can prove:
 *   1. Blocked requests NEVER reach the wallet.
 *   2. TOCTOU mutated payloads receive the frozen pre-mutation snapshot.
 */
function installMockSepoliaWallet() {
  const MOCK_ACCOUNT = '0x1111111111111111111111111111111111111111';
  const SEPOLIA_CHAIN_HEX = '0xaa36a7';
  const forwarded: ForwardedWalletCall[] = [];
  window.__walletForwardedRequests = forwarded;

  const rawProvider = {
    isMetaMask: true,
    chainId: SEPOLIA_CHAIN_HEX,
    async request(args: { method: string; params?: unknown[] }) {
      const { method, params = [] } = args;
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') {
        return [MOCK_ACCOUNT];
      }
      if (method === 'eth_chainId') {
        return SEPOLIA_CHAIN_HEX;
      }
      if (method === 'net_version') {
        return '11155111';
      }
      // Record intercepted signing methods that were ALLOWED through Approval Lens
      if (!window.__walletForwardedRequests) {
        window.__walletForwardedRequests = [];
      }
      window.__walletForwardedRequests.push({
        method,
        params: JSON.parse(JSON.stringify(params)),
      });
      return '0x' + 'ab'.repeat(32);
    },
  };

  // Expose via legacy EIP-1193 window.ethereum
  (window as unknown as { ethereum: unknown }).ethereum = rawProvider;

  // Announce via modern EIP-6963 multi-wallet discovery
  const announce = () => {
    window.dispatchEvent(
      new CustomEvent('eip6963:announceProvider', {
        detail: {
          info: {
            uuid: 'e2e-mock-sepolia-wallet',
            name: 'Mock Sepolia Wallet',
            icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"/>',
            rdns: 'dev.approvallens.mockwallet',
          },
          provider: rawProvider,
        },
      }),
    );
  };

  window.addEventListener('eip6963:requestProvider', announce);
  announce();
}

/**
 * Clicks a decision button inside review.html that immediately triggers chrome.windows.remove()
 * in the background service worker, handling the fast window-close IPC race cleanly.
 */
async function clickDecisionAndWaitClose(reviewPage: Page, buttonName: string) {
  const closedPromise = reviewPage.waitForEvent('close');
  await reviewPage
    .getByRole('button', { name: buttonName })
    .click()
    .catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes('Target page, context or browser has been closed')) {
        throw err;
      }
    });
  if (!reviewPage.isClosed()) {
    await closedPromise;
  }
}

test.describe('Approval Lens Chrome MV3 Extension — End-to-End Security Suite', () => {
  let context: BrowserContext;
  let userDataDir: string;
  let extensionId: string;
  let labPage: Page;

  test.beforeAll(async () => {
    userDataDir = mkdtempSync(path.join(os.tmpdir(), 'approval-lens-e2e-'));
    context = await chromium.launchPersistentContext(userDataDir, {
      channel: 'chromium',
      headless: true,
      locale: 'en-US',
      args: [
        `--disable-extensions-except=${DIST_PATH}`,
        `--load-extension=${DIST_PATH}`,
      ],
    });

    let [serviceWorker] = context.serviceWorkers();
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent('serviceworker');
    }
    extensionId = serviceWorker.url().split('/')[2];
    expect(extensionId).toBeTruthy();

    await context.addInitScript(installMockSepoliaWallet);

    labPage = await context.newPage();
    await labPage.goto(LAB_URL);
    await labPage.click('#connectBtn');
    await expect(labPage.locator('#accountStatus')).toContainText(
      '0x1111111111111111111111111111111111111111',
    );
  });

  test.afterAll(async () => {
    await context?.close();
    if (userDataDir) {
      rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('intercepts unlimited drainer (#2), enforces CRITICAL checkbox lock, switches EN/PT/ES live, and blocks wallet exposure', async () => {
    await labPage.evaluate(() => {
      window.__walletForwardedRequests = [];
    });

    const popupPromise = context.waitForEvent('page');
    await labPage.getByRole('button', { name: 'Trigger Unlimited Drainer' }).click();
    const reviewPage = await popupPromise;

    await reviewPage.waitForLoadState('domcontentloaded');
    expect(reviewPage.url()).toContain(`chrome-extension://${extensionId}/review.html?id=`);

    // Verify CRITICAL verdict banner & locked Proceed button
    await expect(reviewPage.locator('.impact-header')).toContainText('Known malicious indicator');
    const proceedBtn = reviewPage.getByRole('button', { name: 'Proceed to wallet' });
    await expect(proceedBtn).toBeDisabled();

    // Switch live to Português (BR) -> Español -> English with 0 reloads
    await reviewPage.getByRole('button', { name: 'PT', exact: true }).click();
    await expect(reviewPage.locator('.impact-body')).toContainText('TODO o seu saldo de USDC');
    await expect(
      reviewPage.getByRole('button', { name: 'Bloquear solicitação (Recomendado)' }),
    ).toBeVisible();

    await reviewPage.getByRole('button', { name: 'ES', exact: true }).click();
    await expect(reviewPage.locator('.impact-body')).toContainText('TODO tu saldo de USDC');
    await expect(
      reviewPage.getByRole('button', { name: 'Bloquear solicitud (Recomendado)' }),
    ).toBeVisible();

    await reviewPage.getByRole('button', { name: 'EN', exact: true }).click();

    // Verify checking the danger acknowledgement unlocks Proceed, and unchecking re-locks it
    const ackCheckbox = reviewPage.locator('.ack-box input[type="checkbox"]');
    await ackCheckbox.check();
    await expect(proceedBtn).toBeEnabled();
    await ackCheckbox.uncheck();
    await expect(proceedBtn).toBeDisabled();

    // Block the drainer request
    await clickDecisionAndWaitClose(reviewPage, 'Block request (Recommended)');
    await expect(labPage.locator('#log')).toContainText('[maliciousUnlimited] Rejected (4001)');

    // Confirm underlying wallet received 0 signing requests
    const forwardedCount = await labPage.evaluate(
      () => window.__walletForwardedRequests?.length ?? 0,
    );
    expect(forwardedCount).toBe(0);
  });

  test('defeats live TOCTOU bait-and-switch mutation (#9) by forwarding only the frozen 100 USDC snapshot', async () => {
    await labPage.evaluate(() => {
      window.__walletForwardedRequests = [];
    });

    const popupPromise = context.waitForEvent('page');
    await labPage.getByRole('button', { name: 'Trigger Bait-and-Switch' }).click();
    const reviewPage = await popupPromise;
    await reviewPage.waitForLoadState('domcontentloaded');

    // Confirm dApp already mutated txObj.data in memory while Review Window is open
    await expect(labPage.locator('#log')).toContainText(
      'Simulated TOCTOU bait-and-switch: mutated txObj.data AFTER calling request().',
    );

    // Review Window shows the safe 100 USDC pre-mutation snapshot
    await expect(reviewPage.locator('.amount-badge')).toContainText('100 USDC');
    await expect(reviewPage.locator('.impact-header')).toContainText('Understood');

    // User clicks Proceed to wallet
    await clickDecisionAndWaitClose(reviewPage, 'Proceed to wallet');
    await expect(labPage.locator('#log')).toContainText('[toctouMutation] Passed to wallet');

    // Inspect exact calldata received by the underlying Mock Wallet
    const forwarded = await labPage.evaluate(() => window.__walletForwardedRequests ?? []);
    expect(forwarded).toHaveLength(1);
    expect(forwarded[0].method).toBe('eth_sendTransaction');

    const forwardedTx = forwarded[0].params[0] as { to: string; data: string };
    // Must contain benign spender 2222...2222 and 100 USDC (0x05f5e100), NEVER 0xbad0...0bad or ffff...
    expect(forwardedTx.data.toLowerCase()).toContain('2222222222222222222222222222222222222222');
    expect(forwardedTx.data.toLowerCase()).toContain('05f5e100');
    expect(forwardedTx.data.toLowerCase()).not.toContain('bad0000000000000000000000000000000000bad');
    expect(forwardedTx.data.toLowerCase()).not.toContain('ffffffffffffffffffffffffffffffff');
  });

  test('enforces fail-closed blocking when Seaport 0-ETH drain (#11) review window is closed directly', async () => {
    await labPage.evaluate(() => {
      window.__walletForwardedRequests = [];
    });

    const popupPromise = context.waitForEvent('page');
    await labPage.getByRole('button', { name: 'Trigger Seaport 0-ETH Drain' }).click();
    const reviewPage = await popupPromise;
    await reviewPage.waitForLoadState('domcontentloaded');

    await expect(reviewPage.locator('.detail-ledger')).toContainText('You give 1 · Receive 0');
    await expect(reviewPage.getByRole('button', { name: 'Proceed to wallet' })).toBeDisabled();

    // Close the browser window without clicking Block or Proceed
    await reviewPage.close();

    // Background service worker must fail-closed (4001) and never forward to wallet
    await expect(labPage.locator('#log')).toContainText('[seaportZeroDrain] Rejected (4001)');
    const forwardedCount = await labPage.evaluate(
      () => window.__walletForwardedRequests?.length ?? 0,
    );
    expect(forwardedCount).toBe(0);
  });

  test('renders Toolbar Popup session history and toggles opt-in Sourcify ABI lookup cleanly', async () => {
    const popupPage = await context.newPage();
    await popupPage.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(popupPage.locator('.status-banner')).toContainText(
      '100% Local mode · 0 network calls',
    );
    await expect(
      popupPage.getByRole('heading', { name: /Session History \([1-9]\d*\)/ }),
    ).toBeVisible();

    // Toggle Verified ABI lookup (Sourcify) ON and back OFF (controlled async chrome.storage state)
    const sourcifyRow = popupPage.locator('label.toggle-row', {
      hasText: 'Verified ABI lookup (Sourcify)',
    });
    const sourcifyCheckbox = sourcifyRow.locator('input[type="checkbox"]');
    await sourcifyRow.click();
    await expect(sourcifyCheckbox).toBeChecked();
    await expect(popupPage.locator('.status-banner')).toContainText('Sourcify ABI enabled');

    await sourcifyRow.click();
    await expect(sourcifyCheckbox).not.toBeChecked();
    await expect(popupPage.locator('.status-banner')).toContainText(
      '100% Local mode · 0 network calls',
    );

    await popupPage.close();
  });
});
