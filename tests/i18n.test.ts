import { describe, expect, it } from 'vitest';
import { encodeFunctionData, maxUint256, parseAbi, type Address } from 'viem';
import { analyzeRequest } from '../src/core/analyzer';
import {
  buildPlainEnglishSummary,
  formatDeadline,
  formatTokenAmount,
} from '../src/core/format';
import {
  detectDefaultLocale,
  getLocalizedImpactHeadline,
  getLocalizedRequestHeader,
  getMessages,
  localizeFinding,
  localizeLimitation,
} from '../src/core/i18n';
import type { InspectionRequest } from '../src/core/types';

const ERC20_ABI = parseAbi(['function approve(address spender, uint256 amount)']);

const USER_WALLET = '0x1111111111111111111111111111111111111111' as Address;
const USDC_MAINNET = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as Address;
const MALICIOUS_SPENDER = '0xbad0000000000000000000000000000000000bad' as Address;
const SEAPORT_1_6 = '0x0000000000000068f116a894984e2db1123eb395' as Address;

function makeRequest(overrides: Partial<InspectionRequest>): InspectionRequest {
  return {
    requestId: 'test-i18n-001',
    createdAt: '2026-11-24T00:00:00.000Z',
    method: 'eth_sendTransaction',
    params: [],
    payloadHash: '0'.repeat(64),
    origin: 'https://app.example.org',
    walletName: 'MetaMask',
    chainIdHex: '0x1',
    ...overrides,
  };
}

describe('Approval Lens v0.2.5 — Local-First Multi-Language (i18n)', () => {
  it('detects default locale from browser language strings with English fallback', () => {
    expect(detectDefaultLocale('pt-BR')).toBe('pt-BR');
    expect(detectDefaultLocale('pt-PT')).toBe('pt-BR');
    expect(detectDefaultLocale('es-419')).toBe('es');
    expect(detectDefaultLocale('es')).toBe('es');
    expect(detectDefaultLocale('en-US')).toBe('en');
    expect(detectDefaultLocale('de-DE')).toBe('en');
    expect(detectDefaultLocale(undefined)).toBe('en');
  });

  it('localizes token amounts and expiration deadlines across en, pt-BR, and es', () => {
    expect(formatTokenAmount(maxUint256.toString(), 6, 'USDC', true, false, 'en')).toBe(
      'Unlimited USDC',
    );
    expect(formatTokenAmount(maxUint256.toString(), 6, 'USDC', true, false, 'pt-BR')).toBe(
      'Ilimitado USDC',
    );
    expect(formatTokenAmount(maxUint256.toString(), 6, 'USDC', true, false, 'es')).toBe(
      'Ilimitado USDC',
    );

    expect(formatDeadline('281474976710655', 'en')).toBe('Never expires');
    expect(formatDeadline('281474976710655', 'pt-BR')).toBe('Sem expiração');
    expect(formatDeadline('281474976710655', 'es')).toBe('Nunca expira');
  });

  it('translates drainer inspection summaries, headers, verdicts, findings, and limitations in pt-BR and es', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [MALICIOUS_SPENDER, maxUint256],
    });

    const result = await analyzeRequest(
      makeRequest({
        params: [{ from: USER_WALLET, to: USDC_MAINNET, data }],
      }),
    );

    const riskCount = result.findings.filter((f) => f.severity !== 'INFO').length;

    // Português (BR)
    const ptHeader = getLocalizedRequestHeader(result.decoded, 'app.example.org', 'pt-BR');
    expect(ptHeader.title).toContain('limite de gasto');
    expect(getLocalizedImpactHeadline(result, riskCount, 'pt-BR')).toContain(
      'Indicador malicioso conhecido',
    );
    expect(buildPlainEnglishSummary(result, 'pt-BR')).toContain('TODO o seu saldo de USDC');

    const unlFinding = result.findings.find((f) => f.id === 'UNLIMITED_ERC20_APPROVAL')!;
    expect(localizeFinding(unlFinding, 'pt-BR').title).toContain('ILIMITADA');
    expect(localizeLimitation(result.limitations[0], 'pt-BR')).toContain('simulação completa');
    expect(getMessages('pt-BR').blockRequestRecommended).toContain('Recomendado');

    // Español
    const esHeader = getLocalizedRequestHeader(result.decoded, 'app.example.org', 'es');
    expect(esHeader.title).toContain('límite de gasto');
    expect(getLocalizedImpactHeadline(result, riskCount, 'es')).toContain(
      'Indicador malicioso conocido',
    );
    expect(buildPlainEnglishSummary(result, 'es')).toContain('TODO tu saldo de USDC');
    expect(localizeFinding(unlFinding, 'es').title).toContain('ILIMITADA');
    expect(localizeLimitation(result.limitations[0], 'es')).toContain('simulación completa');
    expect(getMessages('es').proceedToWallet).toBe('Continuar a la billetera');
  });

  it('translates zero-ETH Seaport phishing summaries across all 3 languages', async () => {
    const seaportZero = JSON.stringify({
      primaryType: 'OrderComponents',
      domain: {
        name: 'Seaport',
        version: '1.6',
        chainId: 1,
        verifyingContract: SEAPORT_1_6,
      },
      message: {
        offerer: USER_WALLET,
        offer: [
          {
            itemType: 2,
            token: '0x3333333333333333333333333333333333333333',
            identifierOrCriteria: '1',
            startAmount: '1',
            endAmount: '1',
          },
        ],
        consideration: [],
      },
    });

    const res = await analyzeRequest(
      makeRequest({
        method: 'eth_signTypedData_v4',
        params: [USER_WALLET, seaportZero],
      }),
    );

    expect(buildPlainEnglishSummary(res, 'en')).toContain('DANGER:');
    expect(buildPlainEnglishSummary(res, 'pt-BR')).toContain('PERIGO:');
    expect(buildPlainEnglishSummary(res, 'es')).toContain('PELIGRO:');
  });
});
