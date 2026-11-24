import { shortAddr } from './decoders/calldata';
import type {
  DecodedAction,
  InspectionResult,
  Locale,
  RiskFinding,
  Severity,
  Verdict,
} from './types';

export interface LocaleOption {
  code: Locale;
  shortLabel: string;
  label: string;
}

export const SUPPORTED_LOCALES: ReadonlyArray<LocaleOption> = [
  { code: 'en', shortLabel: 'EN', label: 'English' },
  { code: 'pt-BR', shortLabel: 'PT', label: 'Português (BR)' },
  { code: 'es', shortLabel: 'ES', label: 'Español' },
];

export function isSupportedLocale(value: unknown): value is Locale {
  return value === 'en' || value === 'pt-BR' || value === 'es';
}

export function detectDefaultLocale(browserLanguage?: string): Locale {
  if (!browserLanguage || typeof browserLanguage !== 'string') return 'en';
  const normalized = browserLanguage.trim().toLowerCase();
  if (normalized.startsWith('pt')) return 'pt-BR';
  if (normalized.startsWith('es')) return 'es';
  return 'en';
}

export interface UiMessages {
  // Common / Header
  active: string;
  paused: string;
  localZeroRpcPill: string;
  rpcEnrichedPill: string;
  sourcifyLookupPill: string;
  rpcAndAbiPill: string;
  optInNetPill: string;
  localPill: string;
  themeSwitchTitle: (nextMode: 'light' | 'dark') => string;
  copyTitle: (text: string) => string;

  // Popup
  heroIntercepting: string;
  heroPaused: string;
  heroLocalSubtitle: string;
  heroOptInSubtitle: (features: string) => string;
  featureRpc: string;
  featureSourcify: string;
  controlsTitle: string;
  toggleInterceptTitle: string;
  toggleInterceptDesc: string;
  toggleRpcTitle: string;
  toggleRpcDesc: string;
  customRpcHint: string;
  saveBtn: string;
  toggleSourcifyTitle: string;
  toggleSourcifyDesc: string;
  settingsUpdated: string;
  historyTitle: (count: number) => string;
  clearBtn: string;
  historyEmpty: string;
  exportJson: string;
  exportHtml: string;

  // Review States
  loadingInspection: string;
  expiredTitle: string;
  expiredDesc: string;

  // Review Sections & Ledger
  spenderLabel: string;
  recipientLabel: string;
  maliciousDrainerFlag: string;
  tokenContractLabel: string;
  interactingWithLabel: string;
  deadlineLabel: string;
  orderBalanceLabel: string;
  seaportZeroBadge: (offerCount: number) => string;
  seaportPaidBadge: (offerCount: number, receiveCount: number) => string;
  decodedParamsHeading: (count: number) => string;
  nestedOpsHeading: (count: number) => string;
  securityEvidenceHeading: (count: number) => string;
  showTechProof: string;
  hideTechProof: string;
  noRiskRulesMatched: string;
  scopeNoSim: string;
  scopeNeverSafe: string;
  scopeOptInRpc: string;
  scopeZeroCalls: string;

  // Forensic Ledger
  forensicHeading: string;
  sha256Frozen: string;
  kvVerifiedOrigin: string;
  kvTopLevelPage: string;
  kvRpcMethod: string;
  kvDecodedAbi: string;
  kvTokenAndTarget: string;
  kvTargetContract: string;
  kvTokenContract: string;
  kvSpenderAddress: string;
  kvRecipientAddress: string;
  kvRawUnits: string;
  kvRawDeadline: string;
  kvFrozenSha256: string;
  payloadPreview: string;
  networkAuditHeading: (count: number) => string;
  notAnalyzedHeading: string;

  // Decision Footer
  dangerAckCheckbox: string;
  blockRequestCalm: string;
  blockRequestRecommended: string;
  proceedToWallet: string;

  // Token / Deadline Helpers
  unlimitedWord: string;
  rawUnitsWord: string;
  neverExpires: string;
  immediateExpired: string;
  unknownAddress: string;

  // Severity & Verdict Badges
  severityLabels: Record<Severity, string>;
  verdictLabels: Record<Verdict, string>;
}

const MESSAGES: Record<Locale, UiMessages> = {
  en: {
    active: 'Active',
    paused: 'Paused',
    localZeroRpcPill: 'Local · 0 RPC',
    rpcEnrichedPill: 'RPC Enriched',
    sourcifyLookupPill: 'Sourcify Lookup',
    rpcAndAbiPill: 'RPC + ABI Lookup',
    optInNetPill: 'Opt-in Net',
    localPill: 'Local',
    themeSwitchTitle: (next) =>
      `Switch to ${next === 'light' ? 'Pastel Light' : 'Pastel Dark'} mode`,
    copyTitle: (text) => `Copy ${text}`,

    heroIntercepting: 'Intercepting Wallet Approvals',
    heroPaused: 'Interception Paused',
    heroLocalSubtitle: '100% Local mode · 0 network calls',
    heroOptInSubtitle: (features) => `${features} enabled`,
    featureRpc: 'RPC enrichment',
    featureSourcify: 'Sourcify ABI',
    controlsTitle: 'Protection & Privacy Controls',
    toggleInterceptTitle: 'Intercept wallet requests',
    toggleInterceptDesc: 'Inspect approvals & signatures before MetaMask/Rabby opens',
    toggleRpcTitle: 'On-chain RPC enrichment',
    toggleRpcDesc:
      'Off = 100% local (0 network requests). On = reads allowance, token info & proxy slot.',
    customRpcHint: 'Optional custom RPC URL (leave blank for publicnode defaults)',
    saveBtn: 'Save',
    toggleSourcifyTitle: 'Verified ABI lookup (Sourcify)',
    toggleSourcifyDesc:
      'Off = local ABIs only. On = queries Sourcify v2 (+ 4byte fallback) for unknown calls.',
    settingsUpdated: 'Settings updated.',
    historyTitle: (count) => `Session History (${count})`,
    clearBtn: 'Clear',
    historyEmpty:
      'No requests inspected in this browser session yet. Trigger a transaction or signature on any dApp (or the local Attack Test Lab) to inspect it here.',
    exportJson: 'Export JSON',
    exportHtml: 'Export HTML',

    loadingInspection: 'Inspecting wallet request locally…',
    expiredTitle: 'No active inspection found',
    expiredDesc: 'This inspection has already completed or expired (fail-closed protection).',

    spenderLabel: 'Spender',
    recipientLabel: 'Recipient',
    maliciousDrainerFlag: 'Malicious drainer',
    tokenContractLabel: 'Token contract',
    interactingWithLabel: 'Interacting with',
    deadlineLabel: 'Deadline / Expiry',
    orderBalanceLabel: 'Order balance',
    seaportZeroBadge: (offer) => `You give ${offer} · Receive 0`,
    seaportPaidBadge: (offer, rec) => `Offer ${offer} · Receive ${rec}`,
    decodedParamsHeading: (count) => `Decoded parameters (${count})`,
    nestedOpsHeading: (count) => `Nested operations (${count})`,
    securityEvidenceHeading: (count) => `Security evidence (${count})`,
    showTechProof: 'Technical proof & scope',
    hideTechProof: 'Hide technical proof',
    noRiskRulesMatched:
      'No local risk rules matched. Always verify the website domain and recipient before signing.',
    scopeNoSim: '⊘ No EVM simulation',
    scopeNeverSafe: '⊘ Never 100% safe',
    scopeOptInRpc: '🌐 Opt-in RPC active',
    scopeZeroCalls: '🔒 0 network calls',

    forensicHeading: 'Forensic Evidence & Scope Ledger',
    sha256Frozen: 'SHA-256 Frozen',
    kvVerifiedOrigin: 'Verified origin',
    kvTopLevelPage: 'Top-level page',
    kvRpcMethod: 'RPC method',
    kvDecodedAbi: 'Decoded ABI',
    kvTokenAndTarget: 'Token & target',
    kvTargetContract: 'Target contract',
    kvTokenContract: 'Token contract',
    kvSpenderAddress: 'Spender address',
    kvRecipientAddress: 'Recipient address',
    kvRawUnits: 'Raw token units',
    kvRawDeadline: 'Raw deadline',
    kvFrozenSha256: 'Frozen SHA-256',
    payloadPreview: 'Payload preview',
    networkAuditHeading: (count) => `Network & privacy audit (${count})`,
    notAnalyzedHeading: 'What Was NOT Analyzed',

    dangerAckCheckbox:
      'I understand this request triggered a critical warning and may drain my assets if signed.',
    blockRequestCalm: 'Block request',
    blockRequestRecommended: 'Block request (Recommended)',
    proceedToWallet: 'Proceed to wallet',

    unlimitedWord: 'Unlimited',
    rawUnitsWord: 'raw units',
    neverExpires: 'Never expires',
    immediateExpired: 'Immediate / Expired',
    unknownAddress: 'an unknown address',

    severityLabels: {
      CRITICAL: 'Critical',
      HIGH: 'High risk',
      MEDIUM: 'Review',
      LOW: 'Low risk',
      INFO: 'Verified local',
    },
    verdictLabels: {
      KNOWN_MALICIOUS: 'KNOWN MALICIOUS',
      HIGH_RISK: 'HIGH RISK',
      REVIEW_NEEDED: 'REVIEW NEEDED',
      UNDERSTOOD: 'UNDERSTOOD',
      UNANALYZED: 'UNANALYZED',
    },
  },

  'pt-BR': {
    active: 'Ativo',
    paused: 'Pausado',
    localZeroRpcPill: 'Local · 0 RPC',
    rpcEnrichedPill: 'RPC Ativo',
    sourcifyLookupPill: 'Sourcify ABI',
    rpcAndAbiPill: 'RPC + Sourcify',
    optInNetPill: 'Rede Opcional',
    localPill: 'Local',
    themeSwitchTitle: (next) =>
      `Alternar para modo ${next === 'light' ? 'Claro Pastel' : 'Escuro Pastel'}`,
    copyTitle: (text) => `Copiar ${text}`,

    heroIntercepting: 'Interceptando Aprovações da Carteira',
    heroPaused: 'Interceptação Pausada',
    heroLocalSubtitle: 'Modo 100% Local · 0 chamadas de rede',
    heroOptInSubtitle: (features) => `${features} ativado`,
    featureRpc: 'Consulta RPC',
    featureSourcify: 'ABI Sourcify',
    controlsTitle: 'Controles de Proteção e Privacidade',
    toggleInterceptTitle: 'Interceptar solicitações da carteira',
    toggleInterceptDesc: 'Inspeciona aprovações e assinaturas antes de abrir MetaMask/Rabby',
    toggleRpcTitle: 'Enriquecimento RPC on-chain',
    toggleRpcDesc:
      'Desligado = 100% local (0 requisições). Ligado = lê allowance atual, token e proxy.',
    customRpcHint: 'URL RPC personalizada opcional (deixe vazio para usar publicnode)',
    saveBtn: 'Salvar',
    toggleSourcifyTitle: 'Consulta de ABI verificada (Sourcify)',
    toggleSourcifyDesc:
      'Desligado = apenas ABIs locais. Ligado = consulta Sourcify v2 (+ 4byte) em chamadas desconhecidas.',
    settingsUpdated: 'Configurações salvas.',
    historyTitle: (count) => `Histórico da Sessão (${count})`,
    clearBtn: 'Limpar',
    historyEmpty:
      'Nenhuma solicitação inspecionada nesta sessão ainda. Acione uma transação ou assinatura em qualquer dApp (ou no Attack Test Lab) para vê-la aqui.',
    exportJson: 'Exportar JSON',
    exportHtml: 'Exportar HTML',

    loadingInspection: 'Inspecionando solicitação localmente…',
    expiredTitle: 'Nenhuma inspeção ativa encontrada',
    expiredDesc: 'Esta inspeção já foi concluída ou expirou (proteção fail-closed).',

    spenderLabel: 'Gastador (Spender)',
    recipientLabel: 'Destinatário',
    maliciousDrainerFlag: 'Drainer malicioso',
    tokenContractLabel: 'Contrato do token',
    interactingWithLabel: 'Interagindo com',
    deadlineLabel: 'Prazo / Expiração',
    orderBalanceLabel: 'Balanço da ordem',
    seaportZeroBadge: (offer) => `Você entrega ${offer} · Recebe 0`,
    seaportPaidBadge: (offer, rec) => `Oferta ${offer} · Recebe ${rec}`,
    decodedParamsHeading: (count) => `Parâmetros decodificados (${count})`,
    nestedOpsHeading: (count) => `Operações aninhadas (${count})`,
    securityEvidenceHeading: (count) => `Evidências de segurança (${count})`,
    showTechProof: 'Prova técnica e escopo',
    hideTechProof: 'Ocultar prova técnica',
    noRiskRulesMatched:
      'Nenhuma regra local de risco disparou. Sempre verifique o domínio do site e o destinatário antes de assinar.',
    scopeNoSim: '⊘ Sem simulação EVM',
    scopeNeverSafe: '⊘ Nunca 100% seguro',
    scopeOptInRpc: '🌐 RPC opcional ativo',
    scopeZeroCalls: '🔒 0 chamadas de rede',

    forensicHeading: 'Evidências Forenses e Limites de Escopo',
    sha256Frozen: 'SHA-256 Congelado',
    kvVerifiedOrigin: 'Origem verificada',
    kvTopLevelPage: 'Página principal',
    kvRpcMethod: 'Método RPC',
    kvDecodedAbi: 'ABI decodificada',
    kvTokenAndTarget: 'Token e alvo',
    kvTargetContract: 'Contrato alvo',
    kvTokenContract: 'Contrato do token',
    kvSpenderAddress: 'Endereço gastador',
    kvRecipientAddress: 'Endereço destinatário',
    kvRawUnits: 'Unidades brutas',
    kvRawDeadline: 'Prazo bruto',
    kvFrozenSha256: 'SHA-256 congelado',
    payloadPreview: 'Prévia do payload',
    networkAuditHeading: (count) => `Auditoria de rede e privacidade (${count})`,
    notAnalyzedHeading: 'O Que NÃO Foi Analisado',

    dangerAckCheckbox:
      'Eu entendo que esta solicitação acionou um alerta crítico e pode drenar meus ativos se for assinada.',
    blockRequestCalm: 'Bloquear solicitação',
    blockRequestRecommended: 'Bloquear solicitação (Recomendado)',
    proceedToWallet: 'Prosseguir para a carteira',

    unlimitedWord: 'Ilimitado',
    rawUnitsWord: 'unidades brutas',
    neverExpires: 'Sem expiração',
    immediateExpired: 'Imediato / Expirado',
    unknownAddress: 'um endereço desconhecido',

    severityLabels: {
      CRITICAL: 'Crítico',
      HIGH: 'Alto risco',
      MEDIUM: 'Revisar',
      LOW: 'Baixo risco',
      INFO: 'Verificado local',
    },
    verdictLabels: {
      KNOWN_MALICIOUS: 'MALICIOSO CONHECIDO',
      HIGH_RISK: 'ALTO RISCO',
      REVIEW_NEEDED: 'REVISÃO NECESSÁRIA',
      UNDERSTOOD: 'COMPREENDIDO',
      UNANALYZED: 'NÃO ANALISADO',
    },
  },

  es: {
    active: 'Activo',
    paused: 'Pausado',
    localZeroRpcPill: 'Local · 0 RPC',
    rpcEnrichedPill: 'RPC Activo',
    sourcifyLookupPill: 'Sourcify ABI',
    rpcAndAbiPill: 'RPC + Sourcify',
    optInNetPill: 'Red Opcional',
    localPill: 'Local',
    themeSwitchTitle: (next) =>
      `Cambiar a modo ${next === 'light' ? 'Claro Pastel' : 'Oscuro Pastel'}`,
    copyTitle: (text) => `Copiar ${text}`,

    heroIntercepting: 'Interceptando Aprobaciones de Billetera',
    heroPaused: 'Interceptación en Pausa',
    heroLocalSubtitle: 'Modo 100% Local · 0 llamadas de red',
    heroOptInSubtitle: (features) => `${features} activado`,
    featureRpc: 'Consulta RPC',
    featureSourcify: 'ABI Sourcify',
    controlsTitle: 'Controles de Protección y Privacidad',
    toggleInterceptTitle: 'Interceptar solicitudes de billetera',
    toggleInterceptDesc: 'Inspecciona aprobaciones y firmas antes de abrir MetaMask/Rabby',
    toggleRpcTitle: 'Enriquecimiento RPC on-chain',
    toggleRpcDesc:
      'Apagado = 100% local (0 peticiones). Encendido = lee allowance actual, token y proxy.',
    customRpcHint: 'URL RPC personalizada opcional (dejar vacío para usar publicnode)',
    saveBtn: 'Guardar',
    toggleSourcifyTitle: 'Consulta de ABI verificada (Sourcify)',
    toggleSourcifyDesc:
      'Apagado = solo ABIs locales. Encendido = consulta Sourcify v2 (+ 4byte) en llamadas desconocidas.',
    settingsUpdated: 'Configuración actualizada.',
    historyTitle: (count) => `Historial de Sesión (${count})`,
    clearBtn: 'Borrar',
    historyEmpty:
      'Aún no se inspeccionaron solicitudes en esta sesión. Inicia una transacción o firma en cualquier dApp (o en el Attack Test Lab) para verla aquí.',
    exportJson: 'Exportar JSON',
    exportHtml: 'Exportar HTML',

    loadingInspection: 'Inspeccionando solicitud localmente…',
    expiredTitle: 'No se encontró ninguna inspección activa',
    expiredDesc: 'Esta inspección ya finalizó o expiró (protección fail-closed).',

    spenderLabel: 'Autorizado (Spender)',
    recipientLabel: 'Destinatario',
    maliciousDrainerFlag: 'Drainer malicioso',
    tokenContractLabel: 'Contrato del token',
    interactingWithLabel: 'Interactuando con',
    deadlineLabel: 'Vencimiento / Expiración',
    orderBalanceLabel: 'Balance de la orden',
    seaportZeroBadge: (offer) => `Entregas ${offer} · Recibes 0`,
    seaportPaidBadge: (offer, rec) => `Ofreces ${offer} · Recibes ${rec}`,
    decodedParamsHeading: (count) => `Parámetros decodificados (${count})`,
    nestedOpsHeading: (count) => `Operaciones anidadas (${count})`,
    securityEvidenceHeading: (count) => `Evidencia de seguridad (${count})`,
    showTechProof: 'Prueba técnica y alcance',
    hideTechProof: 'Ocultar prueba técnica',
    noRiskRulesMatched:
      'No se activaron reglas locales de riesgo. Verifica siempre el dominio del sitio y el destinatario antes de firmar.',
    scopeNoSim: '⊘ Sin simulación EVM',
    scopeNeverSafe: '⊘ Nunca 100% seguro',
    scopeOptInRpc: '🌐 RPC opcional activo',
    scopeZeroCalls: '🔒 0 llamadas de red',

    forensicHeading: 'Evidencia Forense y Límites de Alcance',
    sha256Frozen: 'SHA-256 Congelado',
    kvVerifiedOrigin: 'Origen verificado',
    kvTopLevelPage: 'Página principal',
    kvRpcMethod: 'Método RPC',
    kvDecodedAbi: 'ABI decodificada',
    kvTokenAndTarget: 'Token y destino',
    kvTargetContract: 'Contrato destino',
    kvTokenContract: 'Contrato del token',
    kvSpenderAddress: 'Dirección autorizada',
    kvRecipientAddress: 'Dirección destinataria',
    kvRawUnits: 'Unidades brutas',
    kvRawDeadline: 'Vencimiento bruto',
    kvFrozenSha256: 'SHA-256 congelado',
    payloadPreview: 'Vista previa del payload',
    networkAuditHeading: (count) => `Auditoría de red y privacidad (${count})`,
    notAnalyzedHeading: 'Lo Que NO Se Analizó',

    dangerAckCheckbox:
      'Entiendo que esta solicitud activó una alerta crítica y puede vaciar mis activos si la firmo.',
    blockRequestCalm: 'Bloquear solicitud',
    blockRequestRecommended: 'Bloquear solicitud (Recomendado)',
    proceedToWallet: 'Continuar a la billetera',

    unlimitedWord: 'Ilimitado',
    rawUnitsWord: 'unidades brutas',
    neverExpires: 'Nunca expira',
    immediateExpired: 'Inmediato / Expirado',
    unknownAddress: 'una dirección desconocida',

    severityLabels: {
      CRITICAL: 'Crítico',
      HIGH: 'Alto riesgo',
      MEDIUM: 'Revisar',
      LOW: 'Bajo riesgo',
      INFO: 'Verificado local',
    },
    verdictLabels: {
      KNOWN_MALICIOUS: 'MALICIOSO CONOCIDO',
      HIGH_RISK: 'ALTO RIESGO',
      REVIEW_NEEDED: 'REVISIÓN NECESARIA',
      UNDERSTOOD: 'COMPRENDIDO',
      UNANALYZED: 'SIN ANALIZAR',
    },
  },
};

export function getMessages(locale: Locale = 'en'): UiMessages {
  return MESSAGES[locale] ?? MESSAGES.en;
}

export function getLocalizedRequestHeader(
  decoded: DecodedAction,
  originHost: string,
  locale: Locale = 'en',
): { title: string; subtitle: string } {
  if (locale === 'pt-BR') {
    switch (decoded.kind) {
      case 'ERC20_APPROVE':
      case 'ERC20_INCREASE_ALLOWANCE':
        return {
          title: 'Solicitação de limite de gasto',
          subtitle: `${originHost} pede permissão para movimentar seus tokens`,
        };
      case 'ERC20_DECREASE_ALLOWANCE':
        return {
          title: 'Redução de limite de gasto',
          subtitle: `${originHost} está reduzindo uma permissão existente de tokens`,
        };
      case 'ERC20_TRANSFER':
      case 'ERC20_TRANSFER_FROM':
      case 'NATIVE_TRANSFER':
        return {
          title: 'Solicitação de transferência',
          subtitle: `${originHost} solicita enviar ativos diretamente da sua carteira`,
        };
      case 'NFT_SET_APPROVAL_FOR_ALL':
        return {
          title: 'Acesso total à coleção de NFTs',
          subtitle: `${originHost} quer controle sobre todos os NFTs desta coleção`,
        };
      case 'NFT_TRANSFER':
        return {
          title: 'Transferência de NFT',
          subtitle: `${originHost} solicita transferir um NFT específico`,
        };
      case 'EIP2612_PERMIT':
      case 'PERMIT2_SINGLE':
      case 'PERMIT2_BATCH':
      case 'PERMIT2_TRANSFER_FROM':
        return {
          title: 'Permissão de gasto sem gás (Permit)',
          subtitle: `${originHost} pede uma assinatura off-chain que autoriza gasto de tokens`,
        };
      case 'SEAPORT_ORDER':
        return {
          title: 'Assinatura de ordem no marketplace',
          subtitle: `${originHost} solicita uma ordem Seaport off-chain para transferir ativos`,
        };
      case 'BLUR_ORDER':
        return {
          title:
            decoded.functionName === 'Blur.BulkOrderRoot'
              ? 'Assinatura em lote no marketplace'
              : 'Assinatura de ordem no marketplace',
          subtitle: `${originHost} solicita assinar uma ordem Blur de NFT off-chain`,
        };
      case 'MULTICALL':
        return {
          title: 'Transação em lote (Multicall)',
          subtitle: `${originHost} agrupou ${decoded.subActions?.length ?? 'várias'} operações em uma única chamada`,
        };
      case 'RAW_ETH_SIGN':
        return {
          title: 'Assinatura às cegas (eth_sign)',
          subtitle: `${originHost} pede para assinar um hash bruto de 32 bytes sem leitura humana`,
        };
      case 'PERSONAL_SIGN':
        return {
          title: 'Assinatura de mensagem',
          subtitle: `${originHost} pede uma assinatura de texto para comprovar posse da carteira`,
        };
      case 'SOURCIFY_DECODED':
        return {
          title: 'Interação com contrato verificado',
          subtitle: `${originHost} está chamando ${decoded.functionName ?? 'uma função verificada'} (via Sourcify)`,
        };
      case 'TYPED_DATA_GENERIC':
        return {
          title: 'Assinatura de dados estruturados',
          subtitle: `${originHost} solicita uma assinatura EIP-712 com esquema personalizado`,
        };
      case 'UNKNOWN_CALLDATA':
      default:
        return {
          title: 'Chamada de contrato não verificada',
          subtitle: `${originHost} chama uma função que não pôde ser decodificada localmente`,
        };
    }
  }

  if (locale === 'es') {
    switch (decoded.kind) {
      case 'ERC20_APPROVE':
      case 'ERC20_INCREASE_ALLOWANCE':
        return {
          title: 'Solicitud de límite de gasto',
          subtitle: `${originHost} pide permiso para retirar tus tokens`,
        };
      case 'ERC20_DECREASE_ALLOWANCE':
        return {
          title: 'Reducción de límite de gasto',
          subtitle: `${originHost} está reduciendo un permiso existente de tokens`,
        };
      case 'ERC20_TRANSFER':
      case 'ERC20_TRANSFER_FROM':
      case 'NATIVE_TRANSFER':
        return {
          title: 'Solicitud de transferencia',
          subtitle: `${originHost} solicita enviar activos directamente desde tu billetera`,
        };
      case 'NFT_SET_APPROVAL_FOR_ALL':
        return {
          title: 'Acceso total a colección NFT',
          subtitle: `${originHost} quiere control de operador sobre todos los NFTs de esta colección`,
        };
      case 'NFT_TRANSFER':
        return {
          title: 'Transferencia de NFT',
          subtitle: `${originHost} solicita transferir un NFT específico`,
        };
      case 'EIP2612_PERMIT':
      case 'PERMIT2_SINGLE':
      case 'PERMIT2_BATCH':
      case 'PERMIT2_TRANSFER_FROM':
        return {
          title: 'Permiso de gasto sin gas (Permit)',
          subtitle: `${originHost} pide una firma off-chain que autoriza gastar tokens`,
        };
      case 'SEAPORT_ORDER':
        return {
          title: 'Firma de orden de marketplace',
          subtitle: `${originHost} solicita una orden Seaport off-chain que autoriza transferir activos`,
        };
      case 'BLUR_ORDER':
        return {
          title:
            decoded.functionName === 'Blur.BulkOrderRoot'
              ? 'Firma masiva de marketplace'
              : 'Firma de orden de marketplace',
          subtitle: `${originHost} solicita firmar una orden Blur de NFT off-chain`,
        };
      case 'MULTICALL':
        return {
          title: 'Solicitud por lotes (Multicall)',
          subtitle: `${originHost} agrupa ${decoded.subActions?.length ?? 'múltiples'} operaciones en una sola llamada`,
        };
      case 'RAW_ETH_SIGN':
        return {
          title: 'Firma a ciegas (eth_sign)',
          subtitle: `${originHost} pide firmar un hash sin formato de 32 bytes`,
        };
      case 'PERSONAL_SIGN':
        return {
          title: 'Firma de mensaje',
          subtitle: `${originHost} pide una firma de texto para verificar propiedad`,
        };
      case 'SOURCIFY_DECODED':
        return {
          title: 'Interacción con contrato verificado',
          subtitle: `${originHost} llama a ${decoded.functionName ?? 'una función verificada'} (vía Sourcify)`,
        };
      case 'TYPED_DATA_GENERIC':
        return {
          title: 'Firma de datos estructurados',
          subtitle: `${originHost} solicita una firma EIP-712 con esquema personalizado`,
        };
      case 'UNKNOWN_CALLDATA':
      default:
        return {
          title: 'Solicitud de contrato no verificada',
          subtitle: `${originHost} llama a una función que no pudo decodificarse localmente`,
        };
    }
  }

  // English default
  switch (decoded.kind) {
    case 'ERC20_APPROVE':
    case 'ERC20_INCREASE_ALLOWANCE':
      return {
        title: 'Spending cap request',
        subtitle: `${originHost} wants permission to withdraw your tokens`,
      };
    case 'ERC20_DECREASE_ALLOWANCE':
      return {
        title: 'Update spending cap',
        subtitle: `${originHost} is reducing an existing token allowance`,
      };
    case 'ERC20_TRANSFER':
    case 'ERC20_TRANSFER_FROM':
    case 'NATIVE_TRANSFER':
      return {
        title: 'Asset transfer request',
        subtitle: `${originHost} is requesting a direct transfer from your wallet`,
      };
    case 'NFT_SET_APPROVAL_FOR_ALL':
      return {
        title: 'NFT collection access request',
        subtitle: `${originHost} wants operator control over every NFT in this collection`,
      };
    case 'NFT_TRANSFER':
      return {
        title: 'NFT transfer request',
        subtitle: `${originHost} wants to transfer a specific NFT`,
      };
    case 'EIP2612_PERMIT':
    case 'PERMIT2_SINGLE':
    case 'PERMIT2_BATCH':
    case 'PERMIT2_TRANSFER_FROM':
      return {
        title: 'Gasless spending permit',
        subtitle: `${originHost} is requesting an off-chain token spending signature`,
      };
    case 'SEAPORT_ORDER':
      return {
        title: 'Marketplace listing signature',
        subtitle: `${originHost} is requesting an off-chain Seaport order authorizing asset transfers`,
      };
    case 'BLUR_ORDER':
      return {
        title:
          decoded.functionName === 'Blur.BulkOrderRoot'
            ? 'Bulk marketplace root signature'
            : 'Marketplace listing signature',
        subtitle: `${originHost} is requesting an off-chain Blur NFT order signature`,
      };
    case 'MULTICALL':
      return {
        title: 'Bundled batch request',
        subtitle: `${originHost} is bundling ${decoded.subActions?.length ?? 'multiple'} operations in one call`,
      };
    case 'RAW_ETH_SIGN':
      return {
        title: 'Blind signature request',
        subtitle: `${originHost} is requesting an unformatted 32-byte hash signature`,
      };
    case 'PERSONAL_SIGN':
      return {
        title: 'Message signature request',
        subtitle: `${originHost} is requesting a text signature to verify ownership`,
      };
    case 'SOURCIFY_DECODED':
      return {
        title: 'Verified contract interaction',
        subtitle: `${originHost} is calling ${decoded.functionName ?? 'a verified function'} (decoded via Sourcify)`,
      };
    case 'TYPED_DATA_GENERIC':
      return {
        title: 'Structured data signature',
        subtitle: `${originHost} is requesting an EIP-712 signature with a custom schema`,
      };
    case 'UNKNOWN_CALLDATA':
    default:
      return {
        title: 'Unverified contract request',
        subtitle: `${originHost} is calling a contract function that could not be decoded locally`,
      };
  }
}

export function getLocalizedImpactHeadline(
  result: InspectionResult,
  riskCount: number,
  locale: Locale = 'en',
): string {
  if (locale === 'pt-BR') {
    switch (result.verdict) {
      case 'KNOWN_MALICIOUS':
        return `${riskCount} ${riskCount === 1 ? 'risco detectado' : 'riscos detectados'} · Indicador malicioso conhecido`;
      case 'HIGH_RISK':
        return `${riskCount} ${riskCount === 1 ? 'risco detectado' : 'riscos detectados'} · Permissão de alto risco`;
      case 'REVIEW_NEEDED':
        return `${riskCount} ${riskCount === 1 ? 'alerta detectado' : 'alertas detectados'} · Revise com atenção`;
      case 'UNANALYZED':
        return 'Chamada não verificada · Não é possível confirmar a intenção';
      case 'UNDERSTOOD':
      default:
        return 'Compreendido · Nenhum sinal de risco conhecido';
    }
  }

  if (locale === 'es') {
    switch (result.verdict) {
      case 'KNOWN_MALICIOUS':
        return `${riskCount} ${riskCount === 1 ? 'riesgo detectado' : 'riesgos detectados'} · Indicador malicioso conocido`;
      case 'HIGH_RISK':
        return `${riskCount} ${riskCount === 1 ? 'riesgo detectado' : 'riesgos detectados'} · Permiso de alto riesgo`;
      case 'REVIEW_NEEDED':
        return `${riskCount} ${riskCount === 1 ? 'alerta detectada' : 'alertas detectadas'} · Revisar con cuidado`;
      case 'UNANALYZED':
        return 'Llamada no verificada · No se puede confirmar la intención';
      case 'UNDERSTOOD':
      default:
        return 'Comprendido · Sin señales de riesgo conocidas';
    }
  }

  switch (result.verdict) {
    case 'KNOWN_MALICIOUS':
      return `${riskCount} ${riskCount === 1 ? 'risk' : 'risks'} detected · Known malicious indicator`;
    case 'HIGH_RISK':
      return `${riskCount} ${riskCount === 1 ? 'risk' : 'risks'} detected · High-risk permission`;
    case 'REVIEW_NEEDED':
      return `${riskCount} ${riskCount === 1 ? 'warning' : 'warnings'} detected · Review carefully`;
    case 'UNANALYZED':
      return 'Unverified contract call · Cannot confirm intent';
    case 'UNDERSTOOD':
    default:
      return 'Understood · No known risk flags matched';
  }
}

export function localizeFinding(
  finding: RiskFinding,
  locale: Locale = 'en',
): { title: string; explanation: string } {
  if (locale === 'en') {
    return { title: finding.title, explanation: finding.explanation };
  }

  const d = finding.details ?? {};

  if (locale === 'pt-BR') {
    switch (finding.id) {
      case 'KNOWN_MALICIOUS_ORIGIN':
        return {
          title: `Origem maliciosa conhecida: ${d.domain ?? ''}`.trim(),
          explanation: `Este domínio (${d.origin ?? d.domain ?? 'desconhecido'}) consta na lista local de inteligência contra phishing.`,
        };
      case 'CROSS_ORIGIN_IFRAME':
        return {
          title: 'Solicitação iniciada por um iframe de outra origem',
          explanation: `Um quadro embutido (${d.frameOrigin ?? '?'}) disparou a assinatura dentro da página principal (${d.topLevelOrigin ?? '?'}). Confirme se você confia em ambos.`,
        };
      case 'EIP712_CHAIN_MISMATCH':
        return {
          title: 'Chain ID da assinatura diferente da rede ativa da carteira',
          explanation: `Sua carteira está na rede ${d.activeChainId ?? '?'}, mas a mensagem assinada especifica a rede ${d.domainChainId ?? '?'}. Golpistas pedem aprovações na Mainnet enquanto você acha que está em uma testnet.`,
        };
      case 'KNOWN_MALICIOUS_ADDRESS':
        return {
          title: finding.title.replace(/^Malicious /, 'Endereço malicioso — '),
          explanation: `Endereço (${shortAddr(String(d.address ?? ''))}) marcado na base local de ameaças por drenagem de ativos.`,
        };
      case 'KNOWN_CONTRACT_LABEL':
        return {
          title: `Contrato reconhecido: ${d.name ?? ''}`.trim(),
          explanation: finding.explanation,
        };
      case 'RAW_ETH_SIGN':
        return {
          title: 'Assinatura às cegas perigosa (eth_sign)',
          explanation:
            'eth_sign assina um hash opaco de 32 bytes sem estrutura legível. dApps modernos legítimos quase nunca exigem eth_sign porque ele pode autorizar transações arbitrárias.',
        };
      case 'MULTICALL_HIDDEN_UNLIMITED_APPROVAL':
        return {
          title: 'Aprovação ERC-20 ILIMITADA oculta dentro de multicall',
          explanation: `Concede a ${shortAddr(String(d.spender ?? ''))} permissão para gastar TODO o seu saldo deste token até ser revogada — descoberta oculta dentro de um lote multicall.`,
        };
      case 'UNLIMITED_ERC20_APPROVAL':
        return {
          title: 'Aprovação ILIMITADA de token ERC-20 solicitada',
          explanation: `Concede a ${shortAddr(String(d.spender ?? ''))} permissão para retirar TODO o seu saldo atual e futuro deste token até que você revogue.`,
        };
      case 'NFT_APPROVAL_FOR_ALL':
        return {
          title: 'Aprovação total da coleção de NFTs (setApprovalForAll)',
          explanation: `Permite que ${shortAddr(String(d.operator ?? ''))} transfira TODOS os NFTs que você possui na coleção ${shortAddr(String(d.collection ?? ''))} sem pedir nova confirmação.`,
        };
      case 'GASLESS_PERMIT_UNLIMITED':
        return {
          title: 'Permit EIP-2612 sem gás concede aprovação ILIMITADA',
          explanation: `Mesmo sendo uma assinatura gratuita off-chain agora, qualquer pessoa com ela pode enviá-la on-chain para permitir que ${shortAddr(String(d.spender ?? ''))} gaste todos os seus tokens.`,
        };
      case 'GASLESS_PERMIT':
        return {
          title: 'Permit EIP-2612 sem gás concede permissão de gasto',
          explanation: `Assinatura off-chain que autoriza ${shortAddr(String(d.spender ?? ''))} a movimentar seus tokens sem que você pague gás agora.`,
        };
      case 'PERMIT2_UNLIMITED':
        return {
          title: 'Assinatura Permit2 sem gás concede permissão ILIMITADA',
          explanation: `Assinaturas Permit2 permitem que ${shortAddr(String(d.spender ?? ''))} retire tokens já aprovados no Uniswap Permit2. Verifique o endereço com cuidado.`,
        };
      case 'PERMIT2_SIGNATURE':
        return {
          title:
            finding.title.includes('BATCH')
              ? 'Aprovação Permit2 em LOTE para múltiplos tokens'
              : 'Assinatura Permit2 sem gás autoriza gasto de tokens',
          explanation: `Permite que ${shortAddr(String(d.spender ?? ''))} retire tokens via Uniswap Permit2 sem taxa de gás imediata.`,
        };
      case 'SEAPORT_ZERO_CONSIDERATION_DRAIN':
        return {
          title: 'Ordem Seaport entrega seus ativos em troca de 0 pagamento',
          explanation:
            'Sua carteira oferece NFT(s) ou token(s), enquanto o valor pago de volta ao seu endereço é 0. Padrão clássico de golpe phishing Seaport.',
        };
      case 'SEAPORT_ORDER_SIGNATURE':
        return {
          title: 'Ordem off-chain de marketplace NFT (Seaport)',
          explanation:
            'Assinar uma ordem Seaport pode listar ou transferir seus NFTs pelo valor especificado no payload. Confira os itens recebidos com atenção.',
        };
      case 'BLUR_ZERO_PRICE_DRAIN':
        return {
          title: 'Ordem de venda Blur lista NFT por preço 0 (ou irrisório)',
          explanation:
            'Esta assinatura lista seu NFT por 0 (ou <= 1000 wei), permitindo que um atacante o capture praticamente de graça.',
        };
      case 'BLUR_BULK_ROOT_SIGNATURE':
        return {
          title: 'Raiz Merkle em lote da Blur oculta preços individuais',
          explanation:
            'Uma assinatura Root da Blur autoriza várias listagens de NFTs de uma só vez. Os preços individuais ficam ocultos no hash da raiz.',
        };
      case 'BLUR_ORDER_SIGNATURE':
        return {
          title: 'Ordem off-chain de marketplace NFT (Blur)',
          explanation:
            'Autoriza transferências de NFTs ou lances conforme os parâmetros assinados. Confira a coleção e o preço.',
        };
      case 'OPAQUE_CALLDATA':
        return {
          title: 'Calldata não pôde ser decodificado localmente',
          explanation: `O seletor de função ${d.selector ?? '(nenhum)'} não consta no conjunto local de ABIs verificadas. O Approval Lens recusa adivinhar o que este contrato fará.`,
        };
      case 'EOA_SPENDER_DETECTED':
        return {
          title: 'O gastador é uma carteira comum (EOA), não um contrato inteligente',
          explanation: `O endereço ${shortAddr(String(d.spender ?? ''))} não possui código de contrato implantado. Protocolos DeFi legítimos usam contratos inteligentes — aprovar uma EOA é um forte sinal de golpe.`,
        };
      case 'EIP1967_BEACON_PROXY':
        return {
          title: 'Contrato alvo usa um proxy atualizável EIP-1967 Beacon',
          explanation: `O contrato beacon ${shortAddr(String(d.beacon ?? ''))} aponta para a implementação ${shortAddr(String(d.implementation ?? ''))}. O administrador pode alterar a lógica de todos os proxies conectados.`,
        };
      case 'EIP1167_MINIMAL_PROXY':
        return {
          title: 'Contrato alvo é um clone mínimo EIP-1167',
          explanation: `Delega chamadas para a implementação mestre ${shortAddr(String(d.implementation ?? ''))}.`,
        };
      case 'EIP1967_PROXY_CONTRACT':
        return {
          title: 'Contrato alvo usa um proxy atualizável EIP-1967',
          explanation: `A implementação atual resolve para ${shortAddr(String(d.implementation ?? ''))}. Contratos proxy podem mudar de comportamento se o admin atualizar a implementação.`,
        };
      case 'SOURCIFY_VERIFIED_DECODE':
        return {
          title: 'ABI do contrato verificada via Sourcify',
          explanation: `Função ${d.functionSignature ?? ''} decodificada a partir do código-fonte verificado no Sourcify v2.`,
        };
      case 'SOURCIFY_CUSTOM_FUNCTION_REVIEW':
        return {
          title: 'Chamada de função personalizada requer revisão',
          explanation:
            'O nome da função e os parâmetros foram verificados via Sourcify, mas a lógica interna do contrato ainda pode movimentar ativos depositados.',
        };
      case 'FOURBYTE_UNVERIFIED_GUESS':
        return {
          title: `Correspondência 4-byte não verificada: ${d.signature ?? ''}`.trim(),
          explanation:
            'Seletor encontrado apenas no diretório público 4byte (código-fonte NÃO verificado no Sourcify). Contratos maliciosos podem forjar colisões de seletores de 4 bytes.',
        };
      default:
        return { title: finding.title, explanation: finding.explanation };
    }
  }

  // Español ('es')
  switch (finding.id) {
    case 'KNOWN_MALICIOUS_ORIGIN':
      return {
        title: `Origen malicioso conocido: ${d.domain ?? ''}`.trim(),
        explanation: `Este dominio (${d.origin ?? d.domain ?? 'desconocido'}) figura en la lista local de inteligencia contra phishing.`,
      };
    case 'CROSS_ORIGIN_IFRAME':
      return {
        title: 'Solicitud iniciada desde un iframe de otro origen',
        explanation: `Un marco incrustado (${d.frameOrigin ?? '?'}) activó la firma dentro de la página principal (${d.topLevelOrigin ?? '?'}). Verifica que confíes en ambos orígenes.`,
      };
    case 'EIP712_CHAIN_MISMATCH':
      return {
        title: 'El Chain ID de la firma no coincide con la red activa',
        explanation: `Tu billetera está en la red ${d.activeChainId ?? '?'}, pero el mensaje firmado especifica la red ${d.domainChainId ?? '?'}. Los atacantes suelen pedir permisos en Mainnet mientras crees estar en una testnet.`,
      };
    case 'KNOWN_MALICIOUS_ADDRESS':
      return {
        title: finding.title.replace(/^Malicious /, 'Dirección maliciosa — '),
        explanation: `Dirección (${shortAddr(String(d.address ?? ''))}) marcada en inteligencia local por vaciado de billeteras.`,
      };
    case 'KNOWN_CONTRACT_LABEL':
      return {
        title: `Contrato reconocido: ${d.name ?? ''}`.trim(),
        explanation: finding.explanation,
      };
    case 'RAW_ETH_SIGN':
      return {
        title: 'Firma a ciegas peligrosa (eth_sign)',
        explanation:
          'eth_sign firma un hash opaco de 32 bytes sin estructura legible. Las dApps modernas legítimas rara vez usan eth_sign porque puede autorizar transacciones arbitrarias.',
      };
    case 'MULTICALL_HIDDEN_UNLIMITED_APPROVAL':
      return {
        title: 'Aprobación ERC-20 ILIMITADA oculta dentro de multicall',
        explanation: `Otorga a ${shortAddr(String(d.spender ?? ''))} permiso para gastar TODO tu saldo de este token hasta revocarlo — descubierta oculta dentro de un lote multicall.`,
      };
    case 'UNLIMITED_ERC20_APPROVAL':
      return {
        title: 'Se solicita aprobación ILIMITADA de token ERC-20',
        explanation: `Otorga a ${shortAddr(String(d.spender ?? ''))} permiso para gastar TODO tu saldo actual y futuro de este token hasta que lo revoques.`,
      };
    case 'NFT_APPROVAL_FOR_ALL':
      return {
        title: 'Aprobación total de colección NFT (setApprovalForAll)',
        explanation: `Permite que ${shortAddr(String(d.operator ?? ''))} transfiera TODOS los NFTs que posees en la colección ${shortAddr(String(d.collection ?? ''))} sin pedir confirmación adicional.`,
      };
    case 'GASLESS_PERMIT_UNLIMITED':
      return {
        title: 'Permit EIP-2612 sin gas otorga aprobación ILIMITADA',
        explanation: `Aunque es una firma off-chain sin gas ahora, cualquiera que la tenga puede enviarla on-chain para que ${shortAddr(String(d.spender ?? ''))} gaste tus tokens.`,
      };
    case 'GASLESS_PERMIT':
      return {
        title: 'Permit EIP-2612 sin gas otorga permiso de gasto',
        explanation: `Firma off-chain que autoriza a ${shortAddr(String(d.spender ?? ''))} a gastar tus tokens sin pagar gas en este momento.`,
      };
    case 'PERMIT2_UNLIMITED':
      return {
        title: 'Firma Permit2 sin gas otorga asignación ILIMITADA',
        explanation: `Las firmas Permit2 permiten que ${shortAddr(String(d.spender ?? ''))} retire tokens previamente aprobados en Uniswap Permit2. Verifica bien la dirección.`,
      };
    case 'PERMIT2_SIGNATURE':
      return {
        title:
          finding.title.includes('BATCH')
            ? 'Aprobación Permit2 por LOTES para múltiples tokens'
            : 'Firma Permit2 sin gas autoriza gasto de tokens',
        explanation: `Permite que ${shortAddr(String(d.spender ?? ''))} retire tokens mediante Uniswap Permit2 sin pagar gas por adelantado.`,
      };
    case 'SEAPORT_ZERO_CONSIDERATION_DRAIN':
      return {
        title: 'Orden Seaport entrega activos a cambio de 0 pago',
        explanation:
          'Tu billetera ofrece NFT(s) o token(s), mientras que el pago que regresa a tu dirección es 0. Coincide con un robo phishing clásico en Seaport.',
      };
    case 'SEAPORT_ORDER_SIGNATURE':
      return {
        title: 'Orden off-chain de marketplace NFT (Seaport)',
        explanation:
          'Firmar una orden Seaport puede listar o transferir tus NFTs por la contraprestación indicada. Verifica cuidadosamente lo que recibes.',
      };
    case 'BLUR_ZERO_PRICE_DRAIN':
      return {
        title: 'Orden de venta Blur lista NFT por precio 0 (o polvo)',
        explanation:
          'Firmar esta orden Blur ofrece tu NFT por 0 (o <= 1000 wei), permitiendo que cualquiera se lo lleve prácticamente gratis.',
      };
    case 'BLUR_BULK_ROOT_SIGNATURE':
      return {
        title: 'Raíz Merkle masiva de Blur oculta precios individuales',
        explanation:
          'Una firma Root de Blur autoriza un árbol Merkle completo de órdenes NFT a la vez. Los precios individuales no pueden verificarse solo con el hash.',
      };
    case 'BLUR_ORDER_SIGNATURE':
      return {
        title: 'Orden off-chain de marketplace NFT (Blur)',
        explanation:
          'Firmar una orden Blur autoriza transferencias o pujas de NFTs según los parámetros firmados. Verifica colección y precio.',
      };
    case 'OPAQUE_CALLDATA':
      return {
        title: 'No se pudo decodificar el calldata localmente',
        explanation: `El selector de función ${d.selector ?? '(ninguno)'} no está en el conjunto local de ABIs verificadas. Approval Lens se niega a adivinar qué hará esta llamada.`,
      };
    case 'EOA_SPENDER_DETECTED':
      return {
        title: 'El autorizado es una billetera personal (EOA), no un contrato inteligente',
        explanation: `La dirección ${shortAddr(String(d.spender ?? ''))} no tiene código de contrato desplegado. Los protocolos DeFi legítimos usan contratos inteligentes — aprobar una EOA es una fuerte señal de phishing.`,
      };
    case 'EIP1967_BEACON_PROXY':
      return {
        title: 'El contrato destino usa un proxy actualizable EIP-1967 Beacon',
        explanation: `El contrato beacon ${shortAddr(String(d.beacon ?? ''))} apunta a la implementación ${shortAddr(String(d.implementation ?? ''))}. Un admin puede actualizar la lógica para todos los proxies conectados.`,
      };
    case 'EIP1167_MINIMAL_PROXY':
      return {
        title: 'El contrato destino es un clon mínimo EIP-1167',
        explanation: `Delega llamadas a la implementación maestra ${shortAddr(String(d.implementation ?? ''))}.`,
      };
    case 'EIP1967_PROXY_CONTRACT':
      return {
        title: 'El contrato destino usa un proxy actualizable EIP-1967',
        explanation: `La implementación resuelve a ${shortAddr(String(d.implementation ?? ''))}. Los contratos proxy pueden cambiar su comportamiento si su admin actualiza la implementación.`,
      };
    case 'SOURCIFY_VERIFIED_DECODE':
      return {
        title: 'ABI del contrato verificada vía Sourcify',
        explanation: `Se decodificó ${d.functionSignature ?? ''} usando metadatos verificados en Sourcify v2.`,
      };
    case 'SOURCIFY_CUSTOM_FUNCTION_REVIEW':
      return {
        title: 'Llamada a función personalizada requiere revisión',
        explanation:
          'El nombre y los parámetros fueron verificados vía Sourcify, pero la lógica interna del contrato aún puede mover activos depositados.',
      };
    case 'FOURBYTE_UNVERIFIED_GUESS':
      return {
        title: `Coincidencia 4-byte no verificada: ${d.signature ?? ''}`.trim(),
        explanation:
          'El selector coincidió solo en el directorio público 4byte (código fuente NO verificado en Sourcify). Los contratos maliciosos pueden falsificar selectores de 4 bytes.',
      };
    default:
      return { title: finding.title, explanation: finding.explanation };
  }
}

export function localizeLimitation(item: string, locale: Locale = 'en'): string {
  if (locale === 'en') return item;

  if (item.startsWith('Approval Lens does not execute full EVM state simulation')) {
    return locale === 'pt-BR'
      ? 'O Approval Lens não executa simulação completa de estado EVM nem audita bytecode arbitrário de contratos.'
      : 'Approval Lens no ejecuta simulación completa de estado EVM ni audita bytecode arbitrario de contratos.';
  }
  if (item.startsWith('Absence of known risk flags')) {
    return locale === 'pt-BR'
      ? 'A ausência de alertas conhecidos NÃO garante que um site ou contrato seja seguro.'
      : 'La ausencia de alertas conocidas NO garantiza que un sitio web o contrato sea seguro.';
  }
  if (item.startsWith('Local-only mode active:')) {
    return locale === 'pt-BR'
      ? 'Modo somente local ativo: metadados on-chain do token, allowance atual, checagem EOA/contrato e resolução de proxy não foram consultados.'
      : 'Modo solo local activo: no se consultaron metadatos on-chain del token, allowance actual, verificación EOA/contrato ni resolución de proxy.';
  }
  if (item.startsWith('Payload schema or ABI was unrecognized')) {
    return locale === 'pt-BR'
      ? 'O esquema do payload ou ABI não foi reconhecido; a avaliação de risco é parcial e marcada como NÃO ANALISADO.'
      : 'El esquema del payload o ABI no fue reconocido; la evaluación de riesgo es parcial y se marca como SIN ANALIZAR.';
  }

  return item;
}
