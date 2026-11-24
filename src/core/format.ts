import { formatUnits } from 'viem';
import { shortAddr } from './decoders/calldata';
import { getMessages } from './i18n';
import { checkMaliciousAddress, lookupKnownContract } from './reputation';
import type { InspectionResult, Locale, RiskFinding, Severity } from './types';

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function sortFindingsBySeverity(findings: RiskFinding[]): RiskFinding[] {
  return [...findings].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99),
  );
}

export function formatTokenAmount(
  raw?: string,
  decimals?: number,
  symbol?: string,
  isUnlimited?: boolean,
  includeRaw = false,
  locale: Locale = 'en',
): string {
  const msg = getMessages(locale);
  if (isUnlimited) {
    const base = `${msg.unlimitedWord}${symbol ? ` ${symbol}` : ''}`;
    return includeRaw && raw ? `${base} (raw: ${raw})` : base;
  }
  if (!raw) return '—';
  if (decimals !== undefined) {
    try {
      const formatted = formatUnits(BigInt(raw), decimals);
      const clean = addThousandsSeparators(formatted);
      const base = `${clean}${symbol ? ` ${symbol}` : ''}`;
      return includeRaw ? `${base} (raw: ${raw})` : base;
    } catch {
      return raw;
    }
  }
  return `${raw} ${msg.rawUnitsWord}`;
}

function addThousandsSeparators(numStr: string): string {
  const [intPart, fracPart] = numStr.split('.');
  const formattedInt = intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  if (!fracPart) return formattedInt;
  const trimmedFrac = fracPart.slice(0, 6).replace(/0+$/, '');
  return trimmedFrac ? `${formattedInt}.${trimmedFrac}` : formattedInt;
}

const YEAR_2100_UNIX_SECONDS = 4102444800n;

export function formatDeadline(deadline?: string, locale: Locale = 'en'): string {
  if (!deadline || !deadline.trim()) return '—';
  const msg = getMessages(locale);
  const trimmed = deadline.trim();
  try {
    const val = BigInt(trimmed);
    if (val <= 0n) return msg.immediateExpired;
    // Treat milliseconds vs seconds
    const seconds = val > 1_000_000_000_000n && val < 4_102_444_800_000n ? val / 1000n : val;
    if (seconds >= YEAR_2100_UNIX_SECONDS) {
      return msg.neverExpires;
    }
    const date = new Date(Number(seconds) * 1000);
    if (Number.isNaN(date.getTime())) return trimmed;
    const intlLocale = locale === 'en' ? 'en-US' : locale;
    return new Intl.DateTimeFormat(intlLocale, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: 'UTC',
    }).format(date);
  } catch {
    return trimmed;
  }
}

function describeActor(address?: string, locale: Locale = 'en'): string {
  if (!address) return getMessages(locale).unknownAddress;
  const bad = checkMaliciousAddress(address);
  if (bad) return `${bad.label} (${shortAddr(address)})`;
  const known = lookupKnownContract(address);
  if (known) return `${known.name} (${shortAddr(address)})`;
  return shortAddr(address);
}

export function buildPlainEnglishSummary(
  result: InspectionResult,
  locale: Locale = 'en',
): string {
  const { decoded, onChain } = result;
  const msg = getMessages(locale);
  const symbol = onChain.tokenSymbol;
  const decimals = onChain.tokenDecimals;
  const formattedAmt = formatTokenAmount(
    decoded.amountRaw,
    decimals,
    symbol,
    decoded.isUnlimited,
    false,
    locale,
  );
  const actor = describeActor(
    decoded.spender ?? decoded.recipient ?? decoded.targetContract,
    locale,
  );
  const expiry = decoded.deadline ? formatDeadline(decoded.deadline, locale) : null;

  if (locale === 'pt-BR') {
    const expiryClause =
      expiry && expiry !== '—'
        ? expiry === msg.neverExpires
          ? ' sem data de expiração'
          : ` até ${expiry}`
        : '';

    switch (decoded.kind) {
      case 'ERC20_APPROVE':
        if (decoded.amountRaw === '0') {
          return `Você está revogando a permissão de ${actor} para gastar seus ${symbol ?? 'tokens'}.`;
        }
        return decoded.isUnlimited
          ? `Você está dando a ${actor} permissão para retirar TODO o seu saldo de ${symbol ?? 'tokens'} (atual e futuro)${expiryClause} sem perguntar novamente.`
          : `Você está autorizando ${actor} a gastar até ${formattedAmt} da sua carteira${expiryClause} sem perguntar novamente.`;
      case 'ERC20_INCREASE_ALLOWANCE':
        return decoded.isUnlimited
          ? `Você está aumentando o limite de gasto de ${actor} para TODO o seu saldo de ${symbol ?? 'tokens'} sem nova confirmação.`
          : `Você está aumentando o limite de gasto de ${actor} em ${formattedAmt} da sua carteira.`;
      case 'ERC20_DECREASE_ALLOWANCE':
        return `Você está reduzindo o limite de gasto de ${actor} em ${formattedAmt}.`;
      case 'ERC20_TRANSFER':
      case 'ERC20_TRANSFER_FROM':
        return `Você está enviando imediatamente ${formattedAmt} diretamente para ${describeActor(decoded.recipient, locale)}.`;
      case 'NFT_SET_APPROVAL_FOR_ALL':
        return decoded.approved
          ? `Você está dando a ${actor} controle total para transferir TODOS os seus NFTs da coleção ${shortAddr(decoded.targetContract)} quando quiser.`
          : `Você está revogando o acesso de ${actor} para transferir seus NFTs da coleção ${shortAddr(decoded.targetContract)}.`;
      case 'NFT_TRANSFER':
        return `Você está transferindo o NFT #${decoded.amountRaw ?? '?'} diretamente para ${describeActor(decoded.recipient, locale)}.`;
      case 'EIP2612_PERMIT':
        return decoded.isUnlimited
          ? `Você está assinando um Permit sem gás que permite a ${actor} gastar TODO o seu saldo de ${symbol ?? 'tokens'}${expiryClause} sem pagar taxa agora.`
          : `Você está assinando um Permit sem gás autorizando ${actor} a gastar até ${formattedAmt} da sua carteira${expiryClause}.`;
      case 'PERMIT2_SINGLE':
        return decoded.isUnlimited
          ? `Você está assinando uma aprovação Permit2 sem gás dando a ${actor} acesso ILIMITADO aos seus ${symbol ?? 'tokens'}${expiryClause}.`
          : `Você está assinando uma aprovação Permit2 sem gás autorizando ${actor} a retirar até ${formattedAmt}${expiryClause}.`;
      case 'PERMIT2_BATCH':
        return `Você está assinando uma aprovação Permit2 em lote dando a ${actor} direitos de gasto sobre ${decoded.subActions?.length ?? 'múltiplos'} tokens de uma só vez${expiryClause}.`;
      case 'PERMIT2_TRANSFER_FROM':
        return `Você está autorizando ${actor} a retirar imediatamente ${formattedAmt} da sua carteira via assinatura Permit2 sem gás.`;
      case 'SEAPORT_ORDER':
        if (decoded.seaportDetails?.zeroConsiderationToOfferer) {
          return `PERIGO: Você está oferecendo ${decoded.seaportDetails.offerCount} ativo(s) em uma ordem Seaport que paga 0 de volta para sua carteira — padrão clássico de golpe phishing de NFT.`;
        }
        return `Você está assinando uma ordem off-chain oferecendo ${decoded.seaportDetails?.offerCount ?? 'seus'} ativo(s) por ${decoded.seaportDetails?.considerationCount ?? 'itens'} de contraprestação. Verifique o valor recebido.`;
      case 'BLUR_ORDER':
        if (decoded.functionName === 'Blur.BulkOrderRoot') {
          return `Você está assinando uma raiz Merkle em lote da Blur autorizando múltiplas listagens de NFTs de uma vez. Os preços individuais estão ocultos no hash.`;
        }
        if (decoded.approved) {
          return `PERIGO: Você está assinando uma ordem Blur listando seu NFT da coleção ${shortAddr(decoded.tokenAddress)} por 0 (ou poeira) — um invasor pode capturá-lo de graça.`;
        }
        return `Você está assinando uma ordem off-chain da Blur na coleção ${shortAddr(decoded.tokenAddress)}. Confira o preço e a direção da ordem.`;
      case 'SOURCIFY_DECODED':
        return `Você está chamando a função verificada ${decoded.functionName ?? 'desconhecida'} em ${
          decoded.contractName
            ? `${decoded.contractName} (${shortAddr(decoded.targetContract)})`
            : describeActor(decoded.targetContract, locale)
        }. Revise os parâmetros decodificados abaixo antes de assinar.`;
      case 'MULTICALL':
        return `Você está executando um lote agrupado de ${decoded.subActions?.length ?? 'várias'} operações em uma única transação. Confira cada etapa aninhada em busca de aprovações ocultas.`;
      case 'NATIVE_TRANSFER':
        return decoded.amountRaw && decoded.amountRaw !== '0'
          ? `Você está enviando ${formatTokenAmount(decoded.amountRaw, 18, 'ETH', false, false, locale)} diretamente para ${describeActor(decoded.recipient, locale)}.`
          : `Você está enviando uma transação com 0 ETH para ${describeActor(decoded.targetContract, locale)}.`;
      case 'PERSONAL_SIGN':
        return `Você está assinando uma mensagem de texto legível para comprovar posse da carteira (geralmente login). Não move tokens diretamente on-chain.`;
      case 'RAW_ETH_SIGN':
        return `PERIGO: Você está assinando um hash bruto e ilegível de 32 bytes (eth_sign) que pode autorizar transações arbitrárias e drenar toda a sua carteira.`;
      case 'TYPED_DATA_GENERIC':
        return `Você está assinando uma mensagem estruturada não reconhecida (${decoded.functionName ?? 'EIP-712'}). Como o esquema não está na base local verificada, confira o site e os campos com atenção.`;
      case 'UNKNOWN_CALLDATA':
      default:
        return `Você está chamando uma função de contrato não reconhecida (${decoded.selector ?? 'seletor desconhecido'}) em ${describeActor(decoded.targetContract, locale)}. O Approval Lens não pode confirmar o que este código fará on-chain.`;
    }
  }

  if (locale === 'es') {
    const expiryClause =
      expiry && expiry !== '—'
        ? expiry === msg.neverExpires
          ? ' sin fecha de expiración'
          : ` hasta el ${expiry}`
        : '';

    switch (decoded.kind) {
      case 'ERC20_APPROVE':
        if (decoded.amountRaw === '0') {
          return `Estás revocando el permiso de ${actor} para gastar tus ${symbol ?? 'tokens'}.`;
        }
        return decoded.isUnlimited
          ? `Estás dando a ${actor} permiso para retirar TODO tu saldo de ${symbol ?? 'tokens'} (actual y futuro)${expiryClause} sin volver a preguntar.`
          : `Estás autorizando a ${actor} a gastar hasta ${formattedAmt} de tu billetera${expiryClause} sin volver a preguntar.`;
      case 'ERC20_INCREASE_ALLOWANCE':
        return decoded.isUnlimited
          ? `Estás aumentando el límite de gasto de ${actor} a TODO tu saldo de ${symbol ?? 'tokens'} sin nueva confirmación.`
          : `Estás aumentando el límite de gasto de ${actor} en ${formattedAmt} desde tu billetera.`;
      case 'ERC20_DECREASE_ALLOWANCE':
        return `Estás reduciendo el límite de gasto de ${actor} en ${formattedAmt}.`;
      case 'ERC20_TRANSFER':
      case 'ERC20_TRANSFER_FROM':
        return `Estás enviando inmediatamente ${formattedAmt} directamente a ${describeActor(decoded.recipient, locale)}.`;
      case 'NFT_SET_APPROVAL_FOR_ALL':
        return decoded.approved
          ? `Estás dando a ${actor} control total para transferir TODOS tus NFTs de la colección ${shortAddr(decoded.targetContract)} cuando quiera.`
          : `Estás revocando el acceso de ${actor} para transferir tus NFTs de la colección ${shortAddr(decoded.targetContract)}.`;
      case 'NFT_TRANSFER':
        return `Estás transfiriendo el NFT #${decoded.amountRaw ?? '?'} directamente a ${describeActor(decoded.recipient, locale)}.`;
      case 'EIP2612_PERMIT':
        return decoded.isUnlimited
          ? `Estás firmando un Permit sin gas que permite a ${actor} gastar TODO tu saldo de ${symbol ?? 'tokens'}${expiryClause} sin pagar gas ahora.`
          : `Estás firmando un Permit sin gas autorizando a ${actor} a gastar hasta ${formattedAmt} de tu billetera${expiryClause}.`;
      case 'PERMIT2_SINGLE':
        return decoded.isUnlimited
          ? `Estás firmando una aprobación Permit2 sin gas dando a ${actor} acceso ILIMITADO a tus ${symbol ?? 'tokens'}${expiryClause}.`
          : `Estás firmando una aprobación Permit2 sin gas permitiendo a ${actor} retirar hasta ${formattedAmt}${expiryClause}.`;
      case 'PERMIT2_BATCH':
        return `Estás firmando una aprobación Permit2 por lotes dando a ${actor} derechos de gasto sobre ${decoded.subActions?.length ?? 'múltiples'} tokens a la vez${expiryClause}.`;
      case 'PERMIT2_TRANSFER_FROM':
        return `Estás autorizando a ${actor} a retirar inmediatamente ${formattedAmt} de tu billetera mediante una firma Permit2 sin gas.`;
      case 'SEAPORT_ORDER':
        if (decoded.seaportDetails?.zeroConsiderationToOfferer) {
          return `PELIGRO: Estás ofreciendo ${decoded.seaportDetails.offerCount} activo(s) en una orden Seaport que paga 0 de vuelta a tu billetera — coincide con un robo phishing de NFT.`;
        }
        return `Estás firmando una orden off-chain ofreciendo ${decoded.seaportDetails?.offerCount ?? 'tus'} activo(s) por ${decoded.seaportDetails?.considerationCount ?? 'elementos'} de contraprestación. Verifica el pago que recibes.`;
      case 'BLUR_ORDER':
        if (decoded.functionName === 'Blur.BulkOrderRoot') {
          return `Estás firmando una raíz Merkle masiva de Blur que autoriza múltiples listados de NFTs a la vez. Los precios individuales están ocultos dentro del hash.`;
        }
        if (decoded.approved) {
          return `PELIGRO: Estás firmando una orden de venta Blur listando tu NFT de ${shortAddr(decoded.tokenAddress)} por 0 (o polvo) — un atacante puede llevárselo gratis.`;
        }
        return `Estás firmando una orden off-chain de Blur en la colección ${shortAddr(decoded.tokenAddress)}. Verifica el precio y el tipo de orden.`;
      case 'SOURCIFY_DECODED':
        return `Estás llamando a la función verificada ${decoded.functionName ?? 'desconocida'} en ${
          decoded.contractName
            ? `${decoded.contractName} (${shortAddr(decoded.targetContract)})`
            : describeActor(decoded.targetContract, locale)
        }. Revisa los parámetros decodificados abajo antes de firmar.`;
      case 'MULTICALL':
        return `Estás ejecutando un lote agrupado de ${decoded.subActions?.length ?? 'múltiples'} operaciones en una sola transacción. Revisa cada paso anidado en busca de aprobaciones ocultas.`;
      case 'NATIVE_TRANSFER':
        return decoded.amountRaw && decoded.amountRaw !== '0'
          ? `Estás enviando ${formatTokenAmount(decoded.amountRaw, 18, 'ETH', false, false, locale)} directamente a ${describeActor(decoded.recipient, locale)}.`
          : `Estás enviando una transacción con 0 ETH a ${describeActor(decoded.targetContract, locale)}.`;
      case 'PERSONAL_SIGN':
        return `Estás firmando un mensaje de texto legible para demostrar propiedad de la billetera (usualmente inicio de sesión). No mueve tokens directamente on-chain.`;
      case 'RAW_ETH_SIGN':
        return `PELIGRO: Estás firmando un hash sin formato de 32 bytes (eth_sign) que puede autorizar transacciones arbitrarias y vaciar toda tu billetera.`;
      case 'TYPED_DATA_GENERIC':
        return `Estás firmando un mensaje estructurado no reconocido (${decoded.functionName ?? 'EIP-712'}). Como su esquema no está en el conjunto local verificado, revisa el sitio y los campos con cuidado.`;
      case 'UNKNOWN_CALLDATA':
      default:
        return `Estás llamando a una función de contrato no reconocida (${decoded.selector ?? 'selector desconocido'}) en ${describeActor(decoded.targetContract, locale)}. Approval Lens no puede verificar qué hará este código on-chain.`;
    }
  }

  // English ('en')
  const expiryClause =
    expiry && expiry !== '—'
      ? expiry === msg.neverExpires
        ? ' with no expiration date'
        : ` until ${expiry}`
      : '';

  switch (decoded.kind) {
    case 'ERC20_APPROVE':
      if (decoded.amountRaw === '0') {
        return `You are revoking ${actor}'s permission to spend your ${symbol ?? 'tokens'}.`;
      }
      return decoded.isUnlimited
        ? `You are giving ${actor} permission to take your ENTIRE ${symbol ?? 'token'} balance (now and in the future)${expiryClause} without asking again.`
        : `You are allowing ${actor} to spend up to ${formattedAmt} from your wallet${expiryClause} without asking again.`;

    case 'ERC20_INCREASE_ALLOWANCE':
      return decoded.isUnlimited
        ? `You are increasing ${actor}'s spending limit to your ENTIRE ${symbol ?? 'token'} balance without asking again.`
        : `You are increasing ${actor}'s spending allowance by ${formattedAmt} from your wallet.`;

    case 'ERC20_DECREASE_ALLOWANCE':
      return `You are reducing ${actor}'s token spending allowance by ${formattedAmt}.`;

    case 'ERC20_TRANSFER':
    case 'ERC20_TRANSFER_FROM':
      return `You are immediately sending ${formattedAmt} directly to ${describeActor(decoded.recipient, locale)}.`;

    case 'NFT_SET_APPROVAL_FOR_ALL':
      return decoded.approved
        ? `You are giving ${actor} full control to transfer ALL of your NFTs in collection ${shortAddr(decoded.targetContract)} whenever they want.`
        : `You are revoking ${actor}'s access to transfer your NFTs in collection ${shortAddr(decoded.targetContract)}.`;

    case 'NFT_TRANSFER':
      return `You are transferring NFT #${decoded.amountRaw ?? '?'} directly to ${describeActor(decoded.recipient, locale)}.`;

    case 'EIP2612_PERMIT':
      return decoded.isUnlimited
        ? `You are signing a gasless permit that lets ${actor} spend your ENTIRE ${symbol ?? 'token'} balance${expiryClause} without paying gas now.`
        : `You are signing a gasless permit allowing ${actor} to spend up to ${formattedAmt} from your wallet${expiryClause}.`;

    case 'PERMIT2_SINGLE':
      return decoded.isUnlimited
        ? `You are signing a gasless Permit2 approval giving ${actor} UNLIMITED access to pull your ${symbol ?? 'tokens'}${expiryClause}.`
        : `You are signing a gasless Permit2 approval allowing ${actor} to pull up to ${formattedAmt}${expiryClause}.`;

    case 'PERMIT2_BATCH':
      return `You are signing a gasless Permit2 batch approval giving ${actor} spending rights across ${decoded.subActions?.length ?? 'multiple'} tokens at once${expiryClause}.`;

    case 'PERMIT2_TRANSFER_FROM':
      return `You are authorizing ${actor} to immediately pull ${formattedAmt} from your wallet via a gasless Permit2 signature.`;

    case 'SEAPORT_ORDER':
      if (decoded.seaportDetails?.zeroConsiderationToOfferer) {
        return `DANGER: You are offering ${decoded.seaportDetails.offerCount} asset(s) in a Seaport order that pays 0 back to your wallet — this matches a zero-price NFT phishing drain.`;
      }
      return `You are signing an off-chain marketplace order offering ${decoded.seaportDetails?.offerCount ?? 'your'} asset(s) for ${decoded.seaportDetails?.considerationCount ?? 'specified'} consideration item(s). Verify the payment returning to your wallet.`;

    case 'BLUR_ORDER':
      if (decoded.functionName === 'Blur.BulkOrderRoot') {
        return `You are signing a Blur bulk Merkle root authorizing multiple NFT listings at once. Individual NFT prices are hidden inside the root hash and cannot be verified here.`;
      }
      if (decoded.approved) {
        return `DANGER: You are signing a Blur sell order listing your NFT from ${shortAddr(decoded.tokenAddress)} for 0 (or dust) — an attacker can sweep it virtually for free.`;
      }
      return `You are signing an off-chain Blur marketplace order on collection ${shortAddr(decoded.tokenAddress)}. Verify the price and order side carefully.`;

    case 'SOURCIFY_DECODED':
      return `You are calling verified function ${decoded.functionName ?? 'unknown'} on ${
        decoded.contractName
          ? `${decoded.contractName} (${shortAddr(decoded.targetContract)})`
          : describeActor(decoded.targetContract, locale)
      }. Review the decoded parameters below before signing.`;

    case 'MULTICALL':
      return `You are executing a bundled batch of ${decoded.subActions?.length ?? 'multiple'} operations in a single transaction. Check every nested step for hidden approvals.`;

    case 'NATIVE_TRANSFER':
      return decoded.amountRaw && decoded.amountRaw !== '0'
        ? `You are sending ${formatTokenAmount(decoded.amountRaw, 18, 'ETH', false, false, locale)} directly to ${describeActor(decoded.recipient, locale)}.`
        : `You are sending a transaction with 0 ETH to ${describeActor(decoded.targetContract, locale)}.`;

    case 'PERSONAL_SIGN':
      return `You are signing a readable text message to prove wallet ownership (typically for logging in). It cannot directly move tokens on-chain unless it matches a protocol order.`;

    case 'RAW_ETH_SIGN':
      return `DANGER: You are signing a raw, unreadable 32-byte hash (eth_sign) that can authorize arbitrary transactions and completely drain your wallet.`;

    case 'TYPED_DATA_GENERIC':
      return `You are signing an unrecognized structured message (${decoded.functionName ?? 'EIP-712'}). Because its schema is not in the local verified set, verify the website and fields carefully.`;

    case 'UNKNOWN_CALLDATA':
    default:
      return `You are calling an unrecognized contract function (${decoded.selector ?? 'unknown selector'}) on ${describeActor(decoded.targetContract, locale)}. Approval Lens cannot verify what this code will do on-chain.`;
  }
}
