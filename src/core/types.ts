export type Verdict =
  | 'KNOWN_MALICIOUS'
  | 'HIGH_RISK'
  | 'REVIEW_NEEDED'
  | 'UNDERSTOOD'
  | 'UNANALYZED';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Locale = 'en' | 'pt-BR' | 'es';

export type EvidenceSource =
  | 'local_decoder'
  | 'local_reputation'
  | 'rpc_read'
  | 'browser_context'
  | 'sourcify_abi'
  | 'fourbyte_guess';

export type InterceptedMethod =
  | 'eth_sendTransaction'
  | 'eth_signTypedData_v4'
  | 'eth_signTypedData_v3'
  | 'eth_signTypedData'
  | 'personal_sign'
  | 'eth_sign';

export interface NetworkLogEntry {
  timestamp: string;
  target: string;
  purpose: string;
  status: 'ok' | 'error' | 'skipped';
  detail?: string;
}

export interface RiskFinding {
  id: string;
  severity: Severity;
  title: string;
  explanation: string;
  source: EvidenceSource;
  details?: Record<string, string | number | boolean | null>;
}

export interface SeaportOrderDetails {
  offerCount: number;
  considerationCount: number;
  offererConsiderationCount: number;
  zeroConsiderationToOfferer: boolean;
  recipients: string[];
}

export interface DecodedArgEntry {
  name: string;
  type: string;
  value: string;
}

export type ProxyKind = 'EIP1967_IMPL' | 'EIP1967_BEACON' | 'EIP1167_MINIMAL';

export interface DecodedAction {
  kind:
    | 'ERC20_APPROVE'
    | 'ERC20_INCREASE_ALLOWANCE'
    | 'ERC20_DECREASE_ALLOWANCE'
    | 'ERC20_TRANSFER'
    | 'ERC20_TRANSFER_FROM'
    | 'NFT_SET_APPROVAL_FOR_ALL'
    | 'NFT_TRANSFER'
    | 'EIP2612_PERMIT'
    | 'PERMIT2_SINGLE'
    | 'PERMIT2_BATCH'
    | 'PERMIT2_TRANSFER_FROM'
    | 'SEAPORT_ORDER'
    | 'BLUR_ORDER'
    | 'MULTICALL'
    | 'NATIVE_TRANSFER'
    | 'PERSONAL_SIGN'
    | 'RAW_ETH_SIGN'
    | 'SOURCIFY_DECODED'
    | 'TYPED_DATA_GENERIC'
    | 'UNKNOWN_CALLDATA';
  summary: string;
  functionName?: string;
  selector?: string;
  targetContract?: string;
  spender?: string;
  recipient?: string;
  owner?: string;
  amountRaw?: string;
  isUnlimited?: boolean;
  approved?: boolean;
  deadline?: string;
  tokenAddress?: string;
  subActions?: DecodedAction[];
  rawPreview?: string;
  decodedArgs?: DecodedArgEntry[];
  abiSource?: 'local' | 'sourcify_exact' | 'sourcify_partial' | 'fourbyte_unverified';
  contractName?: string;
  seaportDetails?: SeaportOrderDetails;
}

export interface OnChainContext {
  rpcEnabled: boolean;
  chainId?: number;
  tokenSymbol?: string;
  tokenDecimals?: number;
  currentAllowanceRaw?: string;
  spenderIsContract?: boolean | null;
  targetIsProxy?: boolean | null;
  proxyKind?: ProxyKind | null;
  proxyImplementation?: string | null;
  beaconAddress?: string | null;
}

export interface InspectionRequest {
  requestId: string;
  createdAt: string;
  method: InterceptedMethod;
  params: unknown[];
  /** SHA-256 hex digest of the canonical frozen payload (TOCTOU protection) */
  payloadHash: string;
  /** Verified by Chrome background service worker via sender.origin */
  origin: string;
  /** Top-level tab origin when different from iframe origin */
  topLevelOrigin?: string;
  /** Wallet name from EIP-6963 metadata if available (e.g., MetaMask, Rabby) */
  walletName?: string;
  chainIdHex?: string;
}

export interface InspectionResult {
  request: InspectionRequest;
  verdict: Verdict;
  headline: string;
  decoded: DecodedAction;
  findings: RiskFinding[];
  limitations: string[];
  onChain: OnChainContext;
  networkLog: NetworkLogEntry[];
  reputationVersion: string;
}

export interface ExtensionSettings {
  enabled: boolean;
  rpcEnrichmentEnabled: boolean;
  abiLookupEnabled: boolean;
  customRpcUrl: string;
  locale?: Locale;
}

export type UserDecision = 'ALLOW' | 'BLOCK';

export interface HistoryRecord {
  requestId: string;
  timestamp: string;
  origin: string;
  method: InterceptedMethod;
  verdict: Verdict;
  headline: string;
  decision: UserDecision;
  result: InspectionResult;
}
