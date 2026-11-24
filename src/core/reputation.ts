import reputationData from '../data/reputation.json';

export interface MaliciousDomainMatch {
  domain: string;
  label: string;
  reason: string;
}

export interface MaliciousAddressMatch {
  address: string;
  label: string;
  reason: string;
}

export interface KnownContractMatch {
  address: string;
  name: string;
  note: string;
  symbol?: string;
  decimals?: number;
}

const maliciousDomainMap = new Map<string, MaliciousDomainMatch>(
  reputationData.maliciousDomains.map((entry) => [entry.domain.toLowerCase(), entry]),
);

const maliciousAddressMap = new Map<string, MaliciousAddressMatch>(
  reputationData.maliciousAddresses.map((entry) => [entry.address.toLowerCase(), entry]),
);

const knownContractMap = new Map<string, KnownContractMatch>(
  reputationData.knownContracts.map((entry) => [entry.address.toLowerCase(), entry]),
);

export function getReputationVersion(): string {
  return reputationData.version;
}

export function extractHostname(originOrUrl: string): string | null {
  try {
    return new URL(originOrUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function checkMaliciousDomain(originOrUrl: string): MaliciousDomainMatch | null {
  const hostname = extractHostname(originOrUrl);
  if (!hostname) return null;

  // Match exact domain or any subdomain of a listed malicious domain
  const exact = maliciousDomainMap.get(hostname);
  if (exact) return exact;

  for (const [domain, entry] of maliciousDomainMap.entries()) {
    if (hostname.endsWith(`.${domain}`)) {
      return entry;
    }
  }
  return null;
}

export function checkMaliciousAddress(address?: string): MaliciousAddressMatch | null {
  if (!address) return null;
  return maliciousAddressMap.get(address.toLowerCase()) ?? null;
}

export function lookupKnownContract(address?: string): KnownContractMatch | null {
  if (!address) return null;
  return knownContractMap.get(address.toLowerCase()) ?? null;
}
