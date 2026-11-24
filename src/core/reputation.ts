import communityDomainsData from '../data/community-domains.json';
import reputationData from '../data/reputation.json';

export interface MaliciousDomainMatch {
  domain: string;
  label: string;
  reason: string;
  feedSource?: string;
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

const communityDomainSet = new Set<string>(
  (communityDomainsData.domains ?? []).map((d) => d.toLowerCase()),
);

const maliciousAddressMap = new Map<string, MaliciousAddressMatch>(
  reputationData.maliciousAddresses.map((entry) => [entry.address.toLowerCase(), entry]),
);

const knownContractMap = new Map<string, KnownContractMatch>(
  reputationData.knownContracts.map((entry) => [entry.address.toLowerCase(), entry]),
);

export function getReputationVersion(): string {
  return `${reputationData.version}+${communityDomainsData.source}@${communityDomainsData.count}`;
}

export function getCommunityFeedMetadata() {
  return {
    source: communityDomainsData.source,
    license: communityDomainsData.license,
    repository: communityDomainsData.repository,
    count: communityDomainsData.count,
    updatedAt: communityDomainsData.updatedAt,
    sha256: communityDomainsData.sha256,
  };
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

  // 1. Check curated local domain rules (exact + parent domain suffix)
  const exact = maliciousDomainMap.get(hostname);
  if (exact) return exact;

  for (const [domain, entry] of maliciousDomainMap.entries()) {
    if (hostname.endsWith(`.${domain}`)) {
      return entry;
    }
  }

  // 2. O(k) parent-label lookup against offline community phishing snapshot (MetaMask eth-phishing-detect)
  const labels = hostname.split('.');
  for (let i = 0; i < labels.length - 1; i += 1) {
    const candidate = labels.slice(i).join('.');
    if (communityDomainSet.has(candidate)) {
      return {
        domain: candidate,
        label: `Community Phishing Blocklist (${communityDomainsData.source})`,
        reason: `Listed in offline ${communityDomainsData.source} snapshot (${communityDomainsData.license}).`,
        feedSource: communityDomainsData.source,
      };
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
