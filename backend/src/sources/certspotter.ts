import { getJson } from '../util/http'
import { hostBelongsToDomain, normalizeHost } from '../util/validate'

interface CertSpotterIssuance {
  dns_names?: string[]
}

// Passive subdomain discovery via SSLMate's certspotter CT API — a more reliable
// alternative to crt.sh. Free, no key (rate-limited when unauthenticated).
// https://api.certspotter.com/v1/issuances?domain=X&include_subdomains=true&expand=dns_names
export async function certSpotterSubdomains(domain: string): Promise<string[]> {
  const url =
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
    `&include_subdomains=true&expand=dns_names`

  const data = await getJson<CertSpotterIssuance[]>(url, { timeoutMs: 25_000 })

  const hosts = new Set<string>()
  for (const issuance of data) {
    for (const name of issuance.dns_names ?? []) {
      const host = normalizeHost(name)
      if (host && hostBelongsToDomain(host, domain)) hosts.add(host)
    }
  }
  return [...hosts]
}
