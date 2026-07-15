import { getJson } from '../util/http'

// Passive intel via AlienVault OTX (no key for these read endpoints): passive
// DNS (historical hostname → IP) and observed URLs for a domain.
// https://otx.alienvault.com/api

export interface OtxResult {
  passiveDns: { hostname: string; address: string }[]
  urlCount: number
  urls: string[]
}

interface PassiveDnsResp {
  passive_dns?: { hostname?: string; address?: string }[]
}
interface UrlListResp {
  url_list?: { url?: string }[]
  actual_size?: number
}

const base = (domain: string) => `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}`

export async function otxIntel(domain: string): Promise<OtxResult> {
  const [dns, urlList] = await Promise.all([
    getJson<PassiveDnsResp>(`${base(domain)}/passive_dns`, { timeoutMs: 15_000 }).catch(() => ({}) as PassiveDnsResp),
    getJson<UrlListResp>(`${base(domain)}/url_list?limit=500`, { timeoutMs: 15_000 }).catch(() => ({}) as UrlListResp),
  ])

  const passiveDns: { hostname: string; address: string }[] = []
  for (const d of dns.passive_dns ?? []) {
    if (d.hostname && d.address) passiveDns.push({ hostname: d.hostname, address: d.address })
    if (passiveDns.length >= 100) break
  }
  const urls = (urlList.url_list ?? []).map((u) => u.url).filter((u): u is string => !!u)
  // Keep the full fetched set (up to the API's 500) so the corpus captures it; the
  // handler trims what it stores in the display blob.
  return { passiveDns, urlCount: urlList.actual_size ?? urls.length, urls: urls.slice(0, 500) }
}
