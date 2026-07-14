import { getDomain } from '../domains/store'
import { listCaptures } from '../capture/store'
import { listFindings } from '../findings/store'
import { knownUrlsFor } from '../jobs/handlers/owaspActive'
import { hostBelongsToDomain } from '../util/validate'

// A workbench sitemap for a target: an endpoint tree assembled from data already
// stored — captured requests (browser extension), ffuf hits, and the discovered
// URL corpus (wayback/CommonCrawl/urlscan/katana + finding URLs). Grouped by host
// → path, carrying the observed method and last-seen status. No new requests.

export interface SitemapEndpoint {
  path: string
  method: string
  status: number | null
  source: 'captured' | 'fuzzed' | 'discovered'
  url: string
}
export interface SitemapHost {
  host: string
  count: number
  endpoints: SitemapEndpoint[]
}

const MAX_ENTRIES = 4000
const MAX_PER_HOST = 800

export function buildSitemap(domainId: number): SitemapHost[] {
  const domain = getDomain(domainId)
  if (!domain) return []
  const inScope = (h: string) => h === domain.host || hostBelongsToDomain(h, domain.host)

  // Keyed by host|method|path so the same endpoint from multiple sources collapses
  // into one row; a real status (from a fuzz hit) upgrades a null one.
  const byKey = new Map<string, SitemapEndpoint & { host: string }>()
  const add = (rawUrl: string, method: string, status: number | null, source: SitemapEndpoint['source']) => {
    if (byKey.size >= MAX_ENTRIES) return
    let u: URL
    try {
      u = new URL(rawUrl)
    } catch {
      return
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return
    const host = u.hostname.toLowerCase()
    if (!inScope(host)) return
    const path = (u.pathname || '/') + u.search
    const key = `${host}|${method}|${path}`
    const ex = byKey.get(key)
    if (ex) {
      if (status != null) ex.status = status
      return
    }
    byKey.set(key, { host, path, method, status, source, url: `${u.protocol}//${host}${path}` })
  }

  for (const c of listCaptures({ domainId, limit: 3000 })) add(c.url, (c.method || 'GET').toUpperCase(), null, 'captured')
  for (const f of listFindings({ domainId, type: 'ffuf', limit: 2000 })) {
    const d = f.data as { url?: unknown; status?: unknown }
    if (typeof d?.url === 'string') add(d.url, 'GET', typeof d.status === 'number' ? d.status : null, 'fuzzed')
  }
  // API-surface findings store endpoints as PATHS (js recon) or {method, path}
  // (OpenAPI) — resolve them to absolute URLs against the finding's host/servers.
  for (const f of listFindings({ domainId, type: 'api', limit: 500 })) {
    const d = f.data as any
    const host = typeof d?.host === 'string' ? d.host : domain.host
    const base = Array.isArray(d?.servers) && typeof d.servers[0] === 'string' ? d.servers[0] : `https://${host}`
    if (typeof d?.endpoint === 'string') add(d.endpoint, 'POST', null, 'discovered') // graphql
    for (const ep of Array.isArray(d?.endpoints) ? d.endpoints : []) {
      if (typeof ep === 'string') {
        const url = ep.startsWith('/') ? `https://${host}${ep}` : /^https?:\/\//.test(ep) ? ep : `https://${ep}`
        add(url, 'GET', null, 'discovered')
      } else if (ep && typeof ep === 'object' && typeof ep.path === 'string') {
        const p = ep.path.startsWith('/') ? ep.path : `/${ep.path}`
        add(`${base.replace(/\/+$/, '')}${p}`, String(ep.method || 'GET').toUpperCase(), null, 'discovered')
      }
    }
  }
  for (const url of knownUrlsFor(domainId)) add(url, 'GET', null, 'discovered')

  const hosts = new Map<string, SitemapEndpoint[]>()
  for (const e of byKey.values()) {
    if (!hosts.has(e.host)) hosts.set(e.host, [])
    hosts.get(e.host)!.push({ path: e.path, method: e.method, status: e.status, source: e.source, url: e.url })
  }
  return [...hosts.entries()]
    .map(([host, endpoints]) => ({
      host,
      count: endpoints.length,
      endpoints: endpoints.sort((a, b) => a.path.localeCompare(b.path)).slice(0, MAX_PER_HOST),
    }))
    .sort((a, b) => b.count - a.count)
}
