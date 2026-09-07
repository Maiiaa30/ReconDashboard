import { get, post, type RequestOptions } from './http'
import type { Finding } from './findings'
import type { Capture } from './captures'
import { subdomainPageSchema, subdomainSummarySchema, type Subdomain } from './schemas'

// Subdomain, SubdomainPage and SubdomainSummary are defined by their zod schemas
// (single source of truth) and re-exported so call sites import them unchanged.
export type { Subdomain, SubdomainPage, SubdomainSummary } from './schemas'

export type SubdomainSort = 'status' | 'host' | 'ip' | 'lastSeen' | 'new'

export interface SubdomainQuery {
  q?: string
  newOnly?: boolean
  sort?: SubdomainSort
  dir?: 'asc' | 'desc'
  limit?: number
  cursor?: string
}

export interface Asset {
  id: number
  domainId: number
  kind: 'host' | 'ip' | 'service'
  value: string
  ip: string | null
  port: number | null
  asn: string | null
  asnName: string | null
  cdn: string | null
  firstSeen: string
  lastSeen: string
  findingCount: number
  activeFindingCount: number
  maxScore: number | null
  findingIds: number[]
  httpStatus: number | null
  title: string | null
  server: string | null
  scheme: string | null
  ports: number[]
  technologies: string[]
  up: boolean | null
  redirect: string | null
  contentLength: number | null
  responseFingerprint: string | null
  screenshotFingerprint: string | null
}

// Per-asset investigation detail. `asset` is the raw inventory row (not the
// enriched list shape); findings/captures/subdomain give the full picture.
export interface AssetDetail {
  asset: {
    id: number
    domainId: number | null
    kind: 'host' | 'ip' | 'service'
    value: string
    ip: string | null
    port: number | null
    asn: string | null
    asnName: string | null
    cdn: string | null
    firstSeen: string
    lastSeen: string
  }
  subdomain: Subdomain | null
  findings: Finding[]
  captures: Capture[]
  related: { sameIp: string[]; sameCert: string[]; sameFavicon: string[] }
}

export interface ScreenshotEntry {
  host: string
  status: number | null
  title: string | null
  scheme: string | null
  capturedAt: string | null
}

export interface LeaksResponse {
  enabled: boolean
  provider: string | null
  autoDaily: boolean
  pending: boolean
  lastCheckedAt: string | null
  findings: Finding[]
}

export interface FreeEmailResult {
  email: string
  found: number
  fields: string[]
  sources: { name: string; date: string | null }[]
  provider: string
}

export const reconApi = {
  // subdomains — full unpaged list (global counts, API-surface + changes views)
  subdomains: (id: number, options?: RequestOptions) => get<{ subdomains: Subdomain[] }>(`/domains/${id}/subdomains`, options),
  // Paged, server-side-filtered/sorted list for the Subdomains page.
  subdomainsPage: (id: number, q: SubdomainQuery = {}, options?: RequestOptions) => {
    const params = new URLSearchParams()
    if (q.q) params.set('q', q.q)
    if (q.newOnly) params.set('newOnly', '1')
    if (q.sort) params.set('sort', q.sort)
    if (q.dir) params.set('dir', q.dir)
    if (q.limit) params.set('limit', String(q.limit))
    if (q.cursor) params.set('cursor', q.cursor)
    const qs = params.toString()
    return get(`/domains/${id}/subdomains/page${qs ? `?${qs}` : ""}`, options, subdomainPageSchema)
  },
  // total + new-host count for a filter set (newOnly excluded), header stats
  // without loading every row.
  subdomainsSummary: (id: number, q: Pick<SubdomainQuery, 'q'> = {}, options?: RequestOptions) => {
    const params = new URLSearchParams()
    if (q.q) params.set('q', q.q)
    const qs = params.toString()
    return get(`/domains/${id}/subdomains/summary${qs ? `?${qs}` : ""}`, options, subdomainSummarySchema)
  },
  assets: (id: number, options?: RequestOptions) => get<{ assets: Asset[] }>(`/domains/${id}/assets`, options),
  // Per-asset investigation detail: findings + captures + subdomain enrichment +
  // hosts sharing its IP / TLS cert / favicon.
  assetDetail: (id: number, assetId: number, options?: RequestOptions) =>
    get<AssetDetail>(`/domains/${id}/assets/${assetId}`, options),
  discover: (id: number) => post<{ jobId: number }>(`/domains/${id}/discover`),
  // passive DNS permutation + brute-resolve (wildcard-guarded)
  dnsPermute: (id: number) => post<{ jobId: number }>(`/domains/${id}/dns-permute`),
  acknowledgeNew: (id: number) => post<{ cleared: number }>(`/domains/${id}/subdomains/acknowledge`),

  // passive recon
  exposure: (id: number) => post<{ jobId: number }>(`/domains/${id}/exposure`),
  osint: (id: number) => post<{ jobId: number }>(`/domains/${id}/osint`),

  // origin discovery (WAF/CDN bypass)
  findOrigin: (id: number, confirm = false) => post<{ jobId: number }>(`/domains/${id}/origin`, { confirm }),

  // passive API-surface discovery (OpenAPI/Swagger + GraphQL). Optional host
  // restricts the scan to one apex/subdomain; omitted = apex + all live subs.
  apiDiscovery: (id: number, host?: string) =>
    post<{ jobId: number }>(`/domains/${id}/api-discovery`, host ? { host } : undefined),

  // domain breach/leak exposure (needs a configured provider; passive lookup)
  leaks: (id: number) => get<LeaksResponse>(`/domains/${id}/leaks`),
  checkLeaks: (id: number) => post<{ jobId: number }>(`/domains/${id}/leaks/check`),
  // free, keyless per-email breach-metadata check (no provider needed)
  checkEmailLeak: (id: number, email: string) =>
    post<{ result: FreeEmailResult }>(`/domains/${id}/leaks/email`, { email }),

  // screenshots
  captureScreenshots: (id: number) => post<{ jobId: number }>(`/domains/${id}/screenshots`),
  screenshots: (id: number) => get<{ screenshots: ScreenshotEntry[] }>(`/domains/${id}/screenshots`),
  screenshotUrl: (id: number, host: string) => `/api/domains/${id}/screenshot?host=${encodeURIComponent(host)}`,
}
