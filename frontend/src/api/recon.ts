import { get, post, type RequestOptions } from './http'
import type { Finding } from './findings'

export interface Subdomain {
  id: number
  domainId: number
  host: string
  source: string | null
  isNew: boolean
  ipAddress: string | null
  httpStatus: number | null
  title: string | null
  server: string | null
  scheme: string | null
  probedAt: string | null
  screenshotPath: string | null
  screenshotAt: string | null
  firstSeen: string
  lastSeen: string
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
  // subdomains
  subdomains: (id: number, options?: RequestOptions) => get<{ subdomains: Subdomain[] }>(`/domains/${id}/subdomains`, options),
  assets: (id: number, options?: RequestOptions) => get<{ assets: Asset[] }>(`/domains/${id}/assets`, options),
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
