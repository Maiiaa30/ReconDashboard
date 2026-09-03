import { del, get, patch, post, type RequestOptions } from './http'

export type DomainMode = 'passive_only' | 'active_authorized'

export interface DomainProfile {
  hasLogin?: boolean
  hasParams?: boolean
  hasUpload?: boolean
  hasApi?: boolean
  hasRedirects?: boolean
}

export interface OwaspConfig {
  xssParams?: string[]
  xssPayloads?: string[]
  redirectParams?: string[]
  sensitivePaths?: string[]
  authHeader?: string
}

export interface ScopeConfig {
  allow?: string[]
  deny?: string[]
}

export interface Domain {
  id: number
  host: string
  label: string | null
  mode: DomainMode
  profile?: DomainProfile
  owaspConfig?: OwaspConfig
  scopeConfig?: ScopeConfig
  authorizedFrom?: string | null
  authorizedUntil?: string | null
  monitorIntervalHours?: number
  createdAt: string
  updatedAt: string
}

export interface DomainOverview {
  id: number
  host: string
  label: string | null
  mode: DomainMode
  createdAt: number | null
  subdomains: { total: number; new: number }
  findings: { total: number; maxScore: number | null }
  exposure: { ips: number; openPorts: number; cves: number }
  lastActivity: number | null
  monitorIntervalHours: number
}

export const domainsApi = {
  domains: () => get<{ domains: Domain[] }>('/domains'),
  domainsOverview: (options?: RequestOptions) => get<{ overview: DomainOverview[] }>('/domains/overview', options),
  createDomain: (host: string, mode: DomainMode, label?: string) =>
    post<{ domain: Domain }>('/domains', { host, mode, label }),
  setDomainMode: (id: number, mode: DomainMode) => patch<{ domain: Domain }>(`/domains/${id}`, { mode }),
  updateDomain: (
    id: number,
    patchBody: {
      mode?: DomainMode
      label?: string | null
      profile?: DomainProfile
      monitorIntervalHours?: number
      owaspConfig?: OwaspConfig
      scopeConfig?: ScopeConfig
      authorizedFrom?: number | null
      authorizedUntil?: number | null
    },
  ) => patch<{ domain: Domain }>(`/domains/${id}`, patchBody),
  deleteDomain: (id: number) => del<{ ok: true }>(`/domains/${id}`),
  // Clear a domain's recon data (findings/subdomains/jobs/captures/…) but keep the domain.
  purgeDomainData: (id: number) => del<{ ok: true }>(`/domains/${id}/data`),
}
