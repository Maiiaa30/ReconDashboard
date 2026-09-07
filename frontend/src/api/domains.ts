import { z } from 'zod'
import { del, get, patch, post, type RequestOptions } from './http'
import {
  domainSchema, domainOverviewSchema,
  type DomainMode, type DomainProfile, type OwaspConfig, type ScopeConfig,
} from './schemas'

// These types are defined by their zod schemas (single source of truth) and
// re-exported so call sites import them from the api facade unchanged.
export type { Domain, DomainMode, DomainProfile, OwaspConfig, ScopeConfig, DomainOverview } from './schemas'

const domainsResponse = z.object({ domains: z.array(domainSchema) }).passthrough()
const domainResponse = z.object({ domain: domainSchema }).passthrough()
const overviewResponse = z.object({ overview: z.array(domainOverviewSchema) }).passthrough()

export const domainsApi = {
  domains: () => get('/domains', {}, domainsResponse),
  domainsOverview: (options?: RequestOptions) => get('/domains/overview', options, overviewResponse),
  createDomain: (host: string, mode: DomainMode, label?: string) =>
    post('/domains', { host, mode, label }, domainResponse),
  setDomainMode: (id: number, mode: DomainMode) => patch(`/domains/${id}`, { mode }, domainResponse),
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
  ) => patch(`/domains/${id}`, patchBody, domainResponse),
  deleteDomain: (id: number) => del<{ ok: true }>(`/domains/${id}`),
  // Clear a domain's recon data (findings/subdomains/jobs/captures/…) but keep the domain.
  purgeDomainData: (id: number) => del<{ ok: true }>(`/domains/${id}/data`),
}
