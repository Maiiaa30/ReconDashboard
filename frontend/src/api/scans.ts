import { get, post } from './http'
import type { DomainProfile } from './domains'

export interface OwaspCategory {
  id: string
  name: string
  description: string
  tags: string[]
  requires: string[]
  payloads: string[]
}

export interface OwaspProfileKey {
  key: keyof DomainProfile
  label: string
  hint: string
}

export const scansApi = {
  // OWASP testing
  owaspCatalog: () => get<{ catalog: OwaspCategory[]; profileKeys: OwaspProfileKey[] }>('/owasp/catalog'),
  runOwasp: (id: number, categoryIds?: string[], scheme?: string, confirm?: boolean, target?: string) =>
    post<{ jobId: number; categories: string[]; tags: string[] }>(`/domains/${id}/owasp`, { categoryIds, scheme, confirm, target }),

  // extra active tools (katana/naabu/dalfox/sslscan/wpenum), gated like scans
  runTool: (id: number, opts: { tool: string; target?: string; scheme?: string; confirm?: boolean; path?: string }) =>
    post<{ jobId: number; tool: string; target: string }>(`/domains/${id}/tool`, opts),

  // active scans (gated server-side; passive domains require confirm:true)
  nmap: (id: number, opts: { target?: string; ports?: string; deep?: boolean; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/scan/nmap`, opts),
  // Attack-surface sweep: one nmap job per live host of the domain (deduped by IP).
  nmapSweep: (id: number, opts: { deep?: boolean; confirm?: boolean } = {}) =>
    post<{
      queued: number
      jobs: { host: string; jobId: number }[]
      skipped: { host: string; reason: string }[]
      capped: boolean
      considered: number
    }>(`/domains/${id}/scan/nmap-sweep`, opts),
  nuclei: (id: number, opts: { target?: string; severity?: string; tags?: string; scheme?: string; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/scan/nuclei`, opts),
  ffuf: (
    id: number,
    opts: { target?: string; path?: string; wordlist?: string; scheme?: string; vhost?: boolean; recursion?: boolean; recursionDepth?: number; autoWordlist?: boolean; confirm?: boolean } = {},
  ) => post<{ jobId: number }>(`/domains/${id}/scan/ffuf`, opts),
  paramDiscovery: (id: number, opts: { target?: string; scheme?: string; path?: string; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/param-discovery`, opts),
  // Verify a passively-observed CVE by running its nuclei template (loud, gated).
  verifyCve: (
    id: number,
    opts: { cveId: string; target?: string; ip?: string; kev?: boolean; scheme?: string; confirm?: boolean },
  ) => post<{ jobId: number }>(`/domains/${id}/verify-cve`, opts),
}
