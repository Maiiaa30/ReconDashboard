import { get, post, type RequestOptions } from './http'
import type { DomainOverview } from './domains'

export interface HomeFinding {
  id: number
  domainId: number | null
  type: string
  data: any
  score: number | null
  tags: string[]
}

export interface RecentChange {
  id: number
  domainId: number | null
  type: 'cve_new' | 'asset_change'
  data: { ip?: string; host?: string; cveId?: string; cvss?: number | null; kev?: boolean; title?: string; detail?: string; action?: { kind: 'nmap' | 'owasp'; label: string; target: string } }
  score: number | null
  createdAt: string
}

// "Today" panel — what's new/risky since the operator's last Home visit.
export interface TodayData {
  since: string
  counts: { findings: number; cves: number; subdomains: number; expiring: number }
  findings: { id: number; domainId: number | null; host: string | null; type: string; data: any; score: number | null; createdAt: string }[]
  cves: { id: number; domainId: number | null; host: string | null; data: any; score: number | null; createdAt: string }[]
  subdomains: { id: number; domainId: number; domainHost: string | null; host: string; httpStatus: number | null; title: string | null; scheme: string | null; loginHint: boolean; firstSeen: string }[]
  expiring: { id: number; host: string; authorizedUntil: string | null; daysLeft: number | null }[]
}

export const homeApi = {
  // engagement home (cross-target overview + top open findings + recent changes)
  home: (options?: RequestOptions) => get<{ overview: DomainOverview[]; topFindings: HomeFinding[]; recentChanges: RecentChange[] }>('/home', options),
  // "Today" — new/risky since the last explicit acknowledgement.
  today: () => get<TodayData>('/home/today'),
  acknowledgeToday: () => post<{ viewedAt: string }>('/home/today/ack'),
}
