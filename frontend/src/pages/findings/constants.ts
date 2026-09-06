import { RISK_SCORE_CLASS, type RiskLevel } from '../../lib/format'
import type { FindingStatus } from '../../api'

// Shared constants and small helpers for the Findings page and its components.

export const STATUSES: FindingStatus[] = ['open', 'confirmed', 'retest_pending', 'retest_passed', 'false_positive', 'resolved', 'ignored']
export const STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Draft',
  confirmed: 'Confirmed',
  retest_pending: 'Ready for retest',
  retest_passed: 'Retest passed',
  false_positive: 'False positive',
  resolved: 'Resolved',
  ignored: 'Ignored',
}
// Per-status select styling (border + text) for at-a-glance triage state.
export const STATUS_SELECT: Record<FindingStatus, string> = {
  open: 'text-blue-300 border-blue-900/60',
  confirmed: 'text-red-300 border-red-900/60',
  retest_pending: 'text-amber-300 border-amber-900/60',
  retest_passed: 'text-emerald-300 border-emerald-900/60',
  false_positive: 'text-zinc-400 border-hair',
  resolved: 'text-green-300 border-green-900/60',
  ignored: 'text-zinc-500 border-hair',
}
// Statuses that are "dealt with" — dimmed and hidden from the default Active view.
export const TRIAGED_AWAY: FindingStatus[] = ['false_positive', 'resolved', 'retest_passed', 'ignored']

export const STATUS_FILTERS = ['active', 'all', ...STATUSES] as const
export type StatusFilter = (typeof STATUS_FILTERS)[number]
export const STATUS_FILTER_LABEL: Record<StatusFilter, string> = { active: 'Active', all: 'All', ...STATUS_LABEL }

export const TYPE_OPTIONS = ['', 'new_subdomain', 'exposure', 'osint', 'origin', 'api', 'nmap', 'nuclei', 'ffuf', 'cve_new', 'authz', 'param'] as const

// "New since" presets — filters to findings first discovered within the window
// (createdAt is the frozen first-seen timestamp, so re-scans of unchanged
// findings never re-enter the list).
export const SINCE_PRESETS = ['', '24h', '7d', '30d'] as const
export type SincePreset = (typeof SINCE_PRESETS)[number]
export const SINCE_LABEL: Record<SincePreset, string> = {
  '': 'Any time',
  '24h': 'Last 24h',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
}
export const SINCE_MS: Record<Exclude<SincePreset, ''>, number> = {
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
}

// Server-side page size for keyset pagination; "Load more" fetches the next page.
export const PAGE_SIZE = 100

export const SEVERITY_OPTIONS = ['', 'critical', 'high', 'medium', 'low', 'info'] as const

export const TYPE_LABEL: Record<string, string> = {
  new_subdomain: 'subdomain',
  exposure: 'exposure',
  osint: 'osint',
  origin: 'origin',
  api: 'api',
  nmap: 'nmap',
  nuclei: 'nuclei',
  ffuf: 'ffuf',
  cve_new: 'new CVE',
  authz: 'authz/IDOR',
  param: 'param',
}

// Left-border + score colors by risk level — the at-a-glance signal.
export const RISK_BORDER: Record<RiskLevel, string> = {
  high: 'border-l-red-500',
  medium: 'border-l-amber-500',
  low: 'border-l-blue-500',
  none: 'border-l-zinc-700',
}
// Score-badge colors live in lib/format (shared with Home) to avoid drift.
export const RISK_SCORE = RISK_SCORE_CLASS

export function tagTone(tag: string): 'zinc' | 'blue' | 'amber' | 'red' | 'green' {
  if (/^(kev|cvss:critical|sev:critical|takeover|db-exposed|zone-transfer|origin-found)/.test(tag)) return 'red'
  if (/^(cvss:high|sev:high|admin-port|admin-surface|has-cve|auth-gated|waf:|kw:)/.test(tag)) return 'amber'
  if (/^(tech:|svc:|owasp:|shodan:)/.test(tag)) return 'blue'
  if (tag === 'live' || tag === 'http-2xx') return 'green'
  return 'zinc'
}
