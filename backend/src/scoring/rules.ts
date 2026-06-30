import type { Scorer, ScoreInput, ScoreResult } from './types'
import { isAdminPort, portTags, statusTags, techFromCpe, techTag } from './taxonomy'

// Rules-based scorer. Deterministic, dependency-free heuristics that flag the
// findings an operator most likely cares about, and attach a consistent,
// useful tag taxonomy. Every point/tag is traceable to a rule below.

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 9000])
const INTERESTING_HOST_WORDS = [
  'admin', 'dev', 'staging', 'stage', 'test', 'qa', 'uat', 'internal', 'intranet', 'vpn',
  'jenkins', 'gitlab', 'git', 'jira', 'confluence', 'grafana', 'kibana', 'phpmyadmin',
  'portal', 'api', 'dashboard', 'backup', 'db', 'sql', 'ftp', 'mail', 'smtp', 'remote',
  'rdp', 'corp', 'legacy', 'old', 'beta', 'demo', 'sandbox', 'status', 'monitor', 'sso',
  'auth', 'login', 'payment', 'pay', 'billing', 's3', 'storage', 'cdn', 'assets',
]
const NUCLEI_SEVERITY_SCORE: Record<string, number> = {
  info: 10, low: 25, medium: 50, high: 80, critical: 95, unknown: 15,
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)))
}

function hostInterest(host: string): { score: number; tags: string[] } {
  const tags: string[] = []
  let score = 0
  const lower = host.toLowerCase()
  for (const word of INTERESTING_HOST_WORDS) {
    if (lower.includes(word)) {
      score += 12
      tags.push(`kw:${word}`)
    }
  }
  return { score: Math.min(score, 40), tags }
}

function scoreSubdomain(data: any): ScoreResult {
  const tags = new Set<string>(['subdomain'])
  let score = 12

  const host = String(data?.host ?? '')
  const hi = hostInterest(host)
  score += hi.score
  hi.tags.forEach((t) => tags.add(t))

  // HTTP probe signals.
  for (const t of statusTags(data?.status)) tags.add(t)
  if (data?.status != null) score += 10 // a live host is more interesting
  if (data?.status === 200) score += 6
  if (data?.status === 401 || data?.status === 403) score += 8 // auth surface

  const tt = techTag(data?.server)
  if (tt) tags.add(tt)

  // Takeover candidate flagged during probe (passive heuristic).
  if (data?.takeover?.service) {
    tags.add('takeover-candidate')
    tags.add(`takeover:${data.takeover.service}`)
    score += 45
  }

  return { score: clamp(score), tags: [...tags] }
}

function scoreExposure(data: any): ScoreResult {
  const tags = new Set<string>(['exposure'])
  let score = 8

  const ports: number[] = Array.isArray(data?.ports) ? data.ports : []
  let hasDb = false
  let hasAdmin = false
  for (const p of ports) {
    for (const t of portTags(p)) tags.add(t)
    if (isAdminPort(p)) {
      hasAdmin = true
      score += 16
    } else if (WEB_PORTS.has(p)) {
      score += 4
    } else {
      score += 2
    }
    if ([1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017].includes(p)) hasDb = true
  }
  if (hasDb) tags.add('db-exposed')
  if (hasAdmin) tags.add('admin-surface')

  // CVEs (with enriched severity / KEV when available).
  const vulns: string[] = Array.isArray(data?.vulns) ? data.vulns : []
  const cves: any[] = Array.isArray(data?.cves) ? data.cves : []
  if (vulns.length) {
    score += Math.min(45, vulns.length * 10)
    tags.add('has-cve')
    tags.add(`cves:${vulns.length}`)
    const maxCvss = Math.max(0, ...cves.map((c) => Number(c?.cvss_v3 ?? c?.cvss ?? 0)))
    if (maxCvss >= 9) { tags.add('cvss:critical'); score += 20 }
    else if (maxCvss >= 7) { tags.add('cvss:high'); score += 12 }
    if (cves.some((c) => c?.kev)) { tags.add('kev'); score += 25 }
  }

  // Tech from CPEs and InternetDB tags.
  for (const cpe of (Array.isArray(data?.cpes) ? data.cpes : [])) {
    const t = techFromCpe(String(cpe))
    if (t) tags.add(t)
  }
  for (const t of (Array.isArray(data?.tags) ? data.tags : [])) tags.add(`shodan:${String(t)}`)

  if (data?.host) {
    const hi = hostInterest(String(data.host))
    score += hi.score
    hi.tags.forEach((t) => tags.add(t))
  }

  return { score: clamp(score), tags: [...tags] }
}

function scoreNuclei(data: any): ScoreResult {
  const severity = String(data?.info?.severity ?? data?.severity ?? 'info').toLowerCase()
  const tags = new Set<string>(['nuclei', `sev:${severity}`])
  if (data?.owaspCategory) {
    for (const id of String(data.owaspCategory).split(',')) tags.add(`owasp:${id}`)
  }
  for (const t of (Array.isArray(data?.info?.tags) ? data.info.tags : [])) {
    if (/^[a-z0-9-]{1,30}$/i.test(String(t))) tags.add(String(t).toLowerCase())
  }
  return { score: clamp(NUCLEI_SEVERITY_SCORE[severity] ?? 15), tags: [...tags] }
}

function scoreNmap(data: any): ScoreResult {
  const tags = new Set<string>(['nmap'])
  const open: any[] = Array.isArray(data?.openPorts) ? data.openPorts : []
  let score = 12
  for (const p of open) {
    const port = Number(p?.port)
    if (Number.isFinite(port)) {
      for (const t of portTags(port)) tags.add(t)
      score += isAdminPort(port) ? 12 : 4
    }
    if (p?.product) {
      const t = techTag(String(p.product))
      if (t) tags.add(t)
    }
  }
  return { score: clamp(score), tags: [...tags] }
}

function scoreFfuf(data: any): ScoreResult {
  const tags = new Set<string>(['ffuf'])
  const status = Number(data?.status)
  for (const t of statusTags(Number.isFinite(status) ? status : null)) tags.add(t)
  let score = 22
  if (status === 200) score += 10
  if (status === 401 || status === 403) { tags.add('auth-gated'); score += 6 }
  return { score: clamp(score), tags: [...tags] }
}

export class RulesScorer implements Scorer {
  readonly name = 'rules'

  async score(input: ScoreInput): Promise<ScoreResult> {
    const data = input.data as any
    switch (input.type) {
      case 'new_subdomain':
        return scoreSubdomain(data)
      case 'exposure':
        return scoreExposure(data)
      case 'nuclei':
        return scoreNuclei(data)
      case 'nmap':
        return scoreNmap(data)
      case 'ffuf':
        return scoreFfuf(data)
      default:
        return { score: 15, tags: [input.type] }
    }
  }
}
