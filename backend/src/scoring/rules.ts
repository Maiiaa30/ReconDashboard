import type { Scorer, ScoreInput, ScoreResult } from './types'
import { isAdminPort, portTags, statusTags, techFromCpe, techTag } from './taxonomy'

// Rules-based scorer. Deterministic, dependency-free heuristics that flag the
// findings an operator most likely cares about, attach a consistent tag
// taxonomy, AND explain themselves: every score function emits `reasons` so the
// UI can show *why* a finding scored the way it did.

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 9000])
const DB_PORTS = [1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017]
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
  if (!Number.isFinite(n)) return 0
  return Math.max(0, Math.min(100, Math.round(n)))
}

function hostInterest(host: string): { score: number; tags: string[]; reasons: string[] } {
  const tags: string[] = []
  const reasons: string[] = []
  let score = 0
  const lower = host.toLowerCase()
  for (const word of INTERESTING_HOST_WORDS) {
    if (lower.includes(word)) {
      score += 12
      tags.push(`kw:${word}`)
      reasons.push(`Hostname contains "${word}" — often a higher-value target (+12)`)
    }
  }
  return { score: Math.min(score, 40), tags, reasons }
}

function scoreSubdomain(data: any): ScoreResult {
  const tags = new Set<string>(['subdomain'])
  const reasons: string[] = []
  let score = 12

  const host = String(data?.host ?? '')
  const hi = hostInterest(host)
  score += hi.score
  hi.tags.forEach((t) => tags.add(t))
  reasons.push(...hi.reasons)

  for (const t of statusTags(data?.status)) tags.add(t)
  if (data?.status != null) {
    score += 10
    reasons.push(`Live host — responds to HTTP (status ${data.status}) (+10)`)
  }
  if (data?.status === 200) {
    score += 6
    reasons.push('Returns 200 OK — a reachable app surface (+6)')
  }
  if (data?.status === 401 || data?.status === 403) {
    score += 8
    reasons.push(`Authentication surface (HTTP ${data.status}) worth probing (+8)`)
  }

  const tt = techTag(data?.server)
  if (tt) tags.add(tt)

  if (data?.takeover?.service) {
    tags.add('takeover-candidate')
    tags.add(`takeover:${data.takeover.service}`)
    score += 45
    reasons.push(`Possible subdomain takeover via ${data.takeover.service} (dangling CNAME) (+45)`)
  }

  return { score: clamp(score), tags: [...tags], reasons }
}

function scoreExposure(data: any): ScoreResult {
  const tags = new Set<string>(['exposure'])
  const reasons: string[] = []
  let score = 8

  const ports: number[] = Array.isArray(data?.ports) ? data.ports : []
  const adminPorts: number[] = []
  const dbPorts: number[] = []
  for (const p of ports) {
    for (const t of portTags(p)) tags.add(t)
    if (isAdminPort(p)) {
      adminPorts.push(p)
      score += 16
    } else if (WEB_PORTS.has(p)) {
      score += 4
    } else {
      score += 2
    }
    if (DB_PORTS.includes(p)) dbPorts.push(p)
  }
  if (dbPorts.length) {
    tags.add('db-exposed')
    reasons.push(`Database port(s) reachable from the internet: ${dbPorts.join(', ')}`)
  }
  if (adminPorts.length) {
    tags.add('admin-surface')
    reasons.push(`Admin/remote-access port(s) open: ${adminPorts.join(', ')} (+16 each)`)
  }
  if (ports.length) reasons.push(`${ports.length} open port(s) total`)

  const vulns: string[] = Array.isArray(data?.vulns) ? data.vulns : []
  const cves: any[] = Array.isArray(data?.cves) ? data.cves : []
  if (vulns.length) {
    score += Math.min(45, vulns.length * 10)
    tags.add('has-cve')
    tags.add(`cves:${vulns.length}`)
    reasons.push(`${vulns.length} known CVE(s) match the detected software (+${Math.min(45, vulns.length * 10)})`)
    const maxCvss = Math.max(0, ...cves.map((c) => Number(c?.cvss_v3 ?? c?.cvss ?? 0)))
    if (maxCvss >= 9) {
      tags.add('cvss:critical')
      score += 20
      reasons.push(`Critical-severity CVE present (CVSS ${maxCvss}) (+20)`)
    } else if (maxCvss >= 7) {
      tags.add('cvss:high')
      score += 12
      reasons.push(`High-severity CVE present (CVSS ${maxCvss}) (+12)`)
    }
    if (cves.some((c) => c?.kev)) {
      tags.add('kev')
      score += 25
      reasons.push('Contains a CISA KEV CVE — known to be actively exploited (+25)')
    }
  }

  for (const cpe of (Array.isArray(data?.cpes) ? data.cpes : [])) {
    const t = techFromCpe(String(cpe))
    if (t) tags.add(t)
  }
  for (const t of (Array.isArray(data?.tags) ? data.tags : [])) tags.add(`shodan:${String(t)}`)

  if (data?.host) {
    const hi = hostInterest(String(data.host))
    score += hi.score
    hi.tags.forEach((t) => tags.add(t))
    reasons.push(...hi.reasons)
  }

  return { score: clamp(score), tags: [...tags], reasons }
}

function scoreNuclei(data: any): ScoreResult {
  const severity = String(data?.info?.severity ?? data?.severity ?? 'info').toLowerCase()
  const tags = new Set<string>(['nuclei', `sev:${severity}`])
  const reasons = [`nuclei matched a ${severity}-severity template`]
  if (data?.info?.name) reasons.push(`Template: ${data.info.name}`)
  if (data?.owaspCategory) {
    for (const id of String(data.owaspCategory).split(',')) tags.add(`owasp:${id}`)
  }
  for (const t of (Array.isArray(data?.info?.tags) ? data.info.tags : [])) {
    if (/^[a-z0-9-]{1,30}$/i.test(String(t))) tags.add(String(t).toLowerCase())
  }
  return { score: clamp(NUCLEI_SEVERITY_SCORE[severity] ?? 15), tags: [...tags], reasons }
}

function scoreNmap(data: any): ScoreResult {
  const tags = new Set<string>(['nmap'])
  const reasons: string[] = []
  const open: any[] = Array.isArray(data?.openPorts) ? data.openPorts : []
  let score = 12
  const adminOpen: number[] = []
  for (const p of open) {
    const port = Number(p?.port)
    if (Number.isFinite(port)) {
      for (const t of portTags(port)) tags.add(t)
      if (isAdminPort(port)) {
        adminOpen.push(port)
        score += 12
      } else {
        score += 4
      }
    }
    if (p?.product) {
      const t = techTag(String(p.product))
      if (t) tags.add(t)
    }
  }
  if (open.length) reasons.push(`${open.length} open service(s) detected`)
  if (adminOpen.length) reasons.push(`Admin/remote port(s) open: ${adminOpen.join(', ')} (+12 each)`)
  return { score: clamp(score), tags: [...tags], reasons }
}

function scoreOwasp(data: any): ScoreResult {
  const severity = String(data?.severity ?? 'info').toLowerCase()
  const category = String(data?.category ?? '')
  const tags = new Set<string>(['owasp', 'active', `sev:${severity}`])
  if (category) tags.add(`owasp:${category}`)
  const reasons: string[] = []
  if (data?.name) reasons.push(`${category ? category + ' — ' : ''}${data.name}`)
  if (data?.evidence) reasons.push(`Evidence: ${data.evidence}`)
  return { score: clamp(NUCLEI_SEVERITY_SCORE[severity] ?? 15), tags: [...tags], reasons }
}

function scoreFfuf(data: any): ScoreResult {
  const tags = new Set<string>(['ffuf'])
  const reasons: string[] = []
  const status = Number(data?.status)
  for (const t of statusTags(Number.isFinite(status) ? status : null)) tags.add(t)
  let score = 22
  if (status === 200) {
    score += 10
    reasons.push('Discovered path returns 200 OK — content exists (+10)')
  }
  if (status === 401 || status === 403) {
    tags.add('auth-gated')
    score += 6
    reasons.push(`Discovered path is auth-gated (HTTP ${status}) — sensitive endpoint (+6)`)
  }
  return { score: clamp(score), tags: [...tags], reasons }
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
      case 'owasp':
        return scoreOwasp(data)
      case 'nmap':
        return scoreNmap(data)
      case 'ffuf':
        return scoreFfuf(data)
      default:
        return { score: 15, tags: [input.type], reasons: [] }
    }
  }
}
