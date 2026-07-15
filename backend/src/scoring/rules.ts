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
    tags.add(`takeover:${data.takeover.service}`)
    if (data.takeover.confirmed) {
      tags.add('takeover-confirmed')
      tags.add('sev:critical')
      score += 95
      reasons.push(`CONFIRMED subdomain takeover via ${data.takeover.service} — the service's unclaimed-page response is being served (+95)`)
    } else {
      tags.add('takeover-candidate')
      score += 45
      reasons.push(`Possible subdomain takeover via ${data.takeover.service} (dangling CNAME) (+45)`)
    }
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
    // reduce, not Math.max(...spread): a pathological CVE list would blow the
    // call stack when spread as arguments.
    const maxCvss = cves.reduce((m, c) => Math.max(m, Number(c?.cvss_v3 ?? c?.cvss ?? 0)), 0)
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

function scoreTool(data: any): ScoreResult {
  const severity = String(data?.severity ?? 'info').toLowerCase()
  const tool = String(data?.tool ?? 'tool')
  const tags = new Set<string>(['tool', tool, `sev:${severity}`])
  const reasons: string[] = []
  if (data?.title) reasons.push(`${tool}: ${data.title}`)
  if (data?.detail) reasons.push(String(data.detail))
  for (const it of (Array.isArray(data?.items) ? data.items : []).slice(0, 8)) reasons.push(String(it))
  return { score: clamp(NUCLEI_SEVERITY_SCORE[severity] ?? 15), tags: [...tags], reasons }
}

function scoreOrigin(data: any): ScoreResult {
  const provider: string | null = data?.provider ?? null
  const confirmed = Array.isArray(data?.confirmedOrigins) ? data.confirmedOrigins.length : 0
  const tags = new Set<string>(['origin'])
  if (provider) tags.add(`waf:${provider}`)
  if (confirmed) tags.add('origin-found')
  const reasons: string[] = []
  let score: number
  if (provider && confirmed) {
    score = 85
    reasons.push(`Real origin IP found behind ${provider} — defeats the edge/WAF for authorized scans (${confirmed} confirmed) (85)`)
  } else if (confirmed) {
    score = 45
    reasons.push(`${confirmed} candidate origin IP(s) confirmed; no CDN/WAF detected (45)`)
  } else if (provider) {
    score = 25
    reasons.push(`Behind ${provider}; no origin IP confirmed yet (25)`)
  } else {
    score = 10
    reasons.push('No CDN/WAF detected; nothing to bypass (10)')
  }
  return { score: clamp(score), tags: [...tags], reasons }
}

function scoreOsint(data: any): ScoreResult {
  const tags = new Set<string>(['osint'])
  const reasons: string[] = []
  let score = 12
  const tech = data?.tech && typeof data.tech === 'object' && !('error' in data.tech) ? data.tech : null
  if (tech) {
    if (tech.os) reasons.push(`OS: ${tech.os}`)
    if (tech.server) reasons.push(`Server: ${tech.server}`)
    if (tech.cdn) reasons.push(`CDN: ${tech.cdn}`)
    if (Array.isArray(tech.technologies) && tech.technologies.length) {
      reasons.push(`Stack: ${tech.technologies.slice(0, 8).join(', ')} (+4)`)
      score += 4
    }
  }
  const archived = Number(data?.archivedUrls ?? data?.wayback?.count ?? 0)
  if (archived > 0) reasons.push(`${archived} archived URL(s) available for parameter/endpoint mining`)
  if (reasons.length === 0) reasons.push(`Passive OSINT gathered for ${data?.domain ?? 'the domain'}`)
  return { score: clamp(score), tags: [...tags], reasons }
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

function scoreApi(data: any): ScoreResult {
  const tags = new Set<string>(['api'])
  const reasons: string[] = []
  let score = 20

  if (data?.kind === 'js') {
    tags.add('js-endpoints')
    const eps = Array.isArray(data.endpoints) ? data.endpoints.length : 0
    const secs = Array.isArray(data.secrets) ? data.secrets.length : 0
    score = 18
    reasons.push(`${eps} API endpoint(s) extracted from the site's JavaScript`)
    if (Array.isArray(data.params) && data.params.length) {
      reasons.push(`${data.params.length} request parameter name(s) for testing`)
    }
    if (secs > 0) {
      tags.add('secret-in-js')
      score = 65
      reasons.push(`${secs} possible secret(s) found in JS — REVIEW (may be false positives)`)
    }
    return { score: clamp(score), tags: [...tags], reasons }
  }

  if (data?.kind === 'graphql') {
    tags.add('graphql')
    reasons.push(`GraphQL endpoint exposed at ${data.endpoint ?? '?'}`)
    if (data.introspectionEnabled) {
      tags.add('graphql-introspection')
      score = 55
      reasons.push('GraphQL introspection is ENABLED — the full schema is publicly readable (disable in production)')
      if (data.typeCount) reasons.push(`${data.typeCount} types exposed via introspection`)
    } else {
      score = 22
      reasons.push('Introspection appears disabled (good)')
    }
  } else {
    // OpenAPI / Swagger spec
    tags.add('api-spec')
    tags.add(data?.format === 'swagger' ? 'swagger' : 'openapi')
    reasons.push(`Public API spec (${data?.format ?? 'openapi'} ${data?.version ?? ''}) at ${data?.specUrl ?? '?'}`)
    if (data?.operationCount) reasons.push(`${data.operationCount} operation(s) enumerated from the spec`)
    if (!Array.isArray(data?.authSchemes) || data.authSchemes.length === 0) {
      tags.add('no-auth-scheme')
      score += 10
      reasons.push('Spec declares no security schemes — endpoints may be unauthenticated (+10)')
    } else {
      reasons.push(`Auth schemes: ${data.authSchemes.slice(0, 4).join(', ')}`)
    }
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
      case 'tool':
        return scoreTool(data)
      case 'nmap':
        return scoreNmap(data)
      case 'ffuf':
        return scoreFfuf(data)
      case 'origin':
        return scoreOrigin(data)
      case 'osint':
        return scoreOsint(data)
      case 'api':
        return scoreApi(data)
      default:
        return { score: 15, tags: [input.type], reasons: [] }
    }
  }
}
