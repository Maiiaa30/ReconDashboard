import type { Scorer, ScoreInput, ScoreResult } from './types'

// Rules-based scorer. Deterministic, dependency-free heuristics that flag the
// findings an operator most likely cares about. Tuned to be explainable, not
// clever — every point added is traceable to a rule below.

const ADMINISH_PORTS = new Set([
  21, 22, 23, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017,
])
const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888])
const INTERESTING_HOST_WORDS = [
  'admin', 'dev', 'staging', 'stage', 'test', 'qa', 'internal', 'vpn', 'jenkins', 'gitlab',
  'git', 'jira', 'confluence', 'grafana', 'kibana', 'phpmyadmin', 'portal', 'api', 'dashboard',
  'backup', 'db', 'sql', 'ftp', 'mail', 'remote', 'rdp', 'corp', 'legacy', 'old',
]
const INTERESTING_NUCLEI_SEVERITY: Record<string, number> = {
  info: 5,
  low: 20,
  medium: 45,
  high: 75,
  critical: 95,
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
  const host = String(data?.host ?? '')
  const { score, tags } = hostInterest(host)
  return { score: clamp(20 + score), tags: ['new-subdomain', ...tags] }
}

function scoreExposure(data: any): ScoreResult {
  const tags: string[] = ['exposure']
  let score = 10
  const ports: number[] = Array.isArray(data?.ports) ? data.ports : []
  const vulns: string[] = Array.isArray(data?.vulns) ? data.vulns : []

  for (const p of ports) {
    if (ADMINISH_PORTS.has(p)) {
      score += 18
      tags.push(`admin-port:${p}`)
    } else if (WEB_PORTS.has(p)) {
      score += 4
    } else {
      score += 2
    }
  }
  if (vulns.length) {
    score += Math.min(40, vulns.length * 12)
    tags.push(`cves:${vulns.length}`)
    // KEV-style ids bump priority hard.
    if (vulns.some((v) => typeof v === 'string')) tags.push('has-cve')
  }
  if (data?.host) {
    const hi = hostInterest(String(data.host))
    score += hi.score
    tags.push(...hi.tags)
  }
  return { score: clamp(score), tags: [...new Set(tags)] }
}

function scoreNuclei(data: any): ScoreResult {
  const severity = String(data?.info?.severity ?? data?.severity ?? 'info').toLowerCase()
  const base = INTERESTING_NUCLEI_SEVERITY[severity] ?? 10
  return { score: clamp(base), tags: ['nuclei', `sev:${severity}`] }
}

function scoreGeneric(type: string): ScoreResult {
  return { score: 15, tags: [type] }
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
        return { score: clamp(15 + (Array.isArray(data?.openPorts) ? data.openPorts.length * 5 : 0)), tags: ['nmap'] }
      case 'ffuf':
        return { score: 25, tags: ['ffuf'] }
      default:
        return scoreGeneric(input.type)
    }
  }
}
