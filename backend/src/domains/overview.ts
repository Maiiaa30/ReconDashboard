import { desc, eq, sql } from 'drizzle-orm'
import { db } from '../db/index'
import { domains, findings, subdomains } from '../db/schema'
import { safeJsonParse } from '../util/json'

export interface DomainOverview {
  id: number
  host: string
  label: string | null
  mode: string
  createdAt: number | null
  subdomains: { total: number; new: number }
  findings: { total: number; maxScore: number | null }
  exposure: { ips: number; openPorts: number; cves: number }
  lastActivity: number | null // epoch ms of most recent recon data
  monitorIntervalHours: number
}

// Short TTL cache: the Domains page polls this and it scans exposure findings,
// so coalesce bursts of requests into one computation.
let cache: { at: number; data: DomainOverview[] } | null = null
const TTL_MS = 8_000

// Drop the cache so the next read recomputes immediately. Called when the domain
// set changes (add/edit/delete) so a freshly-added domain shows up at once
// instead of after the TTL window.
export function invalidateDomainOverviews(): void {
  cache = null
}

// One pass of aggregate queries (GROUP BY) instead of N+1, then assembled in JS.
export function domainOverviews(): DomainOverview[] {
  const nowMs = Date.now()
  if (cache && nowMs - cache.at < TTL_MS) return cache.data

  const doms = db.select().from(domains).orderBy(desc(domains.id)).all()

  const subAgg = db
    .select({
      domainId: subdomains.domainId,
      total: sql<number>`count(*)`,
      fresh: sql<number>`sum(case when ${subdomains.isNew} then 1 else 0 end)`,
      lastSeen: sql<number>`max(${subdomains.lastSeen})`,
    })
    .from(subdomains)
    .groupBy(subdomains.domainId)
    .all()

  const findAgg = db
    .select({
      domainId: findings.domainId,
      total: sql<number>`count(*)`,
      maxScore: sql<number>`max(${findings.score})`,
      lastCreated: sql<number>`max(${findings.createdAt})`,
    })
    .from(findings)
    .groupBy(findings.domainId)
    .all()

  // Exposure highlights need the JSON payload. A single global LIMIT would let a
  // high-volume domain push older domains entirely out of the window (showing
  // them 0 IPs/ports/CVEs); instead apply a PER-DOMAIN cap so every domain gets
  // a fair slice, with a generous overall safety limit to bound work.
  const EXP_PER_DOMAIN_CAP = 5_000
  const EXP_SAFETY_LIMIT = 50_000
  const expRows = db
    .select({ domainId: findings.domainId, data: findings.data })
    .from(findings)
    .where(eq(findings.type, 'exposure'))
    .orderBy(desc(findings.id))
    .limit(EXP_SAFETY_LIMIT)
    .all()

  const subMap = new Map(subAgg.map((r) => [r.domainId, r]))
  const findMap = new Map(findAgg.map((r) => [r.domainId, r]))

  const expMap = new Map<number, { ips: Set<string>; ports: Set<number>; cves: Set<string> }>()
  const perDomainSeen = new Map<number, number>()
  for (const row of expRows) {
    if (row.domainId == null) continue
    const seen = perDomainSeen.get(row.domainId) ?? 0
    if (seen >= EXP_PER_DOMAIN_CAP) continue
    perDomainSeen.set(row.domainId, seen + 1)
    const data = safeJsonParse<{ ip?: string; ports?: number[]; vulns?: string[] }>(row.data, {})
    if (!expMap.has(row.domainId)) {
      expMap.set(row.domainId, { ips: new Set(), ports: new Set(), cves: new Set() })
    }
    const agg = expMap.get(row.domainId)!
    if (data.ip) agg.ips.add(data.ip)
    for (const p of data.ports ?? []) agg.ports.add(p)
    for (const v of data.vulns ?? []) agg.cves.add(v)
  }

  const data = doms.map((d) => {
    const s = subMap.get(d.id)
    const f = findMap.get(d.id)
    const e = expMap.get(d.id)
    const lastActivity = Math.max(Number(s?.lastSeen ?? 0), Number(f?.lastCreated ?? 0)) || null
    return {
      id: d.id,
      host: d.host,
      label: d.label,
      mode: d.mode,
      createdAt: d.createdAt ? d.createdAt.getTime() : null,
      subdomains: { total: Number(s?.total ?? 0), new: Number(s?.fresh ?? 0) },
      findings: { total: Number(f?.total ?? 0), maxScore: f?.maxScore ?? null },
      exposure: { ips: e?.ips.size ?? 0, openPorts: e?.ports.size ?? 0, cves: e?.cves.size ?? 0 },
      lastActivity,
      monitorIntervalHours: d.monitorIntervalHours ?? 0,
    }
  })

  cache = { at: nowMs, data }
  return data
}
