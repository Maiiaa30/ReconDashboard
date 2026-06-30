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
}

// One pass of aggregate queries (GROUP BY) instead of N+1, then assembled in JS.
export function domainOverviews(): DomainOverview[] {
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

  // Exposure highlights need the JSON payload; bounded by # of exposure findings.
  const expRows = db
    .select({ domainId: findings.domainId, data: findings.data })
    .from(findings)
    .where(eq(findings.type, 'exposure'))
    .all()

  const subMap = new Map(subAgg.map((r) => [r.domainId, r]))
  const findMap = new Map(findAgg.map((r) => [r.domainId, r]))

  const expMap = new Map<number, { ips: Set<string>; ports: Set<number>; cves: Set<string> }>()
  for (const row of expRows) {
    if (row.domainId == null) continue
    const data = safeJsonParse<{ ip?: string; ports?: number[]; vulns?: string[] }>(row.data, {})
    if (!expMap.has(row.domainId)) {
      expMap.set(row.domainId, { ips: new Set(), ports: new Set(), cves: new Set() })
    }
    const agg = expMap.get(row.domainId)!
    if (data.ip) agg.ips.add(data.ip)
    for (const p of data.ports ?? []) agg.ports.add(p)
    for (const v of data.vulns ?? []) agg.cves.add(v)
  }

  return doms.map((d) => {
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
    }
  })
}
