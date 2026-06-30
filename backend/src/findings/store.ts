import { and, desc, eq, isNull } from 'drizzle-orm'
import { db } from '../db/index'
import { findings } from '../db/schema'
import { safeJsonParse } from '../util/json'

// Finding types currently produced by the system.
export type FindingType =
  | 'new_subdomain'
  | 'exposure'
  | 'osint'
  | 'nmap'
  | 'nuclei'
  | 'ffuf'
  | 'origin'

export interface NewFinding {
  domainId: number | null
  type: FindingType
  data: unknown
  score?: number | null
  tags?: string[]
}

// Stable identity for a finding so re-scans update the same row, not a dupe.
export function findingKey(type: string, data: any): string | null {
  if (!data) return null
  switch (type) {
    case 'new_subdomain':
      return data.host ? `host:${data.host}` : null
    case 'exposure':
      return data.ip ? `ip:${data.ip}` : null
    case 'origin':
      return `origin:${data.domain ?? ''}`
    case 'osint':
      return `osint:${data.kind ?? data.domain ?? ''}`
    case 'nmap':
      return `nmap:${data.target ?? ''}`
    case 'nuclei':
      return `nuclei:${data.templateId ?? ''}@${data.matched ?? data.target ?? ''}`
    case 'ffuf':
      return data.url ? `url:${data.url}` : null
    default:
      return null
  }
}

export function addFinding(f: NewFinding): number {
  const key = findingKey(f.type, f.data)
  const values = {
    domainId: f.domainId,
    type: f.type,
    data: JSON.stringify(f.data ?? null),
    score: f.score ?? null,
    tags: JSON.stringify(f.tags ?? []),
    dedupeKey: key,
  }

  // Upsert by (domainId, type, dedupeKey): refresh the existing row instead of
  // inserting a duplicate.
  if (key != null) {
    const existing = db
      .select({ id: findings.id })
      .from(findings)
      .where(
        and(
          f.domainId == null ? isNull(findings.domainId) : eq(findings.domainId, f.domainId),
          eq(findings.type, f.type),
          eq(findings.dedupeKey, key),
        ),
      )
      .limit(1)
      .all()[0]
    if (existing) {
      db.update(findings)
        .set({ data: values.data, score: values.score, tags: values.tags, createdAt: new Date() })
        .where(eq(findings.id, existing.id))
        .run()
      return existing.id
    }
  }

  const res = db.insert(findings).values(values).run()
  return Number(res.lastInsertRowid)
}

export function listFindings(opts: { domainId?: number; type?: FindingType; limit?: number } = {}) {
  const conds = []
  if (opts.domainId != null) conds.push(eq(findings.domainId, opts.domainId))
  if (opts.type) conds.push(eq(findings.type, opts.type))

  const rows = db
    .select()
    .from(findings)
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(desc(findings.score), desc(findings.createdAt))
    .limit(Math.max(opts.limit ?? 500, 5000)) // fetch enough to dedup, then cap below
    .all()

  // Read-time dedup (covers rows created before dedupeKey existed): keep the
  // first (highest-scored) finding per domain+type+key.
  const seen = new Set<string>()
  const out: ReturnType<typeof mapRow>[] = []
  for (const r of rows) {
    const data = safeJsonParse<unknown>(r.data, null)
    const key = r.dedupeKey ?? findingKey(r.type, data)
    if (key != null) {
      const dedup = `${r.domainId}|${r.type}|${key}`
      if (seen.has(dedup)) continue
      seen.add(dedup)
    }
    out.push(mapRow(r, data))
    if (out.length >= (opts.limit ?? 500)) break
  }
  return out
}

function mapRow(r: typeof findings.$inferSelect, data: unknown) {
  return { ...r, data, tags: safeJsonParse<string[]>(r.tags, []) }
}

export function updateFindingScore(id: number, score: number, tags: string[]): void {
  db.update(findings).set({ score, tags: JSON.stringify(tags) }).where(eq(findings.id, id)).run()
}
