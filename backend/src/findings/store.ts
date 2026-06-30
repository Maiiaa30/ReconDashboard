import { and, desc, eq } from 'drizzle-orm'
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

export interface NewFinding {
  domainId: number | null
  type: FindingType
  data: unknown
  score?: number | null
  tags?: string[]
}

export function addFinding(f: NewFinding): number {
  const res = db
    .insert(findings)
    .values({
      domainId: f.domainId,
      type: f.type,
      data: JSON.stringify(f.data ?? null),
      score: f.score ?? null,
      tags: JSON.stringify(f.tags ?? []),
    })
    .run()
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
    .limit(opts.limit ?? 500)
    .all()

  return rows.map((r) => ({
    ...r,
    data: safeJsonParse<unknown>(r.data, null),
    tags: safeJsonParse<string[]>(r.tags, []),
  }))
}

export function updateFindingScore(id: number, score: number, tags: string[]): void {
  db.update(findings).set({ score, tags: JSON.stringify(tags) }).where(eq(findings.id, id)).run()
}
