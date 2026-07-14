import { and, desc, eq, gt, inArray, isNull } from 'drizzle-orm'
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
  | 'owasp'
  | 'tool'
  | 'cve_new'
  | 'leak'
  | 'api'
  | 'secret'

// Triage lifecycle state.
export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'resolved' | 'ignored'
export const FINDING_STATUSES: FindingStatus[] = ['open', 'confirmed', 'false_positive', 'resolved', 'ignored']

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
    case 'owasp':
      return `owasp:${data.category ?? ''}:${data.name ?? ''}@${data.url ?? ''}`
    case 'tool':
      return `tool:${data.tool ?? ''}@${data.target ?? ''}`
    case 'ffuf':
      return data.url ? `url:${data.url}` : null
    case 'api':
      if (data.kind === 'graphql') return data.endpoint ? `api:gql:${data.endpoint}` : null
      if (data.kind === 'js') return data.host ? `api:js:${data.host}` : null
      return data.specUrl ? `api:spec:${data.specUrl}` : null
    case 'cve_new':
      return data.ip && data.cveId ? `cvenew:${data.ip}:${data.cveId}` : null
    case 'secret':
      // One row per (repo, path) so re-searching the same leaked file dedupes.
      return data.repo && data.path ? `secret:${data.repo}:${data.path}` : null
    case 'leak': {
      // One row per (identity, breach, credential): same account in the same
      // breach dedups on re-check, but distinct passwords stay distinct.
      const who = String(data.email ?? data.username ?? '').toLowerCase()
      const cred = String(data.password ?? data.hashedPassword ?? '').slice(0, 12)
      return who || cred ? `leak:${who}:${data.source ?? ''}:${cred}` : null
    }
    default:
      return null
  }
}

export function addFinding(f: NewFinding): number {
  const key = findingKey(f.type, f.data)
  const now = new Date()
  const values = {
    domainId: f.domainId,
    type: f.type,
    data: JSON.stringify(f.data ?? null),
    score: f.score ?? null,
    tags: JSON.stringify(f.tags ?? []),
    dedupeKey: key,
    lastSeenAt: now,
  }

  // Upsert by (domainId, type, dedupeKey): refresh the existing row instead of
  // inserting a duplicate. createdAt is deliberately NOT touched here — it is the
  // first-seen timestamp, so re-scans preserve discovery age; only lastSeenAt
  // moves forward. (Clobbering createdAt used to destroy age on every monitor
  // tick, breaking diffs/timelines/change alerts.)
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
        .set({ data: values.data, score: values.score, tags: values.tags, lastSeenAt: now })
        .where(eq(findings.id, existing.id))
        .run()
      return existing.id
    }
  }

  const res = db.insert(findings).values(values).run()
  return Number(res.lastInsertRowid)
}

export function listFindings(
  opts: { domainId?: number; type?: FindingType; limit?: number; since?: Date } = {},
) {
  const conds = []
  if (opts.domainId != null) conds.push(eq(findings.domainId, opts.domainId))
  if (opts.type) conds.push(eq(findings.type, opts.type))
  // "New since X": createdAt is the frozen first-seen timestamp, so this only
  // matches findings actually discovered after the anchor — not ones merely
  // re-touched (lastSeenAt) by a later re-scan.
  if (opts.since) conds.push(gt(findings.createdAt, opts.since))

  const rows = db
    .select()
    .from(findings)
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(desc(findings.score), desc(findings.createdAt))
    // Fetch a bounded multiple of the requested limit for dedup headroom (rows
    // come highest-score-first and dedup keeps the first per key, so the top
    // deduped results are preserved) instead of always pulling 5000 rows on
    // every 4–5s poll — a real cost on domains with 1000+ findings.
    .limit(Math.min(5000, Math.max((opts.limit ?? 500) * 3, 1000)))
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

export function getFinding(id: number) {
  const r = db.select().from(findings).where(eq(findings.id, id)).limit(1).all()[0]
  return r ? mapRow(r, safeJsonParse<unknown>(r.data, null)) : undefined
}

// Operator-attached evidence lives as an array on the finding's data.evidence
// (merged, never clobbered). The report renders these alongside any auto-captured
// data.repro. Bounded so a finding's JSON can't balloon.
export interface EvidenceItem {
  request?: string
  response?: string
  screenshotPath?: string
  note?: string
  addedAt: string
}
const EVIDENCE_MAX_ITEMS = 25

export function appendEvidence(
  id: number,
  item: { request?: string; response?: string; screenshotPath?: string; note?: string },
): { evidenceCount: number } | null {
  const row = db.select().from(findings).where(eq(findings.id, id)).limit(1).all()[0]
  if (!row) return null
  const data = safeJsonParse<Record<string, unknown>>(row.data, {}) ?? {}
  if (typeof data !== 'object' || Array.isArray(data)) return null
  const clip = (s: string | undefined, n: number) => (typeof s === 'string' && s.trim() ? s.slice(0, n) : undefined)
  const entry: EvidenceItem = {
    request: clip(item.request, 64 * 1024),
    response: clip(item.response, 128 * 1024),
    screenshotPath: clip(item.screenshotPath, 512),
    note: clip(item.note, 4096),
    addedAt: new Date().toISOString(),
  }
  if (!entry.request && !entry.response && !entry.screenshotPath && !entry.note) return null // nothing to attach
  const evidence: EvidenceItem[] = Array.isArray(data.evidence) ? (data.evidence as EvidenceItem[]) : []
  evidence.push(entry)
  data.evidence = evidence.slice(-EVIDENCE_MAX_ITEMS)
  db.update(findings).set({ data: JSON.stringify(data) }).where(eq(findings.id, id)).run()
  return { evidenceCount: (data.evidence as EvidenceItem[]).length }
}

// Update triage fields only (status/note). Re-scans never touch these, so an
// operator's triage survives across discovery runs (addFinding's upsert leaves
// status/note untouched).
export function updateFindingTriage(id: number, patch: { status?: FindingStatus; note?: string | null }): boolean {
  const set: Record<string, unknown> = {}
  if (patch.status !== undefined) set.status = patch.status
  if (patch.note !== undefined) set.note = patch.note
  if (Object.keys(set).length === 0) return false
  const res = db.update(findings).set(set).where(eq(findings.id, id)).run()
  return res.changes > 0
}

// Triage many findings at once in a single transaction (bulk status/note). The
// long tail of low-value findings is where a solo operator burns the most time.
export function bulkUpdateTriage(ids: number[], patch: { status?: FindingStatus; note?: string | null }): number {
  const set: Record<string, unknown> = {}
  if (patch.status !== undefined) set.status = patch.status
  if (patch.note !== undefined) set.note = patch.note
  if (Object.keys(set).length === 0 || ids.length === 0) return 0
  let changed = 0
  db.transaction((tx) => {
    for (let i = 0; i < ids.length; i += 500) {
      const res = tx.update(findings).set(set).where(inArray(findings.id, ids.slice(i, i + 500))).run()
      changed += res.changes
    }
  })
  return changed
}

// One-time cleanup of duplicate finding rows created before write-time dedup
// existed (so count(*) and the overview reflect reality). Keeps the best
// (highest score, then newest) row per domain+type+key. Returns rows removed.
export function dedupeExistingFindings(): number {
  const rows = db
    .select({ id: findings.id, domainId: findings.domainId, type: findings.type, data: findings.data, score: findings.score, dedupeKey: findings.dedupeKey })
    .from(findings)
    .orderBy(desc(findings.score), desc(findings.id))
    .all()

  const seen = new Set<string>()
  const toDelete: number[] = []
  for (const r of rows) {
    const key = r.dedupeKey ?? findingKey(r.type, safeJsonParse<unknown>(r.data, null))
    if (key == null) continue
    const k = `${r.domainId}|${r.type}|${key}`
    if (seen.has(k)) toDelete.push(r.id)
    else {
      seen.add(k)
      // backfill dedupeKey on the kept row if missing
      if (r.dedupeKey == null) db.update(findings).set({ dedupeKey: key }).where(eq(findings.id, r.id)).run()
    }
  }

  if (toDelete.length) {
    db.transaction((tx) => {
      for (let i = 0; i < toDelete.length; i += 500) {
        tx.delete(findings).where(inArray(findings.id, toDelete.slice(i, i + 500))).run()
      }
    })
  }
  return toDelete.length
}
