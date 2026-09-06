import { and, desc, eq, gt, lt, lte, sql, type AnyColumn, type SQL } from 'drizzle-orm'
import { db } from '../db/index'
import { auditLog, users, type AuditEntry } from '../db/schema'

// Resolve a session userId to a username for the ledger (single operator, but we
// record who acted regardless).
export function actorName(userId: number | undefined): string {
  if (!userId) return 'unknown'
  const u = db.select({ username: users.username }).from(users).where(eq(users.id, userId)).limit(1).all()[0]
  return u?.username ?? `user:${userId}`
}

// Append-only audit ledger. We only ever INSERT and SELECT here — never UPDATE
// or DELETE — so the record of active actions against a target stays defensible.

export interface NewAuditEntry {
  actor: string
  action: string
  domainId?: number | null
  target?: string | null
  mode?: string | null
  jobId?: number | null
  detail?: unknown
}

export function writeAudit(e: NewAuditEntry): void {
  const detail =
    e.detail == null ? null : typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail).slice(0, 2000)
  db.insert(auditLog)
    .values({
      actor: e.actor,
      action: e.action,
      domainId: e.domainId ?? null,
      target: e.target ?? null,
      mode: e.mode ?? null,
      jobId: e.jobId ?? null,
      detail,
    })
    .run()
}

export function listAudit(opts: { domainId?: number; limit?: number; before?: number } = {}): AuditEntry[] {
  const conds = []
  if (opts.domainId != null) conds.push(eq(auditLog.domainId, opts.domainId))
  if (opts.before != null) conds.push(lte(auditLog.id, opts.before))
  const limit = Math.min(Math.max(opts.limit ?? 200, 1), 1000)
  return db
    .select()
    .from(auditLog)
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(desc(auditLog.id))
    .limit(limit)
    .all()
}

// queryAudit pushes every filter into SQL and pages with a keyset cursor over the
// primary key, so a page is O(page) regardless of how large the append-only ledger
// grows. The id is a monotonic autoincrement written in insertion (time) order, so
// `id desc` IS newest-first and a single-id keyset needs no composite tuple.

export interface AuditFilter {
  domainId?: number
  // Exact-match facets (the ledger draws from a known, finite vocabulary).
  actor?: string
  action?: string
  mode?: string
  // Substring match (case-insensitive) against the target column.
  target?: string
  since?: Date
}

export interface AuditQuery extends AuditFilter {
  // Page size (default 100, capped). limit+1 rows are fetched to detect a next page.
  limit?: number
  // Opaque keyset cursor from a prior page's `nextCursor` (the last row's id).
  cursor?: string
}

export interface AuditPage {
  entries: AuditEntry[]
  nextCursor: string | null
}

const MAX_PAGE = 500
const DEFAULT_PAGE = 100

// LIKE with an explicit escape so a user-supplied % or _ matches literally rather
// than acting as a wildcard.
function likeContains(col: AnyColumn, term: string): SQL {
  const esc = term.replace(/[\\%_]/g, (c) => `\\${c}`)
  return sql`${col} like ${`%${esc}%`} escape '\\'`
}

function auditConds(f: AuditFilter): SQL[] {
  const conds: SQL[] = []
  if (f.domainId != null) conds.push(eq(auditLog.domainId, f.domainId))
  if (f.actor && f.actor.trim()) conds.push(eq(auditLog.actor, f.actor.trim()))
  if (f.action && f.action.trim()) conds.push(eq(auditLog.action, f.action.trim()))
  if (f.mode && f.mode.trim()) conds.push(eq(auditLog.mode, f.mode.trim()))
  if (f.target && f.target.trim()) conds.push(likeContains(auditLog.target, f.target.trim()))
  if (f.since) conds.push(gt(auditLog.ts, f.since))
  return conds
}

// A page of audit entries for the given filter set, newest first, with a keyset
// cursor to fetch the next page. A garbled/out-of-range cursor is ignored (the
// query restarts from the top) rather than throwing.
export function queryAudit(q: AuditQuery = {}): AuditPage {
  const limit = Math.min(MAX_PAGE, Math.max(1, q.limit ?? DEFAULT_PAGE))
  const conds = auditConds(q)
  if (q.cursor) {
    const c = Number(q.cursor)
    if (Number.isSafeInteger(c) && c > 0) conds.push(lt(auditLog.id, c))
  }
  const rows = db
    .select()
    .from(auditLog)
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(desc(auditLog.id))
    .limit(limit + 1)
    .all()

  const hasMore = rows.length > limit
  const entries = hasMore ? rows.slice(0, limit) : rows
  const nextCursor = hasMore ? String(entries[entries.length - 1].id) : null
  return { entries, nextCursor }
}

export interface AuditSummary {
  total: number
  byAction: Record<string, number>
}

// Counts for the current filter set WITHOUT the action facet applied, so the UI
// can show how many entries sit behind each action without pulling every row.
export function summarizeAudit(f: Omit<AuditFilter, 'action'> = {}): AuditSummary {
  const conds = auditConds(f)
  const rows = db
    .select({ k: auditLog.action, n: sql<number>`count(*)` })
    .from(auditLog)
    .where(conds.length ? and(...conds) : undefined)
    .groupBy(auditLog.action)
    .all()

  const byAction: Record<string, number> = {}
  let total = 0
  for (const r of rows) {
    byAction[r.k] = Number(r.n)
    total += Number(r.n)
  }
  return { total, byAction }
}
