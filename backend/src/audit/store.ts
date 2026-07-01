import { and, desc, eq, lte } from 'drizzle-orm'
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
