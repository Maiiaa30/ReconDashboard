import { and, desc, eq, inArray, sql } from 'drizzle-orm'
import { db } from '../db/index'
import { jobs } from '../db/schema'

export type JobType =
  | 'subdomain_discovery'
  | 'exposure_scan'
  | 'osint_gather'
  | 'nmap_scan'
  | 'nuclei_scan'
  | 'ffuf_scan'
  | 'screenshot'
  | 'origin_scan'
  | 'owasp_active'
  | 'tool_scan'

// Loud/active job types we deliberately do NOT auto-resume after a crash: a scan
// interrupted mid-run would silently re-fire against the target on the next boot,
// an authorization/noise hazard. Passive discovery is safe to retry.
const LOUD_TYPES: ReadonlySet<JobType> = new Set([
  'nmap_scan',
  'nuclei_scan',
  'ffuf_scan',
  'owasp_active',
  'tool_scan',
  'origin_scan',
])

// After this many claims a job is dead-lettered instead of re-queued, so a job
// that crashes the process on every run can't crash-loop forever.
const MAX_ATTEMPTS = 3

// Job states that still hold a slot / count as "pending" for dedup + cooldown.
const PENDING_STATUSES = ['queued', 'running'] as const

function domainIdOf(params: unknown): number | null {
  if (params && typeof params === 'object') {
    const raw = (params as Record<string, unknown>).domainId
    const n = Number(raw)
    if (Number.isFinite(n) && n > 0) return n
  }
  return null
}

export function enqueueJob(type: JobType, params: unknown): number {
  const res = db
    .insert(jobs)
    .values({ type, status: 'queued', params: JSON.stringify(params ?? {}), domainId: domainIdOf(params) })
    .run()
  return Number(res.lastInsertRowid)
}

// True if a job of this type for this domain is already queued or running.
// Lets the scheduler / playbooks skip enqueuing a duplicate instead of piling
// work onto the single sequential worker.
export function hasPendingJob(type: JobType, domainId: number): boolean {
  const row = db
    .select({ id: jobs.id })
    .from(jobs)
    .where(and(eq(jobs.type, type), eq(jobs.domainId, domainId), inArray(jobs.status, [...PENDING_STATUSES])))
    .limit(1)
    .all()[0]
  return !!row
}

export function getJob(id: number) {
  return db.select().from(jobs).where(eq(jobs.id, id)).limit(1).all()[0]
}

export function listJobs(limit = 100) {
  return db.select().from(jobs).orderBy(desc(jobs.id)).limit(limit).all()
}

// Claim the oldest queued job by flipping it to running. Single in-process
// worker, but written defensively so only one claim wins.
export function claimNextQueued() {
  const next = db
    .select()
    .from(jobs)
    .where(eq(jobs.status, 'queued'))
    .orderBy(jobs.id)
    .limit(1)
    .all()[0]
  if (!next) return undefined

  const res = db
    .update(jobs)
    .set({
      status: 'running',
      startedAt: new Date(),
      updatedAt: new Date(),
      attempts: sql`${jobs.attempts} + 1`,
    })
    .where(and(eq(jobs.id, next.id), eq(jobs.status, 'queued')))
    .run()

  if (res.changes === 0) return undefined // lost the race
  return getJob(next.id)
}

// Terminal writes are guarded by status='running' (like cancelJob is guarded by
// status='queued') so they are idempotent and can't clobber a status that
// changed underneath — e.g. a future running-cancel, or a second process.
// Returns false if the row was no longer 'running'.
export function finishJob(id: number, result: unknown): boolean {
  const res = db
    .update(jobs)
    .set({
      status: 'done',
      result: JSON.stringify(result ?? null),
      finishedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(and(eq(jobs.id, id), eq(jobs.status, 'running')))
    .run()
  return res.changes > 0
}

// Cancel a job that is still queued. Guarded by status='queued' so it can't
// race the worker claiming it — if the worker already flipped it to running,
// changes === 0 and the caller learns it was too late.
export function cancelJob(id: number): boolean {
  const res = db
    .update(jobs)
    .set({ status: 'cancelled', finishedAt: new Date(), updatedAt: new Date() })
    .where(and(eq(jobs.id, id), eq(jobs.status, 'queued')))
    .run()
  return res.changes > 0
}

export function failJob(id: number, error: string): boolean {
  const res = db
    .update(jobs)
    .set({ status: 'error', error, finishedAt: new Date(), updatedAt: new Date() })
    .where(and(eq(jobs.id, id), eq(jobs.status, 'running')))
    .run()
  return res.changes > 0
}

// On boot, any job left 'running' from a previous process was interrupted.
// Passive jobs under the attempt cap are re-queued (retry once more); loud
// active scans and attempt-exhausted jobs are dead-lettered instead of silently
// re-firing against the target or crash-looping forever.
export function requeueStaleRunning(): { requeued: number; dead: number } {
  const stale = db.select().from(jobs).where(eq(jobs.status, 'running')).all()
  let requeued = 0
  let dead = 0
  for (const j of stale) {
    const loud = LOUD_TYPES.has(j.type as JobType)
    const exhausted = (j.attempts ?? 0) >= MAX_ATTEMPTS
    if (loud || exhausted) {
      const reason = loud
        ? 'interrupted mid-run; loud scan not auto-resumed'
        : `interrupted and exhausted ${j.attempts} attempt(s)`
      const res = db
        .update(jobs)
        .set({ status: 'dead', error: reason, finishedAt: new Date(), updatedAt: new Date() })
        .where(and(eq(jobs.id, j.id), eq(jobs.status, 'running')))
        .run()
      if (res.changes > 0) dead++
    } else {
      const res = db
        .update(jobs)
        .set({ status: 'queued', startedAt: null, updatedAt: new Date() })
        .where(and(eq(jobs.id, j.id), eq(jobs.status, 'running')))
        .run()
      if (res.changes > 0) requeued++
    }
  }
  return { requeued, dead }
}
