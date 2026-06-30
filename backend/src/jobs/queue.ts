import { and, desc, eq } from 'drizzle-orm'
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

export function enqueueJob(type: JobType, params: unknown): number {
  const res = db
    .insert(jobs)
    .values({ type, status: 'queued', params: JSON.stringify(params ?? {}) })
    .run()
  return Number(res.lastInsertRowid)
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
    .set({ status: 'running', startedAt: new Date(), updatedAt: new Date() })
    .where(and(eq(jobs.id, next.id), eq(jobs.status, 'queued')))
    .run()

  if (res.changes === 0) return undefined // lost the race
  return getJob(next.id)
}

export function finishJob(id: number, result: unknown): void {
  db.update(jobs)
    .set({
      status: 'done',
      result: JSON.stringify(result ?? null),
      finishedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(jobs.id, id))
    .run()
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

export function failJob(id: number, error: string): void {
  db.update(jobs)
    .set({ status: 'error', error, finishedAt: new Date(), updatedAt: new Date() })
    .where(eq(jobs.id, id))
    .run()
}

// On boot, any job left 'running' from a previous process is stale.
export function requeueStaleRunning(): number {
  const res = db
    .update(jobs)
    .set({ status: 'queued', startedAt: null, updatedAt: new Date() })
    .where(eq(jobs.status, 'running'))
    .run()
  return res.changes
}
