import { and, desc, eq, inArray, lt, notInArray, sql } from 'drizzle-orm'
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
  | 'leak_check'
  | 'api_discovery'
  | 'intruder'
  | 'code_leak'
  | 'cve_verify'
  | 'authz_diff'
  | 'param_discovery'
  | 'inject_confirm'
  | 'jwt_confuse'

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
  'intruder',
  'cve_verify',
  'authz_diff',
  'param_discovery',
  'inject_confirm',
  'jwt_confuse',
])

// After this many claims a job is dead-lettered instead of re-queued, so a job
// that crashes the process on every run can't crash-loop forever.
const MAX_ATTEMPTS = 3

// Hard wall-clock cap per job. The worker enforces it in-process (withTimeout);
// the reaper below uses it to catch jobs left 'running' past the deadline after
// the worker/process that owned their timer died. The grace margin keeps the
// reaper from racing a job whose in-process timeout is firing at the same moment.
export const JOB_TIMEOUT_MS = 20 * 60 * 1000
const REAP_GRACE_MS = 5 * 60 * 1000

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

// When the most recent SUCCESSFUL job of this type for this domain finished
// (null if none). Powers the per-target active-scan cooldown so a fat-fingered
// double-click / backed-up scheduler can't machine-gun a fragile target.
export function lastFinishedJobAt(type: JobType, domainId: number): Date | null {
  const row = db
    .select({ finishedAt: jobs.finishedAt })
    .from(jobs)
    .where(and(eq(jobs.type, type), eq(jobs.domainId, domainId), eq(jobs.status, 'done')))
    .orderBy(desc(jobs.finishedAt))
    .limit(1)
    .all()[0]
  return row?.finishedAt ?? null
}

// When the most recent job of this type for this domain was created, regardless
// of status (null if none). Used to gate the daily leak check so an errored run
// (e.g. bad API key) doesn't re-enqueue every 60s tick — the cadence is anchored
// on last attempt, not last success.
export function lastJobAt(type: JobType, domainId: number): Date | null {
  const row = db
    .select({ createdAt: jobs.createdAt })
    .from(jobs)
    .where(and(eq(jobs.type, type), eq(jobs.domainId, domainId)))
    .orderBy(desc(jobs.id))
    .limit(1)
    .all()[0]
  return row?.createdAt ?? null
}

// Loud/active job types (do-not-auto-resume set) — also used to decide which
// jobs to write to the audit ledger at start/finish.
export function isLoudJob(type: string): boolean {
  return LOUD_TYPES.has(type as JobType)
}

export function getJob(id: number) {
  return db.select().from(jobs).where(eq(jobs.id, id)).limit(1).all()[0]
}

export function listJobs(limit = 100) {
  return db.select().from(jobs).orderBy(desc(jobs.id)).limit(limit).all()
}

// A lane restricts claiming to loud/active job types or everything else, so the
// worker can run a passive job and a loud scan concurrently without loud scans
// running in parallel against a target. Omit for the old "any job" behaviour.
export type JobLane = 'passive' | 'loud'

const LOUD_TYPE_ARR = [...LOUD_TYPES]

// Claim the oldest queued job (optionally within a lane) by flipping it to
// running. Written defensively (guarded UPDATE) so only one claim wins even with
// two lane loops polling at once.
export function claimNextQueued(lane?: JobLane) {
  const laneCond =
    lane === 'loud' ? inArray(jobs.type, LOUD_TYPE_ARR) : lane === 'passive' ? notInArray(jobs.type, LOUD_TYPE_ARR) : undefined
  const next = db
    .select()
    .from(jobs)
    .where(laneCond ? and(eq(jobs.status, 'queued'), laneCond) : eq(jobs.status, 'queued'))
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

// Coarse progress line for a running job (bumps updatedAt so a stale detector
// and the UI can distinguish a slow job from a wedged one).
export function setJobProgress(id: number, progress: string): void {
  db.update(jobs)
    .set({ progress: progress.slice(0, 500), updatedAt: new Date() })
    .where(and(eq(jobs.id, id), eq(jobs.status, 'running')))
    .run()
}

// Persist an operator's cancel request on a queued/running job. Durable so it
// survives a restart: requeueStaleRunning honors it (cancel, don't re-run) and
// the worker refuses to start a job that carries it. No-op (false) once the job
// has reached a terminal state.
export function markCancelRequested(id: number): boolean {
  const res = db
    .update(jobs)
    .set({ cancelRequested: true, updatedAt: new Date() })
    .where(and(eq(jobs.id, id), inArray(jobs.status, [...PENDING_STATUSES])))
    .run()
  return res.changes > 0
}

// Mark a running job cancelled (operator aborted it). Guarded by status='running'.
export function markJobCancelled(id: number): boolean {
  const res = db
    .update(jobs)
    .set({ status: 'cancelled', error: 'cancelled by operator', finishedAt: new Date(), updatedAt: new Date() })
    .where(and(eq(jobs.id, id), eq(jobs.status, 'running')))
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

// Resolve jobs stuck in 'running'. Two callers:
//   • boot (no options): every 'running' row is stale — no worker is executing
//     it, it was interrupted by the restart.
//   • the periodic reaper (onlyOlderThanMs): only jobs whose startedAt is past
//     the wall-clock deadline, i.e. orphaned 'running' rows whose in-process
//     timer died with their worker; a job still under the deadline is being
//     executed right now and is left alone.
// Resolution: a job the operator asked to cancel is cancelled; loud active scans
// and attempt-exhausted jobs are dead-lettered (never silently re-fire against a
// target or crash-loop); passive jobs under the cap are re-queued.
export function requeueStaleRunning(opts: { onlyOlderThanMs?: number } = {}): {
  requeued: number
  dead: number
  cancelled: number
} {
  let stale = db.select().from(jobs).where(eq(jobs.status, 'running')).all()
  if (opts.onlyOlderThanMs != null) {
    const cutoff = Date.now() - opts.onlyOlderThanMs
    stale = stale.filter((j) => j.startedAt != null && j.startedAt.getTime() < cutoff)
  }
  let requeued = 0
  let dead = 0
  let cancelled = 0
  for (const j of stale) {
    // Honor a durable cancel first — the operator asked for this job to stop, so
    // don't re-run or dead-letter it.
    if (j.cancelRequested) {
      const res = db
        .update(jobs)
        .set({ status: 'cancelled', error: 'cancelled by operator', finishedAt: new Date(), updatedAt: new Date() })
        .where(and(eq(jobs.id, j.id), eq(jobs.status, 'running')))
        .run()
      if (res.changes > 0) cancelled++
      continue
    }
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
  return { requeued, dead, cancelled }
}

// Periodic reaper: resolve any job left 'running' well past the wall-clock
// deadline. Unlike the in-process withTimeout, this catches a job whose worker
// died holding its timer (the DB row is stuck 'running' forever otherwise).
export function reapTimedOutRunning(): { requeued: number; dead: number; cancelled: number } {
  return requeueStaleRunning({ onlyOlderThanMs: JOB_TIMEOUT_MS + REAP_GRACE_MS })
}

// --- Retention (audit §4): the jobs table grows forever otherwise ------------

const TERMINAL_STATUSES = ['done', 'error', 'cancelled', 'dead'] as const

// Delete terminal job rows older than the cutoff. NEVER touches queued/running
// (updatedAt is bumped on every state change, so for a terminal row it marks when
// the job finished). Returns the number of rows removed.
export function pruneTerminalJobs(olderThanMs: number): number {
  const cutoff = new Date(Date.now() - olderThanMs)
  const res = db
    .delete(jobs)
    .where(and(inArray(jobs.status, [...TERMINAL_STATUSES]), lt(jobs.updatedAt, cutoff)))
    .run()
  return res.changes
}

// Start the periodic jobs pruner (default every 6h, plus once on boot). Returns
// null when retention is disabled (retentionDays <= 0).
export function startJobsPruner(retentionDays: number, intervalMs = 6 * 60 * 60 * 1000): NodeJS.Timeout | null {
  if (retentionDays <= 0) return null
  const olderThanMs = retentionDays * 24 * 60 * 60 * 1000
  const run = () => {
    try {
      pruneTerminalJobs(olderThanMs)
    } catch {
      /* best-effort */
    }
  }
  run()
  const timer = setInterval(run, intervalMs)
  timer.unref()
  return timer
}
