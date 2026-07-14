import type { FastifyBaseLogger } from 'fastify'
import type { Job } from '../db/schema'
import {
  JOB_TIMEOUT_MS,
  claimNextQueued,
  failJob,
  finishJob,
  isLoudJob,
  markJobCancelled,
  reapTimedOutRunning,
  requeueStaleRunning,
  setJobProgress,
} from './queue'
import type { JobLane, JobType } from './queue'
import { writeAudit } from '../audit/store'
import { chainAfter } from './chains'

export interface JobContext {
  job: Job
  params: Record<string, unknown>
  log: FastifyBaseLogger
  // Write a coarse progress line (persisted, bumps updatedAt).
  progress: (message: string) => void
  // Aborted when the job times out or the operator cancels it; handlers pass
  // this into util/exec.run and fetch so the underlying work is actually killed.
  signal: AbortSignal
}

export type JobHandler = (ctx: JobContext) => Promise<unknown>

const handlers = new Map<JobType, JobHandler>()

// AbortControllers for jobs currently running, so a timeout or an operator
// cancel can abort the in-flight subprocess/fetch. Single sequential worker, so
// there is at most one — but keyed by id to stay correct if that ever changes.
const controllers = new Map<number, AbortController>()
const cancelRequested = new Set<number>()

export function registerHandler(type: JobType, handler: JobHandler): void {
  handlers.set(type, handler)
}

// Abort a running job. Returns false if it isn't currently running here.
export function cancelRunningJob(id: number): boolean {
  const c = controllers.get(id)
  if (!c) return false
  cancelRequested.add(id)
  c.abort()
  return true
}

function withTimeout<T>(p: Promise<T>, ms: number, onTimeout: () => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout()
      reject(new Error(`job timed out after ${ms}ms`))
    }, ms)
    timer.unref()
    p.then(
      (v) => {
        clearTimeout(timer)
        resolve(v)
      },
      (e) => {
        clearTimeout(timer)
        reject(e)
      },
    )
  })
}

let timer: NodeJS.Timeout | null = null

// Two independent lanes so a long LOUD scan (nmap/naabu/katana can run for
// minutes) doesn't block passive monitoring behind it. Each lane drains its own
// jobs sequentially — loud scans still never run two-at-a-time against a target
// — but the passive and loud lanes run concurrently (≤2 jobs at once).
const laneRunning: Record<JobLane, boolean> = { passive: false, loud: false }

// Execute one already-claimed (running) job to completion.
async function runClaimedJob(job: Job, log: FastifyBaseLogger): Promise<void> {
  const handler = handlers.get(job.type as JobType)
  if (!handler) {
    failJob(job.id, `no handler for job type "${job.type}"`)
    return
  }

  let params: Record<string, unknown> = {}
  try {
    params = job.params ? (JSON.parse(job.params) as Record<string, unknown>) : {}
  } catch {
    failJob(job.id, 'invalid job params JSON')
    return
  }

  const loud = isLoudJob(job.type)

  // Durable cancel: the operator asked to cancel this before it started running
  // here (e.g. requested while queued, or persisted across a restart) — don't run
  // it. Guarded markJobCancelled flips running→cancelled.
  if (job.cancelRequested) {
    markJobCancelled(job.id)
    log.warn({ jobId: job.id, type: job.type }, 'job cancelled before start (persisted request)')
    if (loud) auditJob('job:cancelled', job, params, { type: job.type })
    return
  }

  log.info({ jobId: job.id, type: job.type }, 'job started')
  if (loud) {
    writeAudit({
      actor: 'worker',
      action: 'job:start',
      domainId: job.domainId ?? undefined,
      target: typeof params.target === 'string' ? params.target : undefined,
      jobId: job.id,
      detail: { type: job.type, attempt: job.attempts },
    })
  }
  const controller = new AbortController()
  controllers.set(job.id, controller)
  const ctx: JobContext = {
    job,
    params,
    log,
    signal: controller.signal,
    progress: (m) => setJobProgress(job.id, m),
  }
  try {
    const result = await withTimeout(handler(ctx), JOB_TIMEOUT_MS, () => controller.abort())
    if (cancelRequested.has(job.id)) {
      markJobCancelled(job.id)
      log.warn({ jobId: job.id, type: job.type }, 'job cancelled')
    } else {
      finishJob(job.id, result)
      log.info({ jobId: job.id, type: job.type }, 'job done')
      if (loud) auditJob('job:done', job, params, { type: job.type })
      chainAfter(job, result, log)
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    if (cancelRequested.has(job.id)) {
      markJobCancelled(job.id)
      log.warn({ jobId: job.id, type: job.type }, 'job cancelled')
      if (loud) auditJob('job:cancelled', job, params, { type: job.type })
    } else {
      failJob(job.id, message)
      log.error({ jobId: job.id, type: job.type, err: message }, 'job failed')
      if (loud) auditJob('job:error', job, params, { type: job.type, error: message.slice(0, 500) })
    }
  } finally {
    controllers.delete(job.id)
    cancelRequested.delete(job.id)
  }
}

// Drain one lane's queued jobs sequentially. Guarded so a slow job doesn't stack
// overlapping drains of the same lane.
async function tickLane(lane: JobLane, log: FastifyBaseLogger): Promise<void> {
  if (laneRunning[lane]) return
  laneRunning[lane] = true
  try {
    for (;;) {
      const job = claimNextQueued(lane)
      if (!job) break
      await runClaimedJob(job, log)
    }
  } finally {
    laneRunning[lane] = false
  }
}

function auditJob(action: string, job: Job, params: Record<string, unknown>, detail: unknown): void {
  writeAudit({
    actor: 'worker',
    action,
    domainId: job.domainId ?? undefined,
    target: typeof params.target === 'string' ? params.target : undefined,
    jobId: job.id,
    detail,
  })
}

export function startWorker(log: FastifyBaseLogger, intervalMs = 2_000): void {
  const { requeued, dead, cancelled } = requeueStaleRunning()
  if (requeued > 0) log.warn(`requeued ${requeued} stale running job(s) from a previous run`)
  if (dead > 0) log.warn(`dead-lettered ${dead} stale running job(s) (loud/exhausted — not auto-resumed)`)
  if (cancelled > 0) log.warn(`cancelled ${cancelled} stale running job(s) with a pending cancel request`)

  timer = setInterval(() => {
    // Reap any job stuck 'running' past the wall-clock deadline (its in-process
    // timer died with a previous worker) — durable backstop for the in-memory
    // withTimeout. Cheap: 'running' rows are few and indexed.
    const r = reapTimedOutRunning()
    if (r.dead || r.requeued || r.cancelled) {
      log.warn(`reaper: ${r.dead} dead, ${r.requeued} requeued, ${r.cancelled} cancelled (past deadline)`)
    }
    // Both lanes poll every tick; each is independently guarded, so they run
    // concurrently but never overlap themselves.
    void tickLane('passive', log)
    void tickLane('loud', log)
  }, intervalMs)
  timer.unref()
  log.info('job worker started (passive + loud lanes)')
}

export function stopWorker(): void {
  if (timer) clearInterval(timer)
  timer = null
}
