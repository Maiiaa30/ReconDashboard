import type { FastifyBaseLogger } from 'fastify'
import type { Job } from '../db/schema'
import { claimNextQueued, failJob, finishJob, isLoudJob, markJobCancelled, requeueStaleRunning, setJobProgress } from './queue'
import type { JobType } from './queue'
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

// Hard wall-clock cap per job so a hung external call (whois, fetch, a scan that
// never returns) can't wedge the single worker forever.
const JOB_TIMEOUT_MS = 20 * 60 * 1000

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

let running = false
let timer: NodeJS.Timeout | null = null

async function tick(log: FastifyBaseLogger): Promise<void> {
  if (running) return
  running = true
  try {
    // Drain all currently-queued jobs one at a time (sequential worker).
    for (;;) {
      const job = claimNextQueued()
      if (!job) break

      const handler = handlers.get(job.type as JobType)
      if (!handler) {
        failJob(job.id, `no handler for job type "${job.type}"`)
        continue
      }

      let params: Record<string, unknown> = {}
      try {
        params = job.params ? (JSON.parse(job.params) as Record<string, unknown>) : {}
      } catch {
        failJob(job.id, 'invalid job params JSON')
        continue
      }

      log.info({ jobId: job.id, type: job.type }, 'job started')
      const loud = isLoudJob(job.type)
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
  } finally {
    running = false
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
  const { requeued, dead } = requeueStaleRunning()
  if (requeued > 0) log.warn(`requeued ${requeued} stale running job(s) from a previous run`)
  if (dead > 0) log.warn(`dead-lettered ${dead} stale running job(s) (loud/exhausted — not auto-resumed)`)

  timer = setInterval(() => {
    void tick(log)
  }, intervalMs)
  timer.unref()
  log.info('job worker started')
}

export function stopWorker(): void {
  if (timer) clearInterval(timer)
  timer = null
}
