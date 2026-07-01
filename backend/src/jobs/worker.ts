import type { FastifyBaseLogger } from 'fastify'
import type { Job } from '../db/schema'
import { claimNextQueued, failJob, finishJob, isLoudJob, requeueStaleRunning } from './queue'
import type { JobType } from './queue'
import { writeAudit } from '../audit/store'

export interface JobContext {
  job: Job
  params: Record<string, unknown>
  log: FastifyBaseLogger
}

export type JobHandler = (ctx: JobContext) => Promise<unknown>

const handlers = new Map<JobType, JobHandler>()

// Hard wall-clock cap per job so a hung external call (whois, fetch, a scan that
// never returns) can't wedge the single worker forever.
const JOB_TIMEOUT_MS = 20 * 60 * 1000

export function registerHandler(type: JobType, handler: JobHandler): void {
  handlers.set(type, handler)
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`job timed out after ${ms}ms`)), ms)
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
      try {
        const result = await withTimeout(handler({ job, params, log }), JOB_TIMEOUT_MS)
        finishJob(job.id, result)
        log.info({ jobId: job.id, type: job.type }, 'job done')
        if (loud) {
          writeAudit({
            actor: 'worker',
            action: 'job:done',
            domainId: job.domainId ?? undefined,
            target: typeof params.target === 'string' ? params.target : undefined,
            jobId: job.id,
            detail: { type: job.type },
          })
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        failJob(job.id, message)
        log.error({ jobId: job.id, type: job.type, err: message }, 'job failed')
        if (loud) {
          writeAudit({
            actor: 'worker',
            action: 'job:error',
            domainId: job.domainId ?? undefined,
            target: typeof params.target === 'string' ? params.target : undefined,
            jobId: job.id,
            detail: { type: job.type, error: message.slice(0, 500) },
          })
        }
      }
    }
  } finally {
    running = false
  }
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
