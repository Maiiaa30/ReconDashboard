import type { FastifyPluginAsync } from 'fastify'
import { cancelJob, getJob, listJobs, markCancelRequested } from '../jobs/queue'
import { cancelRunningJob } from '../jobs/worker'
import { safeJsonParse } from '../util/json'

function parseJob(job: ReturnType<typeof getJob>) {
  if (!job) return job
  return {
    ...job,
    params: safeJsonParse<unknown>(job.params, null),
    result: safeJsonParse<unknown>(job.result, null),
  }
}

export const jobRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/jobs', async () => ({ jobs: listJobs().map(parseJob) }))

  app.get<{ Params: { id: string } }>('/api/jobs/:id', async (request, reply) => {
    const job = getJob(Number(request.params.id))
    if (!job) return reply.code(404).send({ error: 'job not found' })
    return { job: parseJob(job) }
  })

  // Cancel a job. A queued job is dropped from the queue; a running job is
  // aborted (its AbortSignal fires, killing the subprocess/fetch that observe
  // it) and marked cancelled by the worker.
  app.post<{ Params: { id: string } }>('/api/jobs/:id/cancel', async (request, reply) => {
    const id = Number(request.params.id)
    const job = getJob(id)
    if (!job) return reply.code(404).send({ error: 'job not found' })
    // Still queued → drop it atomically (guarded by status='queued').
    if (cancelJob(id)) return { job: parseJob(getJob(id)) }
    // Otherwise it's running (or was just claimed out of the queue): persist a
    // durable cancel request (so a restart before it stops still cancels it, not
    // re-runs it) and abort the in-flight work in this process.
    const persisted = markCancelRequested(id)
    const aborted = cancelRunningJob(id)
    if (!persisted && !aborted) {
      return reply.code(409).send({ error: `job is ${getJob(id)?.status ?? 'gone'} — nothing to cancel` })
    }
    return { requested: true, job: parseJob(getJob(id)) }
  })
}
