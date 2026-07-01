import type { FastifyPluginAsync } from 'fastify'
import { cancelJob, getJob, listJobs } from '../jobs/queue'
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
    if (job.status === 'queued') {
      if (!cancelJob(id)) {
        // Lost the race — the worker just claimed it. Fall through to abort it.
        if (!cancelRunningJob(id)) return reply.code(409).send({ error: 'job already started — too late to cancel' })
      }
      return { job: parseJob(getJob(id)) }
    }
    if (job.status === 'running') {
      if (!cancelRunningJob(id)) {
        return reply.code(409).send({ error: 'job is no longer running' })
      }
      return { requested: true, job: parseJob(getJob(id)) }
    }
    return reply.code(409).send({ error: `job is ${job.status} — nothing to cancel` })
  })
}
