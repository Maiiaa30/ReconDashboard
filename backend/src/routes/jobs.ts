import type { FastifyPluginAsync } from 'fastify'
import { cancelJob, getJob, listJobs } from '../jobs/queue'
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

  // Cancel a still-queued job. Running/finished jobs can't be cancelled (the
  // worker has no mid-run abort), so this only affects the queue.
  app.post<{ Params: { id: string } }>('/api/jobs/:id/cancel', async (request, reply) => {
    const id = Number(request.params.id)
    const job = getJob(id)
    if (!job) return reply.code(404).send({ error: 'job not found' })
    if (job.status !== 'queued') {
      return reply.code(409).send({ error: `job is ${job.status} — only queued jobs can be cancelled` })
    }
    if (!cancelJob(id)) {
      return reply.code(409).send({ error: 'job already started — too late to cancel' })
    }
    return { job: parseJob(getJob(id)) }
  })
}
