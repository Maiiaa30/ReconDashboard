import type { FastifyPluginAsync } from 'fastify'
import { getJob, listJobs } from '../jobs/queue'
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
}
