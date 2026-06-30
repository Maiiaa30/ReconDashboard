import type { FastifyPluginAsync } from 'fastify'
import { getDomain } from '../domains/store'
import { enqueueJob } from '../jobs/queue'

// Passive recon triggers: exposure (InternetDB/cvedb) and OSINT aggregation.
// Both are safe on any domain regardless of mode.
export const reconRoutes: FastifyPluginAsync = async (app) => {
  app.post<{ Params: { id: string } }>('/api/domains/:id/exposure', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    return reply.code(202).send({ jobId: enqueueJob('exposure_scan', { domainId: id }) })
  })

  app.post<{ Params: { id: string } }>('/api/domains/:id/osint', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    return reply.code(202).send({ jobId: enqueueJob('osint_gather', { domainId: id }) })
  })
}
