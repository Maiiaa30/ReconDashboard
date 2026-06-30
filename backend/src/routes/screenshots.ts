import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import type { FastifyPluginAsync } from 'fastify'
import { getDomain } from '../domains/store'
import { enqueueJob } from '../jobs/queue'
import { screenshotPathFor } from '../util/screenshotPaths'
import { listSubdomains } from '../subdomains/store'
import { hostBelongsToDomain, normalizeHost } from '../util/validate'

export const screenshotRoutes: FastifyPluginAsync = async (app) => {
  // Enqueue a screenshot job for the domain's live web hosts.
  app.post<{ Params: { id: string } }>('/api/domains/:id/screenshots', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    return reply.code(202).send({ jobId: enqueueJob('screenshot', { domainId: id }) })
  })

  // List which hosts have screenshots (for the gallery).
  app.get<{ Params: { id: string } }>('/api/domains/:id/screenshots', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    const shots = listSubdomains(id)
      .filter((s) => s.screenshotPath)
      .map((s) => ({
        host: s.host,
        status: s.httpStatus,
        title: s.title,
        scheme: s.scheme,
        capturedAt: s.screenshotAt,
      }))
    return { screenshots: shots }
  })

  // Serve a screenshot PNG. The path is derived from the validated host, so a
  // request can only ever reference a file inside the domain's screenshot dir.
  app.get<{ Params: { id: string }; Querystring: { host?: string } }>(
    '/api/domains/:id/screenshot',
    async (request, reply) => {
      const id = Number(request.params.id)
      const domain = getDomain(id)
      if (!domain) return reply.code(404).send({ error: 'domain not found' })

      const rawHost = request.query.host
      if (typeof rawHost !== 'string') return reply.code(400).send({ error: 'invalid host' })
      const host = normalizeHost(rawHost)
      if (!host || (!hostBelongsToDomain(host, domain.host) && host !== domain.host)) {
        return reply.code(400).send({ error: 'invalid host' })
      }

      const path = screenshotPathFor(id, host)
      try {
        await stat(path)
      } catch {
        return reply.code(404).send({ error: 'no screenshot for this host' })
      }
      return reply
        .header('Content-Type', 'image/png')
        .header('Cache-Control', 'private, max-age=300')
        .send(createReadStream(path))
    },
  )
}
