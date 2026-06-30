import type { FastifyPluginAsync } from 'fastify'
import {
  createDomain,
  deleteDomain,
  DomainValidationError,
  getDomain,
  listDomains,
  updateDomain,
  type DomainMode,
} from '../domains/store'
import { enqueueJob } from '../jobs/queue'
import { acknowledgeNew, listSubdomains } from '../subdomains/store'
import { domainOverviews } from '../domains/overview'

export const domainRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/domains', async () => ({
    domains: listDomains().map((d) => ({
      ...d,
      profile: d.profile ? JSON.parse(d.profile) : {},
    })),
  }))

  // At-a-glance per-domain stats for the dashboard cards.
  app.get('/api/domains/overview', async () => ({ overview: domainOverviews() }))

  app.post<{ Body: { host?: string; label?: string; mode?: DomainMode } }>(
    '/api/domains',
    {
      schema: {
        body: {
          type: 'object',
          required: ['host'],
          properties: {
            host: { type: 'string', minLength: 1, maxLength: 253 },
            label: { type: 'string', maxLength: 200 },
            mode: { type: 'string', enum: ['passive_only', 'active_authorized'] },
          },
        },
      },
    },
    async (request, reply) => {
      try {
        const domain = createDomain({
          host: request.body.host!,
          label: request.body.label,
          mode: request.body.mode,
        })
        return reply.code(201).send({ domain })
      } catch (err) {
        if (err instanceof DomainValidationError) return reply.code(400).send({ error: err.message })
        throw err
      }
    },
  )

  app.patch<{
    Params: { id: string }
    Body: { mode?: DomainMode; label?: string | null; profile?: Record<string, unknown> }
  }>(
    '/api/domains/:id',
    {
      schema: {
        body: {
          type: 'object',
          properties: {
            mode: { type: 'string', enum: ['passive_only', 'active_authorized'] },
            label: { type: ['string', 'null'], maxLength: 200 },
            profile: { type: 'object' },
          },
        },
      },
    },
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
      return { domain: updateDomain(id, request.body ?? {}) }
    },
  )

  app.delete<{ Params: { id: string } }>('/api/domains/:id', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    deleteDomain(id)
    return reply.send({ ok: true })
  })

  // --- Subdomains for a domain ----------------------------------------------
  app.get<{ Params: { id: string } }>('/api/domains/:id/subdomains', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    return { subdomains: listSubdomains(id) }
  })

  // Trigger passive subdomain discovery now.
  app.post<{ Params: { id: string } }>(
    '/api/domains/:id/discover',
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
      const jobId = enqueueJob('subdomain_discovery', { domainId: id })
      return reply.code(202).send({ jobId })
    },
  )

  // Acknowledge (clear the "new" flag on) a domain's subdomains.
  app.post<{ Params: { id: string } }>(
    '/api/domains/:id/subdomains/acknowledge',
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
      return { cleared: acknowledgeNew(id) }
    },
  )
}
