import type { FastifyPluginAsync } from 'fastify'
import { getDomain } from '../domains/store'
import { enqueueJob } from '../jobs/queue'
import { hostBelongsToDomain, normalizeHost } from '../util/validate'

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

  // Origin-server discovery behind a CDN/WAF (authorized target only).
  app.post<{ Params: { id: string } }>('/api/domains/:id/origin', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    return reply.code(202).send({ jobId: enqueueJob('origin_scan', { domainId: id }) })
  })

  // Passive code-leak search: look for the domain (+ optional seeds) in public
  // code (GitHub). Queries GitHub, not the target — safe on any domain.
  app.post<{ Params: { id: string }; Body: { seeds?: string[] } }>('/api/domains/:id/code-leaks', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    const seeds = Array.isArray(request.body?.seeds) ? request.body.seeds.filter((s) => typeof s === 'string').slice(0, 5) : []
    return reply.code(202).send({ jobId: enqueueJob('code_leak', { domainId: id, seeds }) })
  })

  // Passive API-surface discovery: OpenAPI/Swagger specs + GraphQL endpoints.
  // Optional `host` restricts the scan to one apex/subdomain (must belong to the
  // domain); omitted = the apex + all live subdomains (the default sweep).
  app.post<{ Params: { id: string }; Body: { host?: string } }>('/api/domains/:id/api-discovery', async (request, reply) => {
    const id = Number(request.params.id)
    const domain = getDomain(id)
    if (!domain) return reply.code(404).send({ error: 'domain not found' })

    let host: string | undefined
    const raw = request.body?.host
    if (typeof raw === 'string' && raw.trim()) {
      const norm = normalizeHost(raw)
      if (!norm || (norm !== domain.host && !hostBelongsToDomain(norm, domain.host))) {
        return reply.code(400).send({ error: 'host is not part of this domain' })
      }
      host = norm
    }
    return reply.code(202).send({ jobId: enqueueJob('api_discovery', { domainId: id, ...(host ? { host } : {}) }) })
  })
}
