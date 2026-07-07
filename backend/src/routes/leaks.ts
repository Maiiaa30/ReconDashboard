import type { FastifyPluginAsync } from 'fastify'
import { config } from '../config'
import { getDomain } from '../domains/store'
import { listFindings } from '../findings/store'
import { enqueueJob, hasPendingJob, lastJobAt } from '../jobs/queue'

// Domain breach/leak exposure. Passive (queries a configured third-party breach
// API keyed on the domain — never touches the target), so it's allowed on any
// domain mode. Active domains also get an automatic daily check (scheduler);
// passive domains are manual via the button here.
export const leakRoutes: FastifyPluginAsync = async (app) => {
  // Manual trigger.
  app.post<{ Params: { id: string } }>('/api/domains/:id/leaks/check', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    if (!config.leaks.enabled) {
      return reply.code(400).send({ error: 'leak provider not configured — set LEAK_PROVIDER + LEAK_API_KEY in .env' })
    }
    if (hasPendingJob('leak_check', id)) {
      return reply.code(409).send({ error: 'a leak check for this domain is already queued or running' })
    }
    return reply.code(202).send({ jobId: enqueueJob('leak_check', { domainId: id }) })
  })

  // Current leak findings + status for the domain.
  app.get<{ Params: { id: string } }>('/api/domains/:id/leaks', async (request, reply) => {
    const id = Number(request.params.id)
    const domain = getDomain(id)
    if (!domain) return reply.code(404).send({ error: 'domain not found' })
    const findings = listFindings({ domainId: id, type: 'leak', limit: 2000 })
    return {
      enabled: config.leaks.enabled,
      provider: config.leaks.enabled ? config.leaks.provider : null,
      autoDaily: domain.mode === 'active_authorized',
      pending: hasPendingJob('leak_check', id),
      lastCheckedAt: lastJobAt('leak_check', id),
      findings,
    }
  })
}
