import type { FastifyPluginAsync } from 'fastify'
import { config } from '../config'
import { getDomain } from '../domains/store'
import { addFinding, listFindings } from '../findings/store'
import { enqueueJob, hasPendingJob, lastJobAt } from '../jobs/queue'
import { checkEmailLeaksFree } from '../sources/leaks'

// Loose email shape check — the free provider validates for real; this just
// rejects obvious junk before we spend a request.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const emailSchema = {
  body: {
    type: 'object',
    required: ['email'],
    properties: { email: { type: 'string', minLength: 3, maxLength: 254 } },
  },
}

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

  // Free, keyless per-email breach-metadata check (no provider config needed).
  // Synchronous + rate-limited like the ad-hoc tools. Stores one metadata
  // finding per breach source (no password — the free tier never returns one).
  app.post<{ Params: { id: string }; Body: { email: string } }>(
    '/api/domains/:id/leaks/email',
    { schema: emailSchema, config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
      const email = request.body.email.trim().toLowerCase()
      if (!EMAIL_RE.test(email)) return reply.code(400).send({ error: 'not a valid email address' })
      try {
        const result = await checkEmailLeaksFree(email)
        for (const s of result.sources) {
          addFinding({
            domainId: id,
            type: 'leak',
            data: {
              email,
              username: null,
              password: null,
              hashedPassword: null,
              name: null,
              phone: null,
              ip: null,
              source: s.name,
              breachDate: s.date,
              fields: result.fields,
              provider: result.provider,
              domain: getDomain(id)!.host,
            },
            score: 45, // metadata exposure, no credential
            tags: ['leak', 'provider:free', ...(s.name ? [`breach:${s.name}`] : [])],
          })
        }
        return { result }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'free lookup failed'
        const code = /rate-limited/.test(message) ? 429 : 502
        return reply.code(code).send({ error: message })
      }
    },
  )
}
