import type { FastifyPluginAsync } from 'fastify'
import { whoisLookup } from '../sources/whois'
import { checkHost, CheckHostError } from '../sources/reachability'

// Ad-hoc lookup tools, not scoped to a tracked domain: WHOIS for any
// domain/IP, and a "check host" reachability probe (ping + TCP + HTTP).
// Both run synchronously (they finish in seconds) and are rate-limited so a
// loop can't hammer external services / spawn ping processes unbounded.
const RATE_LIMIT = { max: 30, timeWindow: '1 minute' }

const whoisSchema = {
  body: {
    type: 'object',
    required: ['query'],
    properties: { query: { type: 'string', minLength: 1, maxLength: 253 } },
  },
}

const checkHostSchema = {
  body: {
    type: 'object',
    required: ['host'],
    properties: {
      host: { type: 'string', minLength: 1, maxLength: 253 },
      ports: { type: 'array', items: { type: 'integer', minimum: 1, maximum: 65535 }, maxItems: 20 },
    },
  },
}

export const toolRoutes: FastifyPluginAsync = async (app) => {
  app.post<{ Body: { query: string } }>(
    '/api/tools/whois',
    { schema: whoisSchema, config: { rateLimit: RATE_LIMIT } },
    async (request, reply) => {
      try {
        return { result: await whoisLookup(request.body.query) }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'whois lookup failed'
        const code = /^invalid /.test(message) ? 400 : 502
        return reply.code(code).send({ error: message })
      }
    },
  )

  app.post<{ Body: { host: string; ports?: number[] } }>(
    '/api/tools/check-host',
    { schema: checkHostSchema, config: { rateLimit: RATE_LIMIT } },
    async (request, reply) => {
      try {
        return { result: await checkHost(request.body.host, request.body.ports) }
      } catch (err) {
        if (err instanceof CheckHostError) return reply.code(400).send({ error: err.message })
        const message = err instanceof Error ? err.message : 'host check failed'
        return reply.code(502).send({ error: message })
      }
    },
  )
}
