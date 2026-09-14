import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { ZodTypeAny } from 'zod'
import { config } from '../config'
import { responseContracts } from './contracts'

// Raised when a route's 2xx payload fails its registered response contract.
// In dev/test this propagates so the failure is loud (a 500 in the response and
// a failing assertion in CI). In production it is caught and logged instead —
// a contract quirk must never take a running deployment down.
export class ResponseContractError extends Error {
  constructor(
    public route: string,
    public issues: string,
  ) {
    super(`Response contract mismatch for ${route}: ${issues}`)
    this.name = 'ResponseContractError'
  }
}

function formatIssues(schema: ZodTypeAny, payload: unknown): string | null {
  const result = schema.safeParse(payload)
  if (result.success) return null
  return result.error.issues
    .slice(0, 5)
    .map((i) => `${i.path.join('.') || '<root>'}: ${i.message}`)
    .join('; ')
}

// preSerialization runs after the handler returns and before the payload is
// JSON-serialized, so `payload` is the plain object the route produced. We only
// validate:
//   - 2xx responses (an error envelope is a different, intentional shape),
//   - routes present in the `responseContracts` registry (opt-in),
//   - object payloads (a route serving a Buffer/stream is skipped).
export function registerResponseValidation(app: FastifyInstance): void {
  app.addHook(
    'preSerialization',
    async (request: FastifyRequest, reply: FastifyReply, payload: unknown) => {
      if (reply.statusCode < 200 || reply.statusCode >= 300) return payload
      const routeUrl = request.routeOptions?.url
      if (!routeUrl) return payload
      const schema = responseContracts[`${request.method} ${routeUrl}`]
      if (!schema) return payload
      if (payload == null || typeof payload !== 'object') return payload

      const issues = formatIssues(schema, payload)
      if (!issues) return payload

      const route = `${request.method} ${routeUrl}`
      if (config.isProd) {
        // Don't break a live response over a contract drift — log it so it is
        // visible in the Readiness/logs surface and fix it forward.
        request.log.error({ route, issues }, 'response contract mismatch (served anyway in production)')
        return payload
      }
      throw new ResponseContractError(route, issues)
    },
  )
}
