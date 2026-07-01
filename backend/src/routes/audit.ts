import type { FastifyPluginAsync } from 'fastify'
import { listAudit } from '../audit/store'

// Read-only view of the append-only audit ledger. There is deliberately NO
// write/delete endpoint — the ledger is only appended by the server itself.
export const auditRoutes: FastifyPluginAsync = async (app) => {
  app.get<{ Querystring: { domainId?: string; limit?: string; before?: string } }>(
    '/api/audit',
    async (request) => {
      const domainId = request.query.domainId ? Number(request.query.domainId) : undefined
      const limit = request.query.limit ? Number(request.query.limit) : undefined
      const before = request.query.before ? Number(request.query.before) : undefined
      return { entries: listAudit({ domainId, limit, before }) }
    },
  )
}
