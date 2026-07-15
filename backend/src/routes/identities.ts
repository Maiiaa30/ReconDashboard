import type { FastifyPluginAsync } from 'fastify'
import { getDomain } from '../domains/store'
import { deleteIdentity, getIdentity, listIdentities, upsertIdentity } from '../identities/store'

// Named identities: session-authed CRUD, per domain. NOT scan-gated — defining an
// identity sends nothing. The credentials are only ever put on the wire by the
// Repeater/Intruder/authz_diff senders, which stay behind the scan gate + SSRF
// guard. Audit of the ACTUAL sends redacts values (logs the identity name only).
export const identityRoutes: FastifyPluginAsync = async (app) => {
  app.get<{ Querystring: { domainId?: string } }>('/api/identities', async (request, reply) => {
    const domainId = Number(request.query.domainId)
    if (!Number.isFinite(domainId)) return reply.code(400).send({ error: 'domainId required' })
    return { identities: listIdentities(domainId) }
  })

  app.post<{ Body: { domainId?: number; name?: string; headers?: Record<string, string>; isAnon?: boolean } }>(
    '/api/identities',
    async (request, reply) => {
      const b = request.body ?? {}
      const domainId = Number(b.domainId)
      if (!Number.isFinite(domainId) || !getDomain(domainId)) return reply.code(400).send({ error: 'valid domainId required' })
      const name = typeof b.name === 'string' ? b.name.trim() : ''
      if (!name) return reply.code(400).send({ error: 'name required' })
      const identity = upsertIdentity({ domainId, name, headers: b.headers, isAnon: b.isAnon })
      return { identity }
    },
  )

  app.delete<{ Params: { id: string } }>('/api/identities/:id', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getIdentity(id)) return reply.code(404).send({ error: 'identity not found' })
    deleteIdentity(id)
    return { ok: true }
  })
}
