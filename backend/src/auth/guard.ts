import type { FastifyReply, FastifyRequest } from 'fastify'

// Routes reachable without an authenticated session.
const PUBLIC = new Set(['GET /api/health', 'POST /api/auth/login'])

// onRequest guard: DEFAULT-DENY. Every request requires a logged-in session
// unless its METHOD + path is on the explicit public allowlist — this does not
// rely on a path-prefix convention, so a future route can't accidentally bypass
// auth. Must be registered AFTER @fastify/session so the session is loaded.
export async function authGuard(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const path = request.url.split('?')[0]
  if (PUBLIC.has(`${request.method} ${path}`)) return
  if (!request.session?.userId) {
    reply.code(401).send({ error: 'unauthorized' })
  }
}
