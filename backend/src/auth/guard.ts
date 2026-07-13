import type { FastifyReply, FastifyRequest } from 'fastify'

// Routes reachable without an authenticated session. POST /api/capture is the
// browser-extension ingest: it can't carry the sameSite=strict session cookie
// (different origin), so it self-authenticates with the CAPTURE_TOKEN shared
// secret inside the handler (and 503s if no token is configured). It is NOT an
// open endpoint — the token check is the auth.
const PUBLIC = new Set(['GET /api/health', 'POST /api/auth/login', 'POST /api/capture'])

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
