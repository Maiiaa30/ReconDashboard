import type { FastifyReply, FastifyRequest } from 'fastify'
import { config } from '../config'

// State-changing methods a CSRF attacker could try to trigger with the operator's
// session cookie. Safe methods (GET/HEAD/OPTIONS) are never guarded.
const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

// Token-authed, deliberately cross-origin endpoints: the browser-capture
// extension POSTs here from whatever site the operator is browsing, carrying the
// CAPTURE_TOKEN instead of a session — so the Origin check must not apply.
const ORIGIN_EXEMPT = new Set(['/api/capture'])

/**
 * Defense-in-depth CSRF guard. The session cookie is already SameSite=strict, so
 * a cross-site request can't carry it; this adds an explicit Origin allowlist for
 * same-origin production serving. A no-op when `trustedOrigins` is empty (dev, or
 * before same-origin serving is configured) or when the request carries no Origin
 * header (same-origin navigations and non-browser clients).
 *
 * Exported as a hook factory so it can be unit-tested directly.
 */
export function originGuard(req: FastifyRequest, reply: FastifyReply, done: (err?: Error) => void): void {
  if (config.trustedOrigins.length === 0) return done()
  if (!MUTATING.has(req.method)) return done()
  const path = req.url.split('?')[0]
  if (ORIGIN_EXEMPT.has(path)) return done()

  const origin = req.headers.origin
  // No Origin header → same-origin navigation or a non-browser client; allow.
  if (!origin) return done()

  const normalized = origin.replace(/\/$/, '')
  if (config.trustedOrigins.includes(normalized)) return done()

  reply.code(403).send({ error: 'cross-origin request refused', code: 'bad_origin' })
}
