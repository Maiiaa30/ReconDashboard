import { timingSafeEqual } from 'node:crypto'
import type { FastifyPluginAsync } from 'fastify'
import { config } from '../config'
import { getDomain, listDomains } from '../domains/store'
import { hostBelongsToDomain } from '../util/validate'
import { insertCapture, listCaptures, getCapture, clearCaptures, deleteCapture } from '../capture/store'
import { actorName, writeAudit } from '../audit/store'

// Browser-extension capture ingest + read.
//
// POST /api/capture is on the auth guard's public allowlist because the
// extension (a different origin) can't present the sameSite=strict session
// cookie. It is NOT open: it requires the CAPTURE_TOKEN shared secret and is
// disabled entirely when no token is configured. The read/clear routes stay
// session-authed (normal dashboard use).
const INGEST_RATE = { max: 600, timeWindow: '1 minute' } // a busy browsing session bursts

// Liveness: the extension polls /api/capture/targets (and POSTs captures) while
// enabled, so the last time we saw a valid token is a good "extension is running"
// signal. In-memory is fine — a restart just re-learns it within a poll cycle.
let lastExtensionSeen = 0

// Constant-time token compare (avoids leaking the token via response timing).
function tokenMatches(provided: string, expected: string): boolean {
  if (!expected) return false
  const a = Buffer.from(provided)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

// Shared auth for the extension-facing routes. Returns an error tuple or null.
function checkCaptureAuth(headerToken: unknown): { code: number; error: string } | null {
  if (!config.captureToken) return { code: 503, error: 'capture is disabled (set CAPTURE_TOKEN to enable)' }
  if (!tokenMatches(String(headerToken ?? ''), config.captureToken)) return { code: 401, error: 'invalid capture token' }
  return null
}

// Match a captured host to a tracked domain (longest apex wins), so capture is
// scoped to targets the operator actually tracks — unknown hosts are refused.
function domainForHost(host: string): { id: number } | null {
  const h = host.toLowerCase()
  const matches = listDomains()
    .filter((d) => h === d.host.toLowerCase() || hostBelongsToDomain(h, d.host))
    .sort((a, b) => b.host.length - a.host.length)
  return matches[0] ?? null
}

const ingestSchema = {
  body: {
    type: 'object',
    required: ['url'],
    properties: {
      url: { type: 'string', minLength: 1, maxLength: 4096 },
      method: { type: 'string', maxLength: 10 },
      headers: {
        type: 'array',
        maxItems: 100,
        items: { type: 'array', minItems: 2, maxItems: 2, items: { type: 'string' } },
      },
      body: { type: ['string', 'null'], maxLength: 512 * 1024 },
      domainId: { type: 'integer' },
    },
  },
}

export const captureRoutes: FastifyPluginAsync = async (app) => {
  app.post<{
    Body: { url: string; method?: string; headers?: [string, string][]; body?: string | null; domainId?: number }
  }>('/api/capture', { schema: ingestSchema, config: { rateLimit: INGEST_RATE } }, async (request, reply) => {
    const authErr = checkCaptureAuth(request.headers['x-capture-token'])
    if (authErr) return reply.code(authErr.code).send({ error: authErr.error })
    lastExtensionSeen = Date.now()

    const b = request.body
    let host: string
    try {
      host = new URL(b.url).hostname
    } catch {
      return reply.code(400).send({ error: 'invalid url' })
    }

    // Scope: only store traffic for a tracked domain. Prefer the caller's
    // domainId (validated to actually own the host), else auto-match the host.
    let domainId: number | null = null
    if (b.domainId != null) {
      const d = getDomain(b.domainId)
      if (d && (host.toLowerCase() === d.host.toLowerCase() || hostBelongsToDomain(host, d.host))) domainId = d.id
    }
    if (domainId == null) domainId = domainForHost(host)?.id ?? null
    if (domainId == null) {
      // Not an error the extension should retry — just tell it we skipped.
      return reply.code(202).send({ stored: false, reason: 'host not in any tracked domain' })
    }

    const id = insertCapture({
      domainId,
      method: b.method ?? 'GET',
      url: b.url,
      host,
      headers: Array.isArray(b.headers) ? b.headers : [],
      body: b.body ?? null,
    })
    return reply.code(202).send({ stored: true, id })
  })

  // The extension polls this (token-authed) to learn which hosts to capture, so
  // it only ships tracked-domain traffic and leaves everything else private.
  app.get('/api/capture/targets', async (request, reply) => {
    const authErr = checkCaptureAuth(request.headers['x-capture-token'])
    if (authErr) return reply.code(authErr.code).send({ error: authErr.error })
    lastExtensionSeen = Date.now()
    return { hosts: listDomains().map((d) => d.host) }
  })

  // Dashboard-side status (session-authed): is capture enabled on the server, and
  // when did we last hear from the extension? Powers the Traffic "not detected" hint.
  app.get('/api/capture/status', async () => ({
    enabled: !!config.captureToken,
    extensionSeenAt: lastExtensionSeen || null,
  }))

  // List captured requests for a domain (dashboard read — session-authed).
  app.get<{ Querystring: { domainId?: string; limit?: string } }>('/api/capture', async (request) => {
    const domainId = request.query.domainId != null && Number.isFinite(Number(request.query.domainId)) ? Number(request.query.domainId) : undefined
    const limit = request.query.limit != null && Number.isFinite(Number(request.query.limit)) ? Number(request.query.limit) : undefined
    return { captures: listCaptures({ domainId, limit }) }
  })

  // Full single capture incl. its body (the list omits bodies for speed).
  app.get<{ Params: { id: string } }>('/api/capture/:id', async (request, reply) => {
    const c = getCapture(Number(request.params.id))
    if (!c) return reply.code(404).send({ error: 'capture not found' })
    return { capture: c }
  })

  // Delete a single captured request.
  app.delete<{ Params: { id: string } }>('/api/capture/:id', async (request, reply) => {
    const id = Number(request.params.id)
    if (!Number.isFinite(id)) return reply.code(400).send({ error: 'invalid id' })
    const deleted = deleteCapture(id)
    if (!deleted) return reply.code(404).send({ error: 'capture not found' })
    return { deleted }
  })

  // Clear a domain's captured history.
  app.delete<{ Querystring: { domainId?: string } }>('/api/capture', async (request, reply) => {
    const domainId = Number(request.query.domainId)
    if (!Number.isFinite(domainId)) return reply.code(400).send({ error: 'domainId required' })
    const cleared = clearCaptures(domainId)
    writeAudit({ actor: actorName(request.session.userId), action: 'capture:clear', domainId, detail: { cleared } })
    return { cleared }
  })
}
