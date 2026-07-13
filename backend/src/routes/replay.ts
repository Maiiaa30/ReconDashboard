import { readFileSync } from 'node:fs'
import type { FastifyPluginAsync } from 'fastify'
import { getDomain } from '../domains/store'
import { assertDomainActive, assertHostInScope, assertScanAllowed, ScanPolicyError } from '../domains/scanPolicy'
import { sendRawRequest, ReplayError, type ReplayRequest } from '../replay/send'
import { expandPayloads, MAX_PAYLOADS, PAYLOAD_MARKER } from '../replay/intruder'
import { insertReplayHistory, listReplayHistory, getReplayHistory, clearReplayHistory } from '../replay/history'
import { enqueueJob } from '../jobs/queue'
import { SsrfBlockedError } from '../sources/guard'
import { actorName, writeAudit } from '../audit/store'

// Read payloads from an installed wordlist. Path is constrained to the wordlists
// dir with no traversal — same guard the ffuf handler uses — so this can't be
// turned into an arbitrary file read. Truncated to the payload cap (wordlists are
// legitimately large); the caller is told how many were used.
const WORDLIST_DIR = '/usr/share/wordlists/'
function wordlistPayloads(path: string): string[] {
  if (!/^\/[A-Za-z0-9._/-]+$/.test(path) || path.includes('..') || !path.startsWith(WORDLIST_DIR)) {
    throw new Error('wordlist must be an absolute path under /usr/share/wordlists/ with no ".."')
  }
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch {
    throw new Error('wordlist not found (wordlists ship in the Docker image, not the local dev backend)')
  }
  const items = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
  if (items.length === 0) throw new Error('wordlist is empty')
  return items.slice(0, MAX_PAYLOADS)
}

// Replay (Repeater): send one operator-composed request server-side and return
// the full response. Active — it sends real traffic to the target — so it's
// scoped to a tracked domain, gated (passive domains need confirm), and
// rate-limited so it can't be turned into an ad-hoc request cannon.
const RATE_LIMIT = { max: 60, timeWindow: '1 minute' }
const MAX_BODY = 1 * 1024 * 1024

const sendSchema = {
  body: {
    type: 'object',
    required: ['domainId', 'url'],
    properties: {
      domainId: { type: 'integer' },
      method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] },
      url: { type: 'string', minLength: 1, maxLength: 4096 },
      headers: { type: 'object', additionalProperties: { type: 'string' } },
      body: { type: 'string', maxLength: MAX_BODY },
      followRedirects: { type: 'boolean' },
      confirm: { type: 'boolean' },
    },
  },
}

export const replayRoutes: FastifyPluginAsync = async (app) => {
  app.post<{
    Body: {
      domainId: number
      method?: string
      url: string
      headers?: Record<string, string>
      body?: string
      followRedirects?: boolean
      confirm?: boolean
    }
  }>('/api/replay/send', { schema: sendSchema, config: { rateLimit: RATE_LIMIT } }, async (request, reply) => {
    const b = request.body
    const domain = getDomain(b.domainId)
    if (!domain) return reply.code(404).send({ error: 'domain not found', code: 'not_found' })

    let host: string
    try {
      host = new URL(b.url).hostname
    } catch {
      return reply.code(400).send({ error: 'invalid url', code: 'invalid_target' })
    }

    try {
      // Domain rails (mode/confirm + authorization window) and that the target
      // host is within the domain + engagement scope — same gate as active scans.
      assertDomainActive(domain, b.confirm === true)
      await assertHostInScope(domain, host)
    } catch (err) {
      if (err instanceof ScanPolicyError) {
        if (err.retryAfterSec) reply.header('Retry-After', String(err.retryAfterSec))
        return reply.code(err.status).send({ error: err.message, code: err.code })
      }
      throw err
    }

    const req: ReplayRequest = {
      method: b.method ?? 'GET',
      url: b.url,
      headers: b.headers,
      body: b.body,
      followRedirects: b.followRedirects === true,
    }

    writeAudit({
      actor: actorName(request.session.userId),
      action: 'replay:send',
      domainId: domain.id,
      target: host,
      mode: domain.mode,
      detail: { method: req.method, url: b.url },
    })

    try {
      const response = await sendRawRequest(req)
      // Record in the Repeater history (best-effort — never fail the send on it).
      try {
        insertReplayHistory({
          domainId: domain.id,
          method: req.method,
          url: req.url,
          reqHeaders: Object.entries(req.headers ?? {}),
          reqBody: req.body ?? null,
          status: response.status,
          statusText: response.statusText,
          timeMs: response.timeMs,
          respBytes: response.bodyBytes,
          respHeaders: response.headers,
          respBody: response.body,
        })
      } catch {
        /* history write is non-critical */
      }
      return { response }
    } catch (err) {
      if (err instanceof SsrfBlockedError) return reply.code(400).send({ error: err.message, code: 'out_of_scope' })
      if (err instanceof ReplayError) return reply.code(err.status).send({ error: err.message })
      const message = err instanceof Error ? err.message : 'replay failed'
      return reply.code(502).send({ error: message })
    }
  })

  // Intruder: iterate a payload set through a request template. Loud (many
  // requests) → a gated LOUD job, not a synchronous call. assertScanAllowed
  // enforces mode/confirm + authorization window + engagement scope + the
  // one-at-a-time pending guard; the run itself is sequential + throttled.
  app.post<{
    Params: { id: string }
    Body: {
      template?: { method?: string; url?: string; headers?: Record<string, string>; body?: string; followRedirects?: boolean }
      payload?: { mode?: 'list' | 'range' | 'wordlist'; list?: string; from?: number; to?: number; pad?: number; wordlist?: string }
      throttleMs?: number
      confirm?: boolean
    }
  }>('/api/domains/:id/intruder', async (request, reply) => {
    const id = Number(request.params.id)
    const { template, payload, throttleMs, confirm } = request.body ?? {}
    if (!template || typeof template.url !== 'string' || !template.url) {
      return reply.code(400).send({ error: 'template.url is required' })
    }
    // The marker must appear somewhere, or every request is identical.
    const marked = [template.url, template.body ?? '', ...Object.values(template.headers ?? {})].some((s) =>
      String(s).includes(PAYLOAD_MARKER),
    )
    if (!marked) return reply.code(400).send({ error: `no ${PAYLOAD_MARKER} marker in the request template` })

    let host: string
    try {
      host = new URL(template.url).hostname
    } catch {
      return reply.code(400).send({ error: 'invalid template.url', code: 'invalid_target' })
    }

    let payloads: string[]
    try {
      payloads =
        payload?.mode === 'wordlist'
          ? wordlistPayloads(String(payload?.wordlist ?? ''))
          : expandPayloads({
              mode: payload?.mode === 'range' ? 'range' : 'list',
              list: payload?.list,
              from: payload?.from,
              to: payload?.to,
              pad: payload?.pad,
            })
    } catch (err) {
      return reply.code(400).send({ error: err instanceof Error ? err.message : 'invalid payloads' })
    }

    try {
      const { domain } = await assertScanAllowed({
        domainId: id,
        target: host,
        confirm: confirm === true,
        jobType: 'intruder',
        cooldownMs: 0, // tuning payloads means re-running often; the pending guard already blocks overlap
      })
      const method = (template.method ?? 'GET').toUpperCase()
      const params = {
        domainId: id,
        target: host,
        template: { method, url: template.url, headers: template.headers, body: template.body, followRedirects: template.followRedirects === true },
        payloads,
        throttleMs: Number(throttleMs) || 0,
      }
      const jobId = enqueueJob('intruder', params)
      writeAudit({
        actor: actorName(request.session.userId),
        action: 'enqueue:intruder',
        domainId: id,
        target: host,
        mode: domain.mode,
        jobId,
        detail: { method, url: template.url, count: payloads.length },
      })
      return reply.code(202).send({ jobId, count: payloads.length })
    } catch (err) {
      if (err instanceof ScanPolicyError) {
        if (err.retryAfterSec) reply.header('Retry-After', String(err.retryAfterSec))
        return reply.code(err.status).send({ error: err.message, code: err.code })
      }
      throw err
    }
  })

  // Repeater history: list (lightweight — no response body), full entry (with
  // response body), and clear. Session-authed like the rest of the dashboard.
  app.get<{ Querystring: { domainId?: string; limit?: string } }>('/api/replay/history', async (request, reply) => {
    const domainId = Number(request.query.domainId)
    if (!Number.isFinite(domainId)) return reply.code(400).send({ error: 'domainId required' })
    const limit = request.query.limit != null && Number.isFinite(Number(request.query.limit)) ? Number(request.query.limit) : undefined
    return { history: listReplayHistory(domainId, limit) }
  })

  app.get<{ Params: { id: string } }>('/api/replay/history/:id', async (request, reply) => {
    const entry = getReplayHistory(Number(request.params.id))
    if (!entry) return reply.code(404).send({ error: 'history entry not found' })
    return { entry }
  })

  app.delete<{ Querystring: { domainId?: string } }>('/api/replay/history', async (request, reply) => {
    const domainId = Number(request.query.domainId)
    if (!Number.isFinite(domainId)) return reply.code(400).send({ error: 'domainId required' })
    const cleared = clearReplayHistory(domainId)
    writeAudit({ actor: actorName(request.session.userId), action: 'replay:history:clear', domainId, detail: { cleared } })
    return { cleared }
  })
}
