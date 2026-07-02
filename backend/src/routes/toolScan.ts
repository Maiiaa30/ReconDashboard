import type { FastifyPluginAsync } from 'fastify'
import { assertScanAllowed, ScanPolicyError } from '../domains/scanPolicy'
import { enqueueJob } from '../jobs/queue'
import { TOOL_IDS } from '../jobs/handlers/toolScan'
import { actorName, writeAudit } from '../audit/store'

// Run one of the extra active tools (katana/naabu/dalfox/sslscan/wpenum) against
// a target. Gating + audit go through the shared scan policy.
export const toolScanRoutes: FastifyPluginAsync = async (app) => {
  app.post<{ Params: { id: string }; Body: { tool?: string; target?: string; scheme?: string; confirm?: boolean; path?: string } }>(
    '/api/domains/:id/tool',
    async (request, reply) => {
      const id = Number(request.params.id)
      const tool = String(request.body?.tool ?? '')
      if (!(TOOL_IDS as readonly string[]).includes(tool)) {
        return reply.code(400).send({ error: `unknown tool — one of: ${TOOL_IDS.join(', ')}` })
      }

      // Optional single path (e.g. bypass403 targeting a specific 403 hit from
      // Fuzzing). Sanitised to a conservative shape before it reaches the runner.
      const rawPath = typeof request.body?.path === 'string' ? request.body.path.trim() : ''
      const path = /^\/[A-Za-z0-9._~%\-/?#&=]{0,300}$/.test(rawPath) ? rawPath : undefined

      try {
        const { domain, target } = await assertScanAllowed({
          domainId: id,
          target: request.body?.target,
          confirm: request.body?.confirm === true,
          jobType: 'tool_scan',
        })
        const scheme = request.body?.scheme === 'http' ? 'http' : 'https'
        const jobId = enqueueJob('tool_scan', { domainId: id, tool, target, scheme, ...(path ? { path } : {}) })
        writeAudit({
          actor: actorName(request.session.userId),
          action: `enqueue:tool_scan`,
          domainId: id,
          target,
          mode: domain.mode,
          jobId,
          detail: { tool, scheme, ...(path ? { path } : {}) },
        })
        return reply.code(202).send({ jobId, tool, target })
      } catch (err) {
        if (err instanceof ScanPolicyError) {
          if (err.retryAfterSec) reply.header('Retry-After', String(err.retryAfterSec))
          return reply.code(err.status).send({ error: err.message, code: err.code })
        }
        throw err
      }
    },
  )
}
