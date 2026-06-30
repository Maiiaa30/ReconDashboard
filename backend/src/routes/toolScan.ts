import type { FastifyPluginAsync } from 'fastify'
import { getDomain } from '../domains/store'
import { enqueueJob } from '../jobs/queue'
import { TOOL_IDS } from '../jobs/handlers/toolScan'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../util/validate'

// Run one of the extra active tools (katana/naabu/dalfox/sslscan/wpenum) against
// a target. active_authorized runs freely; passive_only needs confirm:true.
export const toolScanRoutes: FastifyPluginAsync = async (app) => {
  app.post<{ Params: { id: string }; Body: { tool?: string; target?: string; scheme?: string; confirm?: boolean } }>(
    '/api/domains/:id/tool',
    async (request, reply) => {
      const id = Number(request.params.id)
      const domain = getDomain(id)
      if (!domain) return reply.code(404).send({ error: 'domain not found' })

      const tool = String(request.body?.tool ?? '')
      if (!(TOOL_IDS as readonly string[]).includes(tool)) {
        return reply.code(400).send({ error: `unknown tool — one of: ${TOOL_IDS.join(', ')}` })
      }
      if (domain.mode !== 'active_authorized' && request.body?.confirm !== true) {
        return reply
          .code(400)
          .send({ error: `domain "${domain.host}" is passive_only — confirm you are authorized to actively scan it` })
      }

      const target = (request.body?.target ?? domain.host).trim().toLowerCase()
      if (!isValidHostname(target) && !isValidDomain(target)) {
        return reply.code(400).send({ error: `invalid target: ${target}` })
      }
      if (target !== domain.host && !hostBelongsToDomain(target, domain.host)) {
        return reply.code(400).send({ error: `target ${target} is not within domain ${domain.host}` })
      }
      const scheme = request.body?.scheme === 'http' ? 'http' : 'https'

      const jobId = enqueueJob('tool_scan', { domainId: id, tool, target, scheme })
      return reply.code(202).send({ jobId, tool, target })
    },
  )
}
