import type { FastifyPluginAsync } from 'fastify'
import {
  FINDING_STATUSES,
  getFinding,
  listFindings,
  updateFindingTriage,
  type FindingStatus,
  type FindingType,
} from '../findings/store'

const VALID_TYPES: FindingType[] = ['new_subdomain', 'exposure', 'osint', 'nmap', 'nuclei', 'ffuf', 'origin', 'owasp', 'tool']
const MAX_NOTE = 2000

export const findingRoutes: FastifyPluginAsync = async (app) => {
  app.get<{ Querystring: { domainId?: string; type?: string; limit?: string } }>(
    '/api/findings',
    async (request) => {
      const { domainId, type, limit } = request.query
      const t = type && VALID_TYPES.includes(type as FindingType) ? (type as FindingType) : undefined
      const domainNum = domainId != null && Number.isFinite(Number(domainId)) ? Number(domainId) : undefined
      const limitNum = limit != null && Number.isFinite(Number(limit)) ? Math.min(Number(limit), 2000) : undefined
      return {
        findings: listFindings({ domainId: domainNum, type: t, limit: limitNum }),
      }
    },
  )

  // Triage a finding: set its lifecycle status and/or note.
  app.patch<{ Params: { id: string }; Body: { status?: string; note?: string | null } }>(
    '/api/findings/:id',
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!Number.isFinite(id)) return reply.code(400).send({ error: 'invalid id' })
      const { status, note } = request.body ?? {}
      if (status !== undefined && !FINDING_STATUSES.includes(status as FindingStatus)) {
        return reply.code(400).send({ error: 'invalid status' })
      }
      if (note !== undefined && note !== null && (typeof note !== 'string' || note.length > MAX_NOTE)) {
        return reply.code(400).send({ error: `note must be a string up to ${MAX_NOTE} chars` })
      }
      const ok = updateFindingTriage(id, { status: status as FindingStatus | undefined, note })
      if (!ok) return reply.code(404).send({ error: 'finding not found' })
      return { finding: getFinding(id) }
    },
  )
}
