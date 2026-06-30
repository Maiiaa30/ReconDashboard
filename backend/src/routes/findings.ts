import type { FastifyPluginAsync } from 'fastify'
import { listFindings, type FindingType } from '../findings/store'

const VALID_TYPES: FindingType[] = ['new_subdomain', 'exposure', 'osint', 'nmap', 'nuclei', 'ffuf', 'origin']

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
}
