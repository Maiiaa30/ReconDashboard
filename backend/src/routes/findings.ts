import type { FastifyPluginAsync } from 'fastify'
import { listFindings, type FindingType } from '../findings/store'

const VALID_TYPES: FindingType[] = ['new_subdomain', 'exposure', 'osint', 'nmap', 'nuclei', 'ffuf']

export const findingRoutes: FastifyPluginAsync = async (app) => {
  app.get<{ Querystring: { domainId?: string; type?: string; limit?: string } }>(
    '/api/findings',
    async (request) => {
      const { domainId, type, limit } = request.query
      const t = type && VALID_TYPES.includes(type as FindingType) ? (type as FindingType) : undefined
      return {
        findings: listFindings({
          domainId: domainId ? Number(domainId) : undefined,
          type: t,
          limit: limit ? Math.min(Number(limit), 2000) : undefined,
        }),
      }
    },
  )
}
