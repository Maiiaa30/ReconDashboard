import type { FastifyPluginAsync } from 'fastify'
import { domainOverviews } from '../domains/overview'
import { listFindings } from '../findings/store'

// Engagement Home: a cross-target "what should I look at first" view. Reuses the
// per-domain overview (already cached) plus the top open, non-trivial findings
// across all targets so the operator lands on a prioritized action list.
export const homeRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/home', async () => {
    const overview = domainOverviews()
    const topFindings = listFindings({ limit: 400 })
      .filter((f) => f.status === 'open' && (f.score ?? 0) >= 40)
      .slice(0, 15)
      .map((f) => ({ id: f.id, domainId: f.domainId, type: f.type, data: f.data, score: f.score, tags: f.tags }))
    return { overview, topFindings }
  })
}
