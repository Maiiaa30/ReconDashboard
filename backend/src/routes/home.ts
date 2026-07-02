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
    // "What changed": newest new-CVE-on-a-known-asset alerts, most recent first.
    const recentChanges = listFindings({ type: 'cve_new', limit: 50 })
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 8)
      .map((f) => ({ id: f.id, domainId: f.domainId, data: f.data, score: f.score, createdAt: f.createdAt }))
    return { overview, topFindings, recentChanges }
  })
}
