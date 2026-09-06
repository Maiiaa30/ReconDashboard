import type { FastifyPluginAsync } from 'fastify'
import { queryAudit, summarizeAudit } from '../audit/store'

// Cap free-text terms so a pathological query can't build a huge LIKE / value.
const MAX_TERM = 200
const term = (v?: string) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, MAX_TERM) : undefined)

// Shared parse of the facets common to the list and summary endpoints. The
// `action` facet is intentionally NOT parsed here: the summary groups by action,
// so it must not also filter by it (mirrors parseFindingFilters + status/severity).
function parseAuditFilters(query: {
  domainId?: string
  actor?: string
  mode?: string
  target?: string
  since?: string
}) {
  const { domainId, actor, mode, target, since } = query
  return {
    domainId: domainId != null && Number.isFinite(Number(domainId)) ? Number(domainId) : undefined,
    actor: term(actor),
    mode: term(mode),
    target: term(target),
    since: since != null && Number.isFinite(Number(since)) ? new Date(Number(since)) : undefined,
  }
}

// Read-only view of the append-only audit ledger. There is deliberately NO
// write/delete endpoint — the ledger is only appended by the server itself.
export const auditRoutes: FastifyPluginAsync = async (app) => {
  // Paged, server-side-filtered list. `cursor` continues from a prior page's
  // `nextCursor`; `nextCursor` is null on the last page.
  app.get<{
    Querystring: {
      domainId?: string
      actor?: string
      action?: string
      mode?: string
      target?: string
      since?: string
      limit?: string
      cursor?: string
    }
  }>('/api/audit', async (request) => {
    const { action, limit, cursor } = request.query
    const filters = parseAuditFilters(request.query)
    const limitNum = limit != null && Number.isFinite(Number(limit)) ? Number(limit) : undefined
    return queryAudit({
      ...filters,
      action: term(action),
      limit: limitNum,
      cursor: typeof cursor === 'string' && cursor ? cursor : undefined,
    })
  })

  // Counts by action for the current filter set (action facet excluded), so the
  // UI can render a total and per-action counts without pulling every row.
  app.get<{ Querystring: { domainId?: string; actor?: string; mode?: string; target?: string; since?: string } }>(
    '/api/audit/summary',
    async (request) => summarizeAudit(parseAuditFilters(request.query)),
  )
}
