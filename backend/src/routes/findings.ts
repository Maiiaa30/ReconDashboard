import type { FastifyPluginAsync } from 'fastify'
import {
  appendEvidence,
  bulkUpdateTriage,
  FINDING_STATUSES,
  getFinding,
  getFindingLinks,
  queryFindings,
  requestRetest,
  summarizeFindings,
  updateFindingTriage,
  type FindingStatus,
  type FindingStatusFilter,
  type FindingType,
} from '../findings/store'
import { suggestTriage } from '../findings/triageSuggest'

// Must list EVERY FindingType — a type missing here is silently dropped from the
// ?type= filter, so the query falls back to "all types" and the caller's findings
// (e.g. the API Surface page's type=api) get buried under higher-scored rows past
// the limit. Keep in sync with FindingType in findings/store.ts.
const VALID_TYPES: FindingType[] = [
  'new_subdomain',
  'exposure',
  'osint',
  'nmap',
  'nuclei',
  'ffuf',
  'origin',
  'owasp',
  'tool',
  'cve_new',
  'leak',
  'api',
  'secret',
  'authz',
  'param',
  'asset_change',
]
const MAX_NOTE = 2000
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const VALID_STATUS_FILTERS: FindingStatusFilter[] = ['active', 'all', ...FINDING_STATUSES]
// Cap asset/tag substrings so a pathological query can't build a huge LIKE.
const MAX_TERM = 200

// Shared parse of the filter facets common to the list and summary endpoints.
function parseFindingFilters(query: {
  domainId?: string
  type?: string
  severity?: string
  asset?: string
  tag?: string
  since?: string
}) {
  const { domainId, type, severity, asset, tag, since } = query
  return {
    domainId: domainId != null && Number.isFinite(Number(domainId)) ? Number(domainId) : undefined,
    type: type && VALID_TYPES.includes(type as FindingType) ? (type as FindingType) : undefined,
    severity: severity && VALID_SEVERITIES.includes(severity) ? severity : undefined,
    asset: typeof asset === 'string' && asset.trim() ? asset.trim().slice(0, MAX_TERM) : undefined,
    tag: typeof tag === 'string' && tag.trim() ? tag.trim().slice(0, MAX_TERM) : undefined,
    since: since != null && Number.isFinite(Number(since)) ? new Date(Number(since)) : undefined,
  }
}

export const findingRoutes: FastifyPluginAsync = async (app) => {
  // Paged, server-side-filtered list. `cursor` continues from a prior page's
  // `nextCursor`; `nextCursor` is null on the last page.
  app.get<{
    Querystring: {
      domainId?: string
      type?: string
      status?: string
      severity?: string
      asset?: string
      tag?: string
      limit?: string
      since?: string
      cursor?: string
    }
  }>('/api/findings', async (request) => {
    const { status, limit, cursor } = request.query
    const filters = parseFindingFilters(request.query)
    const statusFilter =
      status && VALID_STATUS_FILTERS.includes(status as FindingStatusFilter) ? (status as FindingStatusFilter) : undefined
    const limitNum = limit != null && Number.isFinite(Number(limit)) ? Number(limit) : undefined
    return queryFindings({
      ...filters,
      status: statusFilter,
      limit: limitNum,
      cursor: typeof cursor === 'string' && cursor ? cursor : undefined,
    })
  })

  // Counts by status and severity for the current filter set (status/severity
  // facets excluded), so the UI can render totals and facet counts without
  // pulling every row.
  app.get<{ Querystring: { domainId?: string; type?: string; asset?: string; tag?: string; since?: string } }>(
    '/api/findings/summary',
    async (request) => summarizeFindings(parseFindingFilters(request.query)),
  )

  // Bulk-triage many findings in one transaction. Registered before :id so the
  // static path wins the route match.
  app.patch<{ Body: { ids?: number[]; status?: string; note?: string | null } }>(
    '/api/findings/bulk',
    async (request, reply) => {
      const { ids, status, note } = request.body ?? {}
      if (!Array.isArray(ids) || ids.length === 0) return reply.code(400).send({ error: 'ids required' })
      if (ids.length > 5000) return reply.code(400).send({ error: 'too many ids (max 5000)' })
      const cleanIds = ids.map(Number).filter((n) => Number.isFinite(n))
      if (status !== undefined && !FINDING_STATUSES.includes(status as FindingStatus)) {
        return reply.code(400).send({ error: 'invalid status' })
      }
      if (note !== undefined && note !== null && (typeof note !== 'string' || note.length > MAX_NOTE)) {
        return reply.code(400).send({ error: `note must be a string up to ${MAX_NOTE} chars` })
      }
      const changed = bulkUpdateTriage(cleanIds, { status: status as FindingStatus | undefined, note })
      return { changed }
    },
  )

  // AI triage helper: SUGGEST dispositions for a domain's open findings. No side
  // effects — it never changes a finding or enqueues a scan; the operator applies
  // suggestions with the normal bulk-triage action. Degrades gracefully when no
  // LLM is configured.
  app.post<{ Body: { domainId?: number } }>('/api/findings/triage-suggest', async (request, reply) => {
    const domainId = Number(request.body?.domainId)
    if (!Number.isFinite(domainId)) return reply.code(400).send({ error: 'domainId required' })
    return suggestTriage(domainId)
  })

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

  // Mark a finding for retest: sets it to retest_pending and stamps when. A later
  // scan that re-detects it flips it back to confirmed automatically; the operator
  // marks it retest_passed once verified fixed.
  app.post<{ Params: { id: string } }>('/api/findings/:id/retest', async (request, reply) => {
    const id = Number(request.params.id)
    if (!Number.isFinite(id)) return reply.code(400).send({ error: 'invalid id' })
    if (!requestRetest(id)) return reply.code(404).send({ error: 'finding not found' })
    return { finding: getFinding(id) }
  })

  // Attach evidence (a request/response, screenshot path, or note) to a finding.
  // Merged into data.evidence (never clobbered) and rendered in the report.
  app.post<{ Params: { id: string }; Body: { request?: string; response?: string; screenshotPath?: string; note?: string } }>(
    '/api/findings/:id/evidence',
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!Number.isFinite(id)) return reply.code(400).send({ error: 'invalid id' })
      if (!getFinding(id)) return reply.code(404).send({ error: 'finding not found' })
      const b = request.body ?? {}
      const str = (v: unknown) => (typeof v === 'string' ? v : undefined)
      const res = appendEvidence(id, { request: str(b.request), response: str(b.response), screenshotPath: str(b.screenshotPath), note: str(b.note) })
      if (!res) return reply.code(400).send({ error: 'provide at least one of: request, response, screenshotPath, note' })
      return { finding: getFinding(id), evidenceCount: res.evidenceCount }
    },
  )

  // Findings linked to/from this one (e.g. the PoC that confirms a CVE).
  app.get<{ Params: { id: string } }>('/api/findings/:id/links', async (request, reply) => {
    const id = Number(request.params.id)
    if (!Number.isFinite(id) || !getFinding(id)) return reply.code(404).send({ error: 'finding not found' })
    return { links: getFindingLinks(id) }
  })
}
