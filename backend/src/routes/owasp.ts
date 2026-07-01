import type { FastifyPluginAsync } from 'fastify'
import { assertScanAllowed, ScanPolicyError } from '../domains/scanPolicy'
import { enqueueJob } from '../jobs/queue'
import { actorName, writeAudit } from '../audit/store'
import {
  applicableCategories,
  OWASP_CATALOG,
  PROFILE_KEYS,
  tagsForCategories,
  type ProfileFlags,
} from '../owasp/catalog'
import { safeJsonParse } from '../util/json'

export const owaspRoutes: FastifyPluginAsync = async (app) => {
  // Static catalog + profile keys for the UI.
  app.get('/api/owasp/catalog', async () => ({ catalog: OWASP_CATALOG, profileKeys: PROFILE_KEYS }))

  // Run OWASP tests for a domain. active_authorized runs freely; passive_only
  // runs only with explicit confirm:true (the UI warns first), matching the
  // Scans/Fuzzing gate. Categories are filtered by the domain's app profile
  // (and optionally an explicit selection).
  app.post<{ Params: { id: string }; Body: { categoryIds?: string[]; scheme?: string; confirm?: boolean; nuclei?: boolean } }>(
    '/api/domains/:id/owasp',
    async (request, reply) => {
      const id = Number(request.params.id)
      try {
        const { domain } = await assertScanAllowed({
          domainId: id,
          confirm: request.body?.confirm === true,
          jobType: 'owasp_active',
        })

        const profile = safeJsonParse<ProfileFlags>(domain.profile, {})
        let cats = applicableCategories(profile)
        const requested = request.body?.categoryIds
        if (Array.isArray(requested) && requested.length) {
          cats = cats.filter((c) => requested.includes(c.id))
        }
        if (cats.length === 0) {
          return reply
            .code(400)
            .send({ error: 'no applicable OWASP categories for this domain profile/selection' })
        }

        const tags = tagsForCategories(cats.map((c) => c.id))
        const scheme = request.body?.scheme === 'http' ? 'http' : 'https'

        // Primary: our own active HTTP checks (no nuclei dependency) — headers,
        // sensitive files, reflected XSS, open redirect, CORS, TRACE, listings.
        const jobs: number[] = []
        jobs.push(enqueueJob('owasp_active', { domainId: id, target: domain.host, scheme }))
        // Complementary: a nuclei pass over the selected categories' tags (only if
        // the operator wants it / the binary is present — degrades gracefully).
        if (request.body?.nuclei !== false) {
          jobs.push(
            enqueueJob('nuclei_scan', {
              domainId: id,
              target: domain.host,
              scheme,
              tags,
              owaspCategory: cats.map((c) => c.id).join(','),
            }),
          )
        }
        writeAudit({
          actor: actorName(request.session.userId),
          action: 'enqueue:owasp',
          domainId: id,
          target: domain.host,
          mode: domain.mode,
          jobId: jobs[0],
          detail: { categories: cats.map((c) => c.id), nuclei: request.body?.nuclei !== false, jobs },
        })
        return reply.code(202).send({ jobId: jobs[0], jobs, categories: cats.map((c) => c.id), tags })
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
