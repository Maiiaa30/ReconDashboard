import type { FastifyPluginAsync } from 'fastify'
import { DomainValidationError, getDomain, requireActiveAuthorized } from '../domains/store'
import { enqueueJob } from '../jobs/queue'
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

  // Run OWASP tests for a domain. Gated behind active_authorized. Categories are
  // filtered by the domain's app profile (and optionally an explicit selection).
  app.post<{ Params: { id: string }; Body: { categoryIds?: string[]; scheme?: string } }>(
    '/api/domains/:id/owasp',
    async (request, reply) => {
      const id = Number(request.params.id)
      const domain = getDomain(id)
      if (!domain) return reply.code(404).send({ error: 'domain not found' })
      try {
        requireActiveAuthorized(id)
      } catch (err) {
        if (err instanceof DomainValidationError) return reply.code(400).send({ error: err.message })
        throw err
      }

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
      // One nuclei job covering all selected categories' tags.
      const jobId = enqueueJob('nuclei_scan', {
        domainId: id,
        target: domain.host,
        scheme,
        tags,
        owaspCategory: cats.map((c) => c.id).join(','),
      })
      return reply.code(202).send({ jobId, categories: cats.map((c) => c.id), tags })
    },
  )
}
