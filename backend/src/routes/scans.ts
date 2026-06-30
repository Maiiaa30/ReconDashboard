import type { FastifyPluginAsync } from 'fastify'
import { DomainValidationError, getDomain, requireActiveAuthorized } from '../domains/store'
import { enqueueJob, type JobType } from '../jobs/queue'
import { hostBelongsToDomain, isValidHostname } from '../util/validate'

// ACTIVE / LOUD scans. Every route here is gated behind the domain being
// active_authorized. These are default-off in the UI and clearly labelled loud.
export const scanRoutes: FastifyPluginAsync = async (app) => {
  function gate(idRaw: string, target: string | undefined): { domainHost: string; target: string } {
    const id = Number(idRaw)
    const domain = getDomain(id)
    if (!domain) throw new DomainValidationError('domain not found')
    requireActiveAuthorized(id) // throws if passive_only
    const t = (target ?? domain.host).trim().toLowerCase()
    if (!isValidHostname(t) && t !== domain.host) {
      throw new DomainValidationError(`invalid target: ${target}`)
    }
    if (t !== domain.host && !hostBelongsToDomain(t, domain.host)) {
      throw new DomainValidationError(`target ${t} is not within authorized domain ${domain.host}`)
    }
    return { domainHost: domain.host, target: t }
  }

  function makeRoute(path: string, jobType: JobType, build: (body: any, target: string) => Record<string, unknown>) {
    app.post<{ Params: { id: string }; Body: Record<string, unknown> }>(
      path,
      async (request, reply) => {
        const id = Number(request.params.id)
        try {
          const { target } = gate(request.params.id, request.body?.target as string | undefined)
          const params = { domainId: id, target, ...build(request.body ?? {}, target) }
          return reply.code(202).send({ jobId: enqueueJob(jobType, params) })
        } catch (err) {
          if (err instanceof DomainValidationError) {
            const code = err.message === 'domain not found' ? 404 : 400
            return reply.code(code).send({ error: err.message })
          }
          throw err
        }
      },
    )
  }

  makeRoute('/api/domains/:id/scan/nmap', 'nmap_scan', (body) => ({
    ports: typeof body.ports === 'string' ? body.ports : undefined,
  }))

  makeRoute('/api/domains/:id/scan/nuclei', 'nuclei_scan', (body) => ({
    scheme: body.scheme === 'http' ? 'http' : 'https',
    severity: typeof body.severity === 'string' ? body.severity : undefined,
  }))

  makeRoute('/api/domains/:id/scan/ffuf', 'ffuf_scan', (body) => ({
    scheme: body.scheme === 'http' ? 'http' : 'https',
    path: typeof body.path === 'string' ? body.path : 'FUZZ',
    wordlist: typeof body.wordlist === 'string' ? body.wordlist : undefined,
  }))
}
