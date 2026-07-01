import type { FastifyPluginAsync } from 'fastify'
import { assertScanAllowed, ScanPolicyError } from '../domains/scanPolicy'
import { enqueueJob, type JobType } from '../jobs/queue'
import { actorName, writeAudit } from '../audit/store'

// ACTIVE / LOUD scans. All gating (mode/confirm, target-belongs, authorization
// window, engagement scope, pending guard, cooldown) lives in assertScanAllowed;
// every allowed enqueue is written to the append-only audit ledger.
export const scanRoutes: FastifyPluginAsync = async (app) => {
  function makeRoute(path: string, jobType: JobType, build: (body: any, target: string) => Record<string, unknown>) {
    app.post<{ Params: { id: string }; Body: Record<string, unknown> }>(
      path,
      async (request, reply) => {
        const id = Number(request.params.id)
        try {
          const { domain, target } = await assertScanAllowed({
            domainId: id,
            target: request.body?.target as string | undefined,
            confirm: request.body?.confirm === true,
            jobType,
          })
          const params = { domainId: id, target, ...build(request.body ?? {}, target) }
          const jobId = enqueueJob(jobType, params)
          writeAudit({
            actor: actorName(request.session.userId),
            action: `enqueue:${jobType}`,
            domainId: id,
            target,
            mode: domain.mode,
            jobId,
            detail: build(request.body ?? {}, target),
          })
          return reply.code(202).send({ jobId })
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

  makeRoute('/api/domains/:id/scan/nmap', 'nmap_scan', (body) => ({
    ports: typeof body.ports === 'string' ? body.ports : undefined,
  }))

  makeRoute('/api/domains/:id/scan/nuclei', 'nuclei_scan', (body) => {
    // Template tags: accept a comma string, hand the handler a validated array.
    const rawTags = body.tags
    const tags =
      typeof rawTags === 'string'
        ? rawTags.split(',').map((t) => t.trim().toLowerCase()).filter((t) => /^[a-z0-9-]+$/.test(t))
        : undefined
    return {
      scheme: body.scheme === 'http' ? 'http' : 'https',
      severity: typeof body.severity === 'string' ? body.severity : undefined,
      tags,
    }
  })

  makeRoute('/api/domains/:id/scan/ffuf', 'ffuf_scan', (body) => ({
    scheme: body.scheme === 'http' ? 'http' : 'https',
    path: typeof body.path === 'string' ? body.path : 'FUZZ',
    wordlist: typeof body.wordlist === 'string' ? body.wordlist : undefined,
  }))
}
