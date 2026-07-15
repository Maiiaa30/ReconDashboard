import type { FastifyBaseLogger } from 'fastify'
import type { Job } from '../db/schema'
import { enqueueJob, hasPendingJob } from './queue'

// Post-completion chaining: when a job finishes, conditionally enqueue the next
// step of the natural recon kill-chain so a one-person team doesn't drive every
// hop by hand. Deliberately conservative — only PASSIVE follow-ons fire
// automatically, and each is deduped via hasPendingJob so a backed-up worker
// can't pile up. Loud/active scans stay operator-initiated.
export function chainAfter(job: Job, result: unknown, log: FastifyBaseLogger): void {
  try {
    const domainId = job.domainId
    if (domainId == null) return

    if (job.type === 'subdomain_discovery') {
      const r = result as { newCount?: number } | null
      // New hosts → re-check exposure (their IPs) and capture screenshots.
      if (!hasPendingJob('exposure_scan', domainId)) {
        enqueueJob('exposure_scan', { domainId })
        log.info({ domainId, chainFrom: job.id }, 'chain: enqueued exposure after discovery')
      }
      if ((r?.newCount ?? 0) > 0 && !hasPendingJob('screenshot', domainId)) {
        enqueueJob('screenshot', { domainId })
        log.info({ domainId, chainFrom: job.id }, 'chain: enqueued screenshots for new live hosts')
      }
    }

    if (job.type === 'exposure_scan') {
      // Exposure done → refresh the PASSIVE intel that feeds the URL corpus and
      // the API surface, so param-discovery / JS-recon / OWASP see fresh data
      // instead of a stale sample. Both are passive (not in LOUD_TYPES) and
      // deduped; nothing loud is auto-enqueued here.
      for (const t of ['osint_gather', 'api_discovery'] as const) {
        if (!hasPendingJob(t, domainId)) {
          enqueueJob(t, { domainId })
          log.info({ domainId, chainFrom: job.id }, `chain: enqueued ${t} after exposure`)
        }
      }
    }
  } catch (err) {
    log.warn({ err, jobId: job.id }, 'chain step failed')
  }
}
