import type { FastifyBaseLogger } from 'fastify'
import { domainsDueForMonitoring, markMonitored } from '../domains/store'
import { enqueueJob, hasPendingJob } from './queue'

// Per-domain auto-monitoring. Each domain can opt into "re-run passive recon
// every N hours" (Domains tab). A lightweight ticker checks once a minute which
// domains are due and enqueues discovery + exposure for them; the discovery
// handler already alerts (Discord) on newly-found subdomains. The first run
// fires immediately after enabling (lastMonitoredAt is null).
let timer: NodeJS.Timeout | null = null

const TICK_MS = 60_000

export function startScheduler(log: FastifyBaseLogger): void {
  log.info('auto-monitor scheduler active (checks every 60s)')

  timer = setInterval(() => {
    let due: ReturnType<typeof domainsDueForMonitoring>
    try {
      due = domainsDueForMonitoring(Date.now())
    } catch (err) {
      log.error({ err }, 'auto-monitor tick failed')
      return
    }
    for (const d of due) {
      // Per-domain isolation: one domain throwing must not skip the rest, and we
      // only stamp lastMonitoredAt once both enqueues succeed (else the next tick
      // retries). Skip enqueue when a prior monitoring job for this domain is
      // still pending, so a backed-up worker doesn't accumulate duplicates.
      try {
        if (!hasPendingJob('subdomain_discovery', d.id)) enqueueJob('subdomain_discovery', { domainId: d.id })
        if (!hasPendingJob('exposure_scan', d.id)) enqueueJob('exposure_scan', { domainId: d.id })
        markMonitored(d.id)
        log.info({ domain: d.host, everyHours: d.monitorIntervalHours }, 'auto-monitor enqueued recon')
      } catch (err) {
        log.error({ err, domain: d.host }, 'auto-monitor enqueue failed for domain')
      }
    }
  }, TICK_MS)
  timer.unref()
}

export function stopScheduler(): void {
  if (timer) clearInterval(timer)
  timer = null
}
