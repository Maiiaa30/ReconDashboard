import type { FastifyBaseLogger } from 'fastify'
import { domainsDueForMonitoring, markMonitored } from '../domains/store'
import { enqueueJob } from './queue'

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
    try {
      const due = domainsDueForMonitoring(Date.now())
      for (const d of due) {
        enqueueJob('subdomain_discovery', { domainId: d.id })
        enqueueJob('exposure_scan', { domainId: d.id })
        markMonitored(d.id)
        log.info({ domain: d.host, everyHours: d.monitorIntervalHours }, 'auto-monitor enqueued recon')
      }
    } catch (err) {
      log.error({ err }, 'auto-monitor tick failed')
    }
  }, TICK_MS)
  timer.unref()
}

export function stopScheduler(): void {
  if (timer) clearInterval(timer)
  timer = null
}
