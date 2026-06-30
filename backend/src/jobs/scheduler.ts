import type { FastifyBaseLogger } from 'fastify'
import { config } from '../config'
import { listDomains } from '../domains/store'
import { enqueueJob } from './queue'

// Minimal interval scheduler for passive subdomain discovery. Disabled by
// default (SCHEDULE_SUBDOMAINS_MINUTES=0); manual "Run discovery now" is the
// primary path. When enabled, it enqueues a discovery job per domain each tick.
let timer: NodeJS.Timeout | null = null

export function startScheduler(log: FastifyBaseLogger): void {
  const minutes = config.scheduleSubdomainsMinutes
  if (!minutes || minutes <= 0) {
    log.info('subdomain scheduler disabled (manual runs only)')
    return
  }

  const intervalMs = minutes * 60_000
  log.info(`subdomain scheduler enabled: every ${minutes} min`)

  timer = setInterval(() => {
    try {
      const domains = listDomains()
      for (const d of domains) {
        enqueueJob('subdomain_discovery', { domainId: d.id })
      }
      if (domains.length) log.info(`scheduler enqueued discovery for ${domains.length} domain(s)`)
    } catch (err) {
      log.error({ err }, 'scheduler tick failed')
    }
  }, intervalMs)
  timer.unref()
}

export function stopScheduler(): void {
  if (timer) clearInterval(timer)
  timer = null
}
