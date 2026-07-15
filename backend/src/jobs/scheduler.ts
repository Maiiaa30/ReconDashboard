import type { FastifyBaseLogger } from 'fastify'
import { config } from '../config'
import { domainsDueForMonitoring, listDomains, markMonitored } from '../domains/store'
import { enqueueJob, hasPendingJob, lastJobAt } from './queue'

const LEAK_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000 // active domains: once a day
const CODE_LEAK_INTERVAL_MS = 24 * 60 * 60 * 1000 // public-code search: once a day

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
        // Refresh the passive intel that feeds the URL corpus + API surface so the
        // downstream attack tools don't work off stale data. Both are passive
        // (not in LOUD_TYPES); nothing loud is ever scheduled.
        if (!hasPendingJob('osint_gather', d.id)) enqueueJob('osint_gather', { domainId: d.id })
        if (!hasPendingJob('api_discovery', d.id)) enqueueJob('api_discovery', { domainId: d.id })
        markMonitored(d.id)
        log.info({ domain: d.host, everyHours: d.monitorIntervalHours }, 'auto-monitor enqueued recon')
      } catch (err) {
        log.error({ err, domain: d.host }, 'auto-monitor enqueue failed for domain')
      }
    }

    // Daily breach/leak check for ACTIVE domains only (passive domains are
    // manual, per the operator's rule). Anchored on last attempt (any status)
    // so an errored run — e.g. a bad API key — doesn't re-enqueue every tick.
    if (config.leaks.enabled) {
      for (const d of listDomains()) {
        if (d.mode !== 'active_authorized') continue
        if (hasPendingJob('leak_check', d.id)) continue
        const last = lastJobAt('leak_check', d.id)
        if (last && Date.now() - last.getTime() < LEAK_CHECK_INTERVAL_MS) continue
        try {
          enqueueJob('leak_check', { domainId: d.id })
          log.info({ domain: d.host }, 'daily leak-check enqueued')
        } catch (err) {
          log.error({ err, domain: d.host }, 'leak-check enqueue failed for domain')
        }
      }
    }

    // Daily public-code leak search for ACTIVE domains, when a GitHub token is
    // configured (GitHub requires auth for code search). Queries GitHub, not the
    // target, so it's passive — but kept to active domains to bound API usage.
    if (config.githubToken) {
      for (const d of listDomains()) {
        if (d.mode !== 'active_authorized') continue
        if (hasPendingJob('code_leak', d.id)) continue
        const last = lastJobAt('code_leak', d.id)
        if (last && Date.now() - last.getTime() < CODE_LEAK_INTERVAL_MS) continue
        try {
          enqueueJob('code_leak', { domainId: d.id })
          log.info({ domain: d.host }, 'daily code-leak search enqueued')
        } catch (err) {
          log.error({ err, domain: d.host }, 'code-leak enqueue failed for domain')
        }
      }
    }
  }, TICK_MS)
  timer.unref()
}

export function stopScheduler(): void {
  if (timer) clearInterval(timer)
  timer = null
}
