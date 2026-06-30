import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { alertList } from '../../notify/discord'
import { crtShSubdomains } from '../../sources/crtsh'
import { subfinderSubdomains } from '../../sources/subfinder'
import { diffAndStore } from '../../subdomains/store'
import type { JobContext } from '../worker'

// Phase 2: passive subdomain discovery. crt.sh (always) + subfinder (if present).
// Purely passive — no active probing, no shell strings. Diffs against stored
// hosts, flags new ones, alerts Discord (grouped).
export async function subdomainDiscoveryHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const discovered: { host: string; source: string }[] = []
  const sources: Record<string, number | string> = {}

  // crt.sh
  try {
    const crt = await crtShSubdomains(domain.host)
    for (const host of crt) discovered.push({ host, source: 'crtsh' })
    sources.crtsh = crt.length
  } catch (err) {
    sources.crtsh = `error: ${err instanceof Error ? err.message : String(err)}`
    log.warn({ domain: domain.host, err }, 'crt.sh discovery failed')
  }

  // subfinder (passive). Unavailable locally without the binary.
  try {
    const sf = await subfinderSubdomains(domain.host)
    if (sf.available) {
      for (const host of sf.hosts) discovered.push({ host, source: 'subfinder' })
      sources.subfinder = sf.hosts.length
    } else {
      sources.subfinder = 'unavailable (binary not installed)'
    }
  } catch (err) {
    sources.subfinder = `error: ${err instanceof Error ? err.message : String(err)}`
    log.warn({ domain: domain.host, err }, 'subfinder discovery failed')
  }

  const diff = diffAndStore(domainId, discovered)

  // Record + score each genuinely new subdomain as a finding.
  for (const host of diff.newHosts) {
    await addScoredFinding({
      domainId,
      type: 'new_subdomain',
      data: { host, domain: domain.host },
      tags: ['new-subdomain'],
    })
  }

  // Grouped Discord alert for new subdomains (silent if no webhook).
  if (diff.newHosts.length > 0) {
    await alertList(
      `🛰️ ${diff.newHosts.length} new subdomain(s) for ${domain.host}`,
      diff.newHosts,
    )
  }

  return {
    domain: domain.host,
    sources,
    discovered: diff.total,
    newCount: diff.newHosts.length,
    newHosts: diff.newHosts,
    updated: diff.updatedCount,
  }
}
