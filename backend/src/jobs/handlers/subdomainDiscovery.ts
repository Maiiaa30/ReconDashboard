import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { alertSubdomains, type SubdomainAlert } from '../../notify/discord'
import { crtShSubdomains } from '../../sources/crtsh'
import { probeHost } from '../../sources/httpProbe'
import { detectTakeover } from '../../sources/takeover'
import { subfinderSubdomains } from '../../sources/subfinder'
import { diffAndStore, updateProbe } from '../../subdomains/store'
import { mapLimit } from '../../util/async'
import type { JobContext } from '../worker'

const PROBE_CONCURRENCY = 8
const MAX_PROBE = 200 // cap probing on very large new batches

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

  // Lightweight HTTP probe of new hosts (status / title / server / ip), bounded
  // concurrency. Enriches the stored row, the finding, and the Discord alert.
  const toProbe = diff.newHosts.slice(0, MAX_PROBE)
  const probes = await mapLimit(
    toProbe,
    PROBE_CONCURRENCY,
    (host) => probeHost(host),
    { host: '', scheme: null, status: null, title: null, server: null, ip: null, url: null, cnames: [] },
  )
  const probeByHost = new Map(probes.filter((p) => p.host).map((p) => [p.host, p]))

  for (const host of toProbe) {
    const p = probeByHost.get(host)
    if (p) {
      updateProbe(domainId, host, {
        ip: p.ip,
        status: p.status,
        title: p.title,
        server: p.server,
        scheme: p.scheme,
      })
    }
  }

  // Record + score each genuinely new subdomain as a finding (with probe data
  // and a passive takeover-candidate hint).
  let takeoverCount = 0
  for (const host of diff.newHosts) {
    const p = probeByHost.get(host)
    const takeover = p ? detectTakeover(p.cnames, p.status) : null
    if (takeover) takeoverCount++
    await addScoredFinding({
      domainId,
      type: 'new_subdomain',
      data: {
        host,
        domain: domain.host,
        status: p?.status ?? null,
        title: p?.title ?? null,
        server: p?.server ?? null,
        ip: p?.ip ?? null,
        cnames: p?.cnames ?? [],
        takeover,
      },
      tags: ['new-subdomain'],
    })
  }

  // Grouped, enriched Discord alert (silent if no webhook).
  if (diff.newHosts.length > 0) {
    const alerts: SubdomainAlert[] = diff.newHosts.map((host) => {
      const p = probeByHost.get(host)
      return {
        host,
        status: p?.status ?? null,
        title: p?.title ?? null,
        server: p?.server ?? null,
        ip: p?.ip ?? null,
      }
    })
    await alertSubdomains(`🛰️ ${diff.newHosts.length} new subdomain(s) for ${domain.host}`, alerts)
  }

  return {
    domain: domain.host,
    sources,
    discovered: diff.total,
    newCount: diff.newHosts.length,
    newHosts: diff.newHosts,
    updated: diff.updatedCount,
    takeoverCandidates: takeoverCount,
  }
}
