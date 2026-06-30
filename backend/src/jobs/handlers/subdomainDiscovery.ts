import { getDomain, updateDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { safeJsonParse } from '../../util/json'
import { alertSubdomains, type SubdomainAlert } from '../../notify/discord'
import { certSpotterSubdomains } from '../../sources/certspotter'
import { crtShSubdomains } from '../../sources/crtsh'
import { probeHost } from '../../sources/httpProbe'
import { detectTakeover } from '../../sources/takeover'
import { subfinderSubdomains } from '../../sources/subfinder'
import { diffAndStore, listUnprobed, updateProbe } from '../../subdomains/store'
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

  // crt.sh (certificate transparency)
  try {
    const crt = await crtShSubdomains(domain.host)
    for (const host of crt) discovered.push({ host, source: 'crtsh' })
    sources.crtsh = crt.length
  } catch (err) {
    sources.crtsh = `error: ${err instanceof Error ? err.message : String(err)}`
    log.warn({ domain: domain.host, err }, 'crt.sh discovery failed')
  }

  // certspotter (redundant CT source — covers crt.sh outages)
  try {
    const cs = await certSpotterSubdomains(domain.host)
    for (const host of cs) discovered.push({ host, source: 'certspotter' })
    sources.certspotter = cs.length
  } catch (err) {
    sources.certspotter = `error: ${err instanceof Error ? err.message : String(err)}`
    log.warn({ domain: domain.host, err }, 'certspotter discovery failed')
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

  // Lightweight HTTP probe: all new hosts, plus back-fill any existing hosts
  // that were never probed (e.g. discovered before probing existed). Bounded
  // concurrency. Enriches the stored row, the finding, and the Discord alert.
  const backfill = listUnprobed(domainId, MAX_PROBE).filter((h) => !diff.newHosts.includes(h))
  const toProbe = [...diff.newHosts, ...backfill].slice(0, MAX_PROBE)
  const probes = await mapLimit(
    toProbe,
    PROBE_CONCURRENCY,
    (host) => probeHost(host),
    {
      host: '', scheme: null, status: null, title: null, server: null, ip: null, url: null,
      cnames: [], loginHint: false, apiHint: false,
    },
  )
  const probeByHost = new Map(probes.filter((p) => p.host).map((p) => [p.host, p]))

  // Stamp probe data for EVERY host we probed (probes[] is index-aligned with
  // toProbe). Crucially this writes probedAt even on failure (status null), so a
  // dead host is probed exactly once and never re-probed every discovery run.
  toProbe.forEach((host, i) => {
    const p = probes[i]
    updateProbe(domainId, host, {
      ip: p?.ip ?? null,
      status: p?.status ?? null,
      title: p?.title ?? null,
      server: p?.server ?? null,
      scheme: p?.scheme ?? null,
    })
  })

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

  // Auto-fill the OWASP app profile from recon signals (only ever turns flags
  // ON; never clobbers the operator's manual choices). Makes OWASP filtering
  // smart without manual checkboxes.
  const detected: Record<string, boolean> = {}
  if (probes.some((p) => p.loginHint)) detected.hasLogin = true
  if (probes.some((p) => p.apiHint)) detected.hasApi = true
  if (Object.keys(detected).length) {
    // Re-read the profile fresh (not the job-start snapshot) so we don't clobber
    // a concurrent operator PATCH; only ever turn flags ON.
    const fresh = getDomain(domainId)
    const current = safeJsonParse<Record<string, boolean>>(fresh?.profile, {})
    const merged = { ...current, ...detected }
    if (JSON.stringify(merged) !== JSON.stringify(current)) {
      updateDomain(domainId, { profile: merged })
      log.info({ domain: domain.host, detected }, 'auto-updated OWASP app profile')
    }
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
