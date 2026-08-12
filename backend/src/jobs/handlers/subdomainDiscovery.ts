import { getDomain, updateDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { safeJsonParse } from '../../util/json'
import { alertSubdomains, type SubdomainAlert } from '../../notify/discord'
import { certSpotterSubdomains } from '../../sources/certspotter'
import { crtShSubdomains } from '../../sources/crtsh'
import { dnsxResolveHosts } from '../../sources/dnsx'
import { httpxProbeHosts } from '../../sources/httpx'
import { confirmTakeover, detectTakeover } from '../../sources/takeover'
import { subfinderSubdomains } from '../../sources/subfinder'
import { diffAndStore, listSubdomains, updateProbe } from '../../subdomains/store'
import { linkAssetFinding, upsertAsset } from '../../assets/store'
import { mapLimit } from '../../util/async'
import { alertChanges, recordAndDetectChanges } from '../../findings/changeWatch'
import type { JobContext } from '../worker'

const MAX_PROBE = 200 // cap probing on very large new batches

// Phase 2: passive subdomain discovery. crt.sh (always) + subfinder (if present).
// Purely passive — no active probing, no shell strings. Diffs against stored
// hosts, flags new ones, alerts Discord (grouped).
export async function subdomainDiscoveryHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const discovered: { host: string; source: string }[] = []
  const sources: Record<string, number | string> = {}

  // Run the passive sources concurrently so a slow crt.sh doesn't add its
  // latency on top of certspotter/subfinder — the job finishes in max(sources)
  // rather than the sum, and one source failing never blocks the others.
  progress(`querying passive subdomain sources for ${domain.host}`)
  const [crtRes, csRes, sfRes] = await Promise.allSettled([
    crtShSubdomains(domain.host, signal),
    certSpotterSubdomains(domain.host, signal),
    subfinderSubdomains(domain.host, signal),
  ])

  // crt.sh (certificate transparency)
  if (crtRes.status === 'fulfilled') {
    for (const host of crtRes.value) discovered.push({ host, source: 'crtsh' })
    sources.crtsh = crtRes.value.length
  } else {
    sources.crtsh = `error: ${crtRes.reason instanceof Error ? crtRes.reason.message : String(crtRes.reason)}`
    log.warn({ domain: domain.host, err: crtRes.reason }, 'crt.sh discovery failed')
  }

  // certspotter (redundant CT source — covers crt.sh outages)
  if (csRes.status === 'fulfilled') {
    for (const host of csRes.value) discovered.push({ host, source: 'certspotter' })
    sources.certspotter = csRes.value.length
  } else {
    sources.certspotter = `error: ${csRes.reason instanceof Error ? csRes.reason.message : String(csRes.reason)}`
    log.warn({ domain: domain.host, err: csRes.reason }, 'certspotter discovery failed')
  }

  // subfinder (passive). Unavailable locally without the binary.
  if (sfRes.status === 'fulfilled') {
    if (sfRes.value.available) {
      for (const host of sfRes.value.hosts) discovered.push({ host, source: 'subfinder' })
      sources.subfinder = sfRes.value.hosts.length
    } else {
      sources.subfinder = 'unavailable (binary not installed)'
    }
  } else {
    sources.subfinder = `error: ${sfRes.reason instanceof Error ? sfRes.reason.message : String(sfRes.reason)}`
    log.warn({ domain: domain.host, err: sfRes.reason }, 'subfinder discovery failed')
  }

  const diff = diffAndStore(domainId, discovered)

  // Materialize newly-discovered hosts as durable assets (their IP + asn/cdn are
  // enriched later by the exposure scan, which upserts the same host asset).
  for (const host of diff.newHosts.slice(0, 1000)) upsertAsset({ domainId, kind: 'host', value: host })

  // Continuous validation: prioritize new hosts, then refresh the known web
  // estate so each monitoring run can detect response/technology changes. dnsx
  // and httpx are batch accelerators; both degrade to safe built-in behavior.
  const knownHosts = [domain.host, ...listSubdomains(domainId).map((row) => row.host)]
  const toProbe = [...new Set([...diff.newHosts, ...knownHosts])].slice(0, MAX_PROBE)
  progress(`validating DNS and HTTP for ${toProbe.length} host(s)`)
  const dnsx = await dnsxResolveHosts(toProbe, signal).catch((err) => {
    log.warn({ err }, 'dnsx validation failed; continuing with built-in DNS')
    return { available: false, records: new Map() }
  })
  const httpx = await httpxProbeHosts(toProbe, signal).catch((err) => {
    log.warn({ err }, 'httpx batch failed; continuing with empty observations')
    return { available: false, probes: [] }
  })
  sources.dnsx = dnsx.available ? dnsx.records.size : 'unavailable (using built-in resolver)'
  sources.httpx = httpx.available ? httpx.probes.filter((probe) => probe.status != null).length : 'unavailable (using built-in probe)'
  const probes = toProbe.map((host) => {
    const probe = httpx.probes.find((item) => item.host === host) ?? {
      host, scheme: null, status: null, title: null, server: null, ip: null, url: null,
      cnames: [], loginHint: false, apiHint: false, technologies: [], redirect: null,
      contentHash: null, contentLength: null,
    }
    const dns = dnsx.records.get(host)
    if (dns) {
      probe.ip ??= dns.a[0] ?? null
      probe.cnames = [...new Set([...probe.cnames, ...dns.cname])]
    }
    return probe
  })
  const probeByHost = new Map(probes.filter((p) => p.host).map((p) => [p.host, p]))

  // Stamp probe data for EVERY host we probed (probes[] is index-aligned with
  // toProbe). Crucially this writes probedAt even on failure (status null), so a
  // dead host is probed exactly once and never re-probed every discovery run.
  const changeAlerts: Promise<void>[] = []
  toProbe.forEach((host, i) => {
    const p = probes[i]
    updateProbe(domainId, host, {
      ip: p?.ip ?? null,
      status: p?.status ?? null,
      title: p?.title ?? null,
      server: p?.server ?? null,
      scheme: p?.scheme ?? null,
      loginHint: p?.loginHint ?? false,
    })
    if (p?.status != null) {
      const changes = recordAndDetectChanges(domainId, `host:${host}`, {
        up: true, title: p.title, status: p.status, server: p.server,
        redirect: p.redirect, tech: p.technologies,
        contentHash: p.contentHash, contentLength: p.contentLength,
      })
      if (changes.length) changeAlerts.push(alertChanges(domainId, `host:${host}`, [host], changes))
      upsertAsset({ domainId, kind: 'host', value: host, ip: p.ip })
    }
  })
  await Promise.all(changeAlerts)

  // Record + score each genuinely new subdomain as a finding (with probe data
  // and a passive takeover-candidate hint).
  const takeoverByHost = new Map<string, NonNullable<ReturnType<typeof detectTakeover>>>()
  for (const probe of probes) {
    const takeover = detectTakeover(probe.cnames, probe.status)
    if (takeover) takeoverByHost.set(probe.host, takeover)
  }
  const confirmedTakeovers = await mapLimit(
    [...takeoverByHost.entries()],
    4,
    async ([host, takeover]) => ({ host, takeover: { ...takeover, confirmed: await confirmTakeover(host, takeover.service, signal).catch(() => false) } }),
    null,
  )
  const confirmedByHost = new Map(confirmedTakeovers.filter((item): item is NonNullable<typeof item> => !!item).map((item) => [item.host, item.takeover]))
  const takeoverCount = takeoverByHost.size
  for (const host of diff.newHosts) {
    if (signal.aborted) throw signal.reason ?? new Error('subdomain discovery cancelled')
    const p = probeByHost.get(host)
    const takeover = confirmedByHost.get(host) ?? null
    const findingId = await addScoredFinding({
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
    linkAssetFinding(
      upsertAsset({ domainId, kind: 'host', value: host, ip: p?.ip ?? null }),
      findingId,
    )
  }

  // A provider resource can become dangling long after the hostname was first
  // discovered. Refresh the original stable finding whenever an existing host
  // becomes a takeover candidate, so monitoring catches that transition.
  for (const [host, takeover] of confirmedByHost) {
    if (diff.newHosts.includes(host)) continue
    const p = probeByHost.get(host)
    const findingId = await addScoredFinding({
      domainId,
      type: 'new_subdomain',
      data: {
        host, domain: domain.host, status: p?.status ?? null, title: p?.title ?? null,
        server: p?.server ?? null, ip: p?.ip ?? null, cnames: p?.cnames ?? [], takeover,
      },
      tags: ['new-subdomain', 'takeover-monitor'],
    })
    linkAssetFinding(upsertAsset({ domainId, kind: 'host', value: host, ip: p?.ip ?? null }), findingId)
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
