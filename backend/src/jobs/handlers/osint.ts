import { getDomain } from '../../domains/store'
import { recordCorpusUrls, type CorpusUrl } from '../../corpus/store'
import { addScoredFinding } from '../../findings/score'
import { addFinding } from '../../findings/store'
import { enumerateBuckets } from '../../sources/buckets'
import { certSpotterSubdomains } from '../../sources/certspotter'
import { crtShSubdomains } from '../../sources/crtsh'
import { resolveDns } from '../../sources/dns'
import { gatherDnsIntel } from '../../sources/dnsIntel'
import { fingerprintHost } from '../../sources/fingerprint'
import { commonCrawlUrls, type CommonCrawlResult } from '../../sources/commoncrawl'
import { internetDbLookup } from '../../sources/internetdb'
import { otxIntel, type OtxResult } from '../../sources/otx'
import { urlscanSearch, type UrlscanResult } from '../../sources/urlscan'
import { waybackUrls, type WaybackResult } from '../../sources/wayback'
import { whoisDomain } from '../../sources/whois'
import { zoneTransfer } from '../../sources/zoneTransfer'
import { diffAndStore } from '../../subdomains/store'
import { hostBelongsToDomain, isValidIp } from '../../util/validate'
import type { JobContext } from '../worker'

// Phase 4: OSINT / info center. One screen's worth of passive intel about a
// target, aggregated from several sources. All passive.
export async function osintHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const host = domain.host

  const result: Record<string, unknown> = { domain: host }

  // DNS
  try {
    result.dns = await resolveDns(host)
  } catch (err) {
    result.dns = { error: err instanceof Error ? err.message : String(err) }
    log.warn({ host, err }, 'osint dns failed')
  }

  // WHOIS
  try {
    result.whois = await whoisDomain(host)
  } catch (err) {
    result.whois = { error: err instanceof Error ? err.message : String(err) }
    log.warn({ host, err }, 'osint whois failed')
  }

  // Certificate transparency (subdomain breadth): crt.sh first, falling back to
  // certspotter (the same CT data from a more reliable API) when crt.sh is slow
  // or down — so this card shows results instead of a timeout error.
  try {
    let ctHosts: string[]
    let source = 'crt.sh'
    try {
      ctHosts = await crtShSubdomains(host)
    } catch (err) {
      log.warn({ host, err }, 'crt.sh failed, falling back to certspotter')
      ctHosts = await certSpotterSubdomains(host)
      source = 'certspotter (crt.sh unavailable)'
    }
    result.crtsh = { count: ctHosts.length, sample: ctHosts.slice(0, 50), source }
  } catch (err) {
    result.crtsh = { error: err instanceof Error ? err.message : String(err) }
  }

  // DNS zone transfer (AXFR) against the zone's nameservers.
  try {
    const dns = result.dns as { ns?: string[] } | undefined
    const ns = dns?.ns ?? []
    if (ns.length) {
      const zt = await zoneTransfer(host, ns)
      result.zoneTransfer = zt
      if (zt.vulnerable) {
        addFinding({
          domainId,
          type: 'osint',
          data: { kind: 'zone_transfer', domain: host, servers: zt.servers, sample: zt.sample },
          tags: ['zone-transfer', 'misconfig', 'critical'],
          score: 90,
        })
      }
    }
  } catch (err) {
    result.zoneTransfer = { error: err instanceof Error ? err.message : String(err) }
  }

  // InternetDB for the apex's first IP
  try {
    const dns = result.dns as { a?: string[] } | undefined
    const ip = dns?.a?.[0]
    if (ip && isValidIp(ip)) {
      result.internetdb = await internetDbLookup(ip)
    }
  } catch (err) {
    result.internetdb = { error: err instanceof Error ? err.message : String(err) }
  }

  // Passive URL / intel sources — Wayback, Common Crawl, urlscan.io and OTX —
  // gathered concurrently (independent, each best-effort with its own timeout).
  const [wayback, commoncrawl, urlscan, otx] = await Promise.allSettled([
    waybackUrls(host),
    commonCrawlUrls(host),
    urlscanSearch(host),
    otxIntel(host),
  ])
  const settle = (r: PromiseSettledResult<unknown>) =>
    r.status === 'fulfilled' ? r.value : { error: r.reason instanceof Error ? r.reason.message : String(r.reason) }
  const wb = settle(wayback) as WaybackResult | { error: string }
  const cc = settle(commoncrawl) as CommonCrawlResult | { error: string }
  const us = settle(urlscan) as UrlscanResult | { error: string }
  const ox = settle(otx) as OtxResult | { error: string }

  // Persist the FULL URL corpus (thousands of URLs) to url_corpus so the whole
  // attack surface reaches JS-recon / param-discovery / OWASP — the finding blob
  // keeps only a small display sample. urlscan pages and OTX urls are folded in
  // (they were collected then dropped before).
  const corpus: CorpusUrl[] = []
  if (!('error' in wb)) corpus.push(...wb.urls.map((url) => ({ url, source: 'wayback' })))
  if (!('error' in cc)) corpus.push(...cc.urls.map((url) => ({ url, source: 'commoncrawl' })))
  if (!('error' in us)) corpus.push(...us.pages.map((p) => ({ url: p.url, source: 'urlscan' })))
  if (!('error' in ox)) corpus.push(...ox.urls.map((url) => ({ url, source: 'otx' })))
  try {
    const added = recordCorpusUrls(domainId, corpus)
    log.info({ host, collected: corpus.length, added }, 'url corpus persisted')
  } catch (err) {
    log.warn({ host, err }, 'url corpus persist failed')
  }

  // OTX passive-DNS hostnames → subdomain inventory (in-scope only). These are
  // historical hostname→IP observations that never re-entered discovery; folding
  // them in gets new-host diffing/alerting for free (same as the cert-SAN fold).
  if (!('error' in ox) && ox.passiveDns.length) {
    try {
      const inScope = [...new Set(ox.passiveDns.map((d) => d.hostname.toLowerCase()))].filter(
        (h) => h === host || hostBelongsToDomain(h, host),
      )
      if (inScope.length) {
        const res = diffAndStore(domainId, inScope.map((h) => ({ host: h, source: 'otx-dns' })))
        if (res.newHosts.length) log.info({ host, newHosts: res.newHosts.length }, 'osint: new subdomains from OTX passive DNS')
      }
    } catch (err) {
      log.warn({ host, err }, 'otx passive-dns fold failed')
    }
  }

  // Store trimmed copies in the finding blob (drop the big `urls` arrays).
  result.wayback = 'error' in wb ? wb : { count: wb.count, sample: wb.sample, withParams: wb.withParams }
  result.commoncrawl = 'error' in cc ? cc : { indexes: cc.indexes, count: cc.count, truncated: cc.truncated, sample: cc.sample, withParams: cc.withParams }
  result.urlscan = 'error' in us ? us : { count: us.count, pages: us.pages.slice(0, 50) }
  result.otx = 'error' in ox ? ox : { passiveDns: ox.passiveDns, urlCount: ox.urlCount, urls: ox.urls.slice(0, 50) }

  // Technology fingerprint: OS, server, and stack from HTTP headers/cookies/HTML,
  // enriched with any CPEs InternetDB surfaced for the apex IP.
  try {
    const idb = result.internetdb as { cpes?: string[] } | { error: string } | undefined
    const cpes = idb && !('error' in idb) ? idb.cpes ?? [] : []
    result.tech = await fingerprintHost(host, cpes)
  } catch (err) {
    result.tech = { error: err instanceof Error ? err.message : String(err) }
    log.warn({ host, err }, 'osint fingerprint failed')
  }

  // Cloud storage buckets derived from the domain name (keyless; requests go to
  // AWS/GCP/Azure, not the target). Open buckets are high-value findings.
  try {
    const buckets = await enumerateBuckets(host)
    const open = buckets.filter((b) => b.state === 'open')
    const locked = buckets.filter((b) => b.state === 'locked')
    result.buckets = { open: open.map((b) => b.url), locked: locked.map((b) => b.url) }
    for (const b of open) {
      await addScoredFinding({
        domainId,
        type: 'tool',
        data: {
          tool: 'bucket',
          target: b.name,
          severity: 'high',
          title: `Open ${b.provider.toUpperCase()} bucket: ${b.name}`,
          detail: `Publicly listable/readable at ${b.url}`,
          items: [b.url],
        },
        tags: ['bucket', b.provider, 'exposure', 'sev:high'],
      })
    }
  } catch (err) {
    result.buckets = { error: err instanceof Error ? err.message : String(err) }
  }

  // SPF / DMARC / CAA intel from the raw TXT/CAA already resolved above. Weak
  // policy = spoofable (osint findings); SPF ip4:/ip6: ranges become infra pivots.
  try {
    const dns = result.dns as { txt?: string[]; caa?: string[] } | undefined
    if (dns && !('error' in (dns as object))) {
      const intel = await gatherDnsIntel(host, dns.txt ?? [], dns.caa ?? [], async (h) => (await resolveDns(h)).txt)
      result.dnsIntel = { spf: intel.spf, dmarc: intel.dmarc, caaIssuers: intel.caaIssuers, candidateRanges: intel.candidateRanges }
      for (const f of intel.findings) {
        addFinding({
          domainId,
          type: 'osint',
          data: { kind: f.kind, domain: host, name: f.name, severity: f.severity, evidence: f.evidence, _scoreReasons: [f.evidence] },
          tags: ['osint', 'dns-intel', `sev:${f.severity}`],
          score: f.score,
        })
      }
    }
  } catch (err) {
    log.warn({ host, err }, 'osint dns-intel failed')
  }

  await addScoredFinding({ domainId, type: 'osint', data: result, tags: ['osint'] })

  return result
}
