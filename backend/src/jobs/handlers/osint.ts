import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { addFinding } from '../../findings/store'
import { certSpotterSubdomains } from '../../sources/certspotter'
import { crtShSubdomains } from '../../sources/crtsh'
import { resolveDns } from '../../sources/dns'
import { fingerprintHost } from '../../sources/fingerprint'
import { internetDbLookup } from '../../sources/internetdb'
import { waybackUrls } from '../../sources/wayback'
import { whoisDomain } from '../../sources/whois'
import { zoneTransfer } from '../../sources/zoneTransfer'
import { isValidIp } from '../../util/validate'
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

  // Wayback Machine archived URLs (historical endpoints + params to test).
  try {
    result.wayback = await waybackUrls(host)
  } catch (err) {
    result.wayback = { error: err instanceof Error ? err.message : String(err) }
  }

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

  await addScoredFinding({ domainId, type: 'osint', data: result, tags: ['osint'] })

  return result
}
