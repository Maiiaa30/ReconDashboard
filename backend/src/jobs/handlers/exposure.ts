import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { alertNewCves, recordAndDetectNewCves, type AssetCve } from '../../findings/cveWatch'
import { asnLookup } from '../../sources/asn'
import { enrichCves } from '../../sources/cvedb'
import { resolveDns } from '../../sources/dns'
import { grabTlsCert } from '../../sources/tlsCert'
import { internetDbLookup } from '../../sources/internetdb'
import { diffAndStore, listSubdomains } from '../../subdomains/store'
import { hostBelongsToDomain, isValidIp } from '../../util/validate'
import { mapLimit } from '../../util/async'
import type { JobContext } from '../worker'

const MAX_HOSTS = 150
const MAX_IPS = 150

// Phase 3: "Shodan of each domain" — passive exposure via Shodan InternetDB
// (free, no key) + CVE enrichment via cvedb. No active scanning.
export async function exposureHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  // Build the host list: the apex + known subdomains (capped).
  const hosts = [domain.host, ...listSubdomains(domainId).map((s) => s.host)].slice(0, MAX_HOSTS)

  // Resolve hosts to IPs with bounded concurrency (one slow/timeout host no
  // longer adds its full timeout to the wall clock), remembering which hostnames
  // map to each IP.
  const resolved = await mapLimit(
    hosts,
    8,
    async (host) => {
      try {
        const dns = await resolveDns(host)
        return { host, ips: [...dns.a, ...dns.aaaa].filter(isValidIp) }
      } catch (err) {
        log.warn({ host, err }, 'dns resolution failed during exposure scan')
        return { host, ips: [] as string[] }
      }
    },
    { host: '', ips: [] as string[] },
  )
  const ipToHosts = new Map<string, Set<string>>()
  for (const { host, ips } of resolved) {
    for (const ip of ips) {
      if (!ipToHosts.has(ip)) {
        if (ipToHosts.size >= MAX_IPS) continue
        ipToHosts.set(ip, new Set())
      }
      ipToHosts.get(ip)!.add(host)
    }
  }

  // ASN/BGP enrichment for every resolved IP in one bulk Team Cymru query.
  const asnMap = await asnLookup([...ipToHosts.keys()])

  // InternetDB + CVE enrichment per IP, again with bounded concurrency. Kept
  // modest so we stay polite to the free InternetDB/cvedb endpoints. DB writes
  // inside each task are synchronous (better-sqlite3), so they don't interleave;
  // each IP is distinct, so the per-asset CVE baseline is race-free.
  const perIp = await mapLimit(
    [...ipToHosts.entries()],
    4,
    async ([ip, hostSet]) => {
      try {
        const rec = await internetDbLookup(ip)
        if (!rec) return null

        const cves = rec.vulns.length ? await enrichCves(rec.vulns) : []
        const asn = asnMap.get(ip) ?? null
        const finding = {
          ip,
          host: [...hostSet][0],
          hostnames: [...hostSet],
          ports: rec.ports,
          cpes: rec.cpes,
          tags: rec.tags,
          vulns: rec.vulns,
          cves,
          asn,
        }
        const asnTags = asn?.asn ? [`asn:${asn.asn}`] : []
        await addScoredFinding({ domainId, type: 'exposure', data: finding, tags: ['exposure', ...asnTags] })

        // "New CVE on a known asset" watch: rec.vulns is the authoritative CVE-id
        // set for this IP; enrich each with cvss/kev from the cvedb records. Record
        // + diff vs the asset's baseline, and alert on anything genuinely new.
        const cveMap = new Map(cves.map((c) => [c.cve_id, c]))
        const assetCveList: AssetCve[] = rec.vulns.map((id) => {
          const c = cveMap.get(id)
          return { id, cvss: c?.cvss_v3 ?? c?.cvss ?? null, kev: !!c?.kev }
        })
        const fresh = recordAndDetectNewCves(domainId, ip, assetCveList)
        if (fresh.length) await alertNewCves(domainId, ip, [...hostSet], fresh)
        return finding
      } catch (err) {
        log.warn({ ip, err }, 'internetdb enrichment failed')
        return null
      }
    },
    null,
  )

  const records: unknown[] = perIp.filter((r) => r !== null)
  const exposedIps = records.length

  // TLS certificate SAN harvest on the apex — SANs frequently reveal sibling
  // hostnames; in-scope ones are folded into the subdomain inventory.
  let cert = null
  try {
    cert = await grabTlsCert(domain.host)
    if (cert?.sans.length) {
      const inScope = cert.sans.filter((h) => h === domain.host || hostBelongsToDomain(h, domain.host))
      if (inScope.length) diffAndStore(domainId, inScope.map((host) => ({ host, source: 'tls-cert' })))
    }
  } catch (err) {
    log.warn({ err }, 'tls cert grab failed')
  }

  return {
    domain: domain.host,
    hostsChecked: hosts.length,
    ipsResolved: ipToHosts.size,
    exposedIps,
    asns: [...new Set([...asnMap.values()].map((a) => a.asn).filter(Boolean))],
    cert: cert ? { sans: cert.sans.length, fingerprint256: cert.fingerprint256, issuer: cert.issuer, validTo: cert.validTo } : null,
    records,
  }
}
