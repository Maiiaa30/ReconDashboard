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

  // Resolve each host to IPs, remembering which hostnames map to each IP.
  const ipToHosts = new Map<string, Set<string>>()
  for (const host of hosts) {
    try {
      const dns = await resolveDns(host)
      for (const ip of [...dns.a, ...dns.aaaa]) {
        if (!isValidIp(ip)) continue
        if (!ipToHosts.has(ip)) ipToHosts.set(ip, new Set())
        ipToHosts.get(ip)!.add(host)
      }
    } catch (err) {
      log.warn({ host, err }, 'dns resolution failed during exposure scan')
    }
    if (ipToHosts.size >= MAX_IPS) break
  }

  // ASN/BGP enrichment for every resolved IP in one bulk Team Cymru query.
  const asnMap = await asnLookup([...ipToHosts.keys()])

  const records: unknown[] = []
  let exposedIps = 0

  for (const [ip, hostSet] of ipToHosts) {
    try {
      const rec = await internetDbLookup(ip)
      if (!rec) continue
      exposedIps++

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
      records.push(finding)
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
    } catch (err) {
      log.warn({ ip, err }, 'internetdb lookup failed')
    }
  }

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
