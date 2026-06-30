import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { enrichCves } from '../../sources/cvedb'
import { resolveDns } from '../../sources/dns'
import { internetDbLookup } from '../../sources/internetdb'
import { listSubdomains } from '../../subdomains/store'
import { isValidIp } from '../../util/validate'
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

  const records: unknown[] = []
  let exposedIps = 0

  for (const [ip, hostSet] of ipToHosts) {
    try {
      const rec = await internetDbLookup(ip)
      if (!rec) continue
      exposedIps++

      const cves = rec.vulns.length ? await enrichCves(rec.vulns) : []
      const finding = {
        ip,
        host: [...hostSet][0],
        hostnames: [...hostSet],
        ports: rec.ports,
        cpes: rec.cpes,
        tags: rec.tags,
        vulns: rec.vulns,
        cves,
      }
      records.push(finding)
      await addScoredFinding({ domainId, type: 'exposure', data: finding, tags: ['exposure'] })
    } catch (err) {
      log.warn({ ip, err }, 'internetdb lookup failed')
    }
  }

  return {
    domain: domain.host,
    hostsChecked: hosts.length,
    ipsResolved: ipToHosts.size,
    exposedIps,
    records,
  }
}
