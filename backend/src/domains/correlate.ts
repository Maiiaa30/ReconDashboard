import { cdnForIp } from '../sources/cdn'
import { listFindings } from '../findings/store'
import { listSubdomains } from '../subdomains/store'

// Attack-path correlation: every piece (subdomains, IPs, ports, CVEs, ASN, cert
// fingerprint) is already collected but lands as separate finding rows. This
// joins them by shared IP into a prioritized, IP-centric asset view so the
// operator sees "admin.example.com -> 1.2.3.4 (AS…) -> :8080 -> CVE-x" without
// reconstructing it by eye. Read-only, pure joins over stored data. CDN edge IPs
// are excluded from host-linking so a shared Cloudflare IP doesn't over-link
// unrelated subdomains.

export interface AttackPath {
  ip: string
  cdn: string | null
  asn: string | null
  asnName: string | null
  hosts: string[]
  ports: number[]
  cveCount: number
  worstCvss: number | null
  kev: boolean
  score: number
}

export function correlateDomain(domainId: number): AttackPath[] {
  const exposures = listFindings({ domainId, type: 'exposure', limit: 5000 })
  const subs = listSubdomains(domainId)

  // Map IP -> hostnames from the subdomain inventory (skip CDN edges).
  const ipHosts = new Map<string, Set<string>>()
  for (const s of subs) {
    const ip = s.ipAddress
    if (!ip || cdnForIp(ip)) continue
    if (!ipHosts.has(ip)) ipHosts.set(ip, new Set())
    ipHosts.get(ip)!.add(s.host)
  }

  const paths: AttackPath[] = []
  for (const f of exposures) {
    const d = (f.data ?? {}) as any
    const ip = d.ip
    if (!ip) continue
    const cdn = cdnForIp(ip)
    const hosts = new Set<string>([...(Array.isArray(d.hostnames) ? d.hostnames : []), ...(ipHosts.get(ip) ?? [])])
    const cves: any[] = Array.isArray(d.cves) ? d.cves : []
    const worstCvss = cves.length ? Math.max(0, ...cves.map((c) => Number(c?.cvss_v3 ?? c?.cvss ?? 0))) : null
    paths.push({
      ip,
      cdn,
      asn: d.asn?.asn ?? null,
      asnName: d.asn?.asName ?? null,
      hosts: [...hosts],
      ports: Array.isArray(d.ports) ? d.ports : [],
      cveCount: Array.isArray(d.vulns) ? d.vulns.length : 0,
      worstCvss: worstCvss && worstCvss > 0 ? worstCvss : null,
      kev: cves.some((c) => c?.kev),
      score: f.score ?? 0,
    })
  }

  // Worst first: KEV, then CVSS, then the exposure score.
  return paths.sort(
    (a, b) => Number(b.kev) - Number(a.kev) || (b.worstCvss ?? 0) - (a.worstCvss ?? 0) || b.score - a.score,
  )
}
