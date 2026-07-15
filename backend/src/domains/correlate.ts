import { cdnForIp } from '../sources/cdn'
import { listFindings } from '../findings/store'
import { listAssets } from '../assets/store'

// Attack-path correlation: the host->IP->ports/CVEs/ASN graph. It is now backed by
// the durable `assets` table (host cross-linking + asn/cdn come from asset rows),
// joined with the exposure findings for the volatile per-IP detail (ports/CVEs).
// Read-only; CDN edge IPs are excluded from host-linking so a shared Cloudflare IP
// doesn't over-link unrelated subdomains. Cached per domain (the Intel page + the
// advisor both call this, and each call otherwise re-scans up to 5000 findings).

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

const cache = new Map<number, { at: number; data: AttackPath[] }>()
const TTL_MS = 8_000

// Drop a domain's cached correlation (call after new exposure/asset data lands).
export function invalidateCorrelation(domainId: number): void {
  cache.delete(domainId)
}

export function correlateDomain(domainId: number): AttackPath[] {
  const now = Date.now()
  const hit = cache.get(domainId)
  if (hit && now - hit.at < TTL_MS) return hit.data
  const data = buildCorrelation(domainId)
  cache.set(domainId, { at: now, data })
  return data
}

function buildCorrelation(domainId: number): AttackPath[] {
  const assets = listAssets(domainId)
  const ipAssets = assets.filter((a) => a.kind === 'ip')
  const cdnIps = new Set(ipAssets.filter((a) => a.cdn).map((a) => a.ip ?? a.value))

  // Hosts per IP from the durable host assets (skip CDN edges — don't over-link).
  const hostsByIp = new Map<string, Set<string>>()
  for (const a of assets) {
    if (a.kind !== 'host' || !a.ip || cdnIps.has(a.ip)) continue
    if (!hostsByIp.has(a.ip)) hostsByIp.set(a.ip, new Set())
    hostsByIp.get(a.ip)!.add(a.value)
  }

  // Volatile per-IP detail (ports/CVEs/score) still lives on the exposure finding.
  const expByIp = new Map<string, { data: any; score: number }>()
  for (const f of listFindings({ domainId, type: 'exposure', limit: 5000 })) {
    const ip = (f.data as any)?.ip
    if (ip) expByIp.set(ip, { data: f.data ?? {}, score: f.score ?? 0 })
  }

  const ipAssetByIp = new Map(ipAssets.map((a) => [a.ip ?? a.value, a]))
  // Union of asset IPs + exposure-finding IPs, so a domain scanned before the
  // assets table existed still renders until its next exposure scan populates it.
  const allIps = new Set<string>([...ipAssetByIp.keys(), ...expByIp.keys()])

  const paths: AttackPath[] = []
  for (const ip of allIps) {
    const asset = ipAssetByIp.get(ip)
    const exp = expByIp.get(ip)
    const d = (exp?.data ?? {}) as any
    const cdn = asset?.cdn ?? cdnForIp(ip)
    const hosts = new Set<string>([...(Array.isArray(d.hostnames) ? d.hostnames : []), ...(hostsByIp.get(ip) ?? [])])
    const cves: any[] = Array.isArray(d.cves) ? d.cves : []
    const worstCvss = cves.length ? Math.max(0, ...cves.map((c) => Number(c?.cvss_v3 ?? c?.cvss ?? 0))) : null
    paths.push({
      ip,
      cdn,
      asn: asset?.asn ?? d.asn?.asn ?? null,
      asnName: asset?.asnName ?? d.asn?.asName ?? null,
      hosts: [...hosts],
      ports: Array.isArray(d.ports) ? d.ports : [],
      cveCount: Array.isArray(d.vulns) ? d.vulns.length : 0,
      worstCvss: worstCvss && worstCvss > 0 ? worstCvss : null,
      kev: cves.some((c) => c?.kev),
      score: exp?.score ?? 0,
    })
  }

  // Worst first: KEV, then CVSS, then the exposure score.
  return paths.sort((a, b) => Number(b.kev) - Number(a.kev) || (b.worstCvss ?? 0) - (a.worstCvss ?? 0) || b.score - a.score)
}
