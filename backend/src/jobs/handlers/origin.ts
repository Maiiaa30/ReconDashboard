import { getDomain } from '../../domains/store'
import { addFinding } from '../../findings/store'
import { cdnForIp, wafFromHeaders } from '../../sources/cdn'
import { resolveDns } from '../../sources/dns'
import { probeHost } from '../../sources/httpProbe'
import { originCandidates, probeOrigin } from '../../sources/origin'
import { listSubdomains } from '../../subdomains/store'
import { mapLimit } from '../../util/async'
import { isValidIp } from '../../util/validate'
import type { JobContext } from '../worker'

const MAX_CANDIDATES = 15

// "WAF/Cloudflare bypass" = legitimate origin-server discovery for an authorized
// target: find the real IP behind the CDN/WAF so authorized active scans hit the
// origin, not the edge. Detection is passive; verification connects directly to
// candidate IPs (the target's own infrastructure).
export async function originHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const host = domain.host

  // --- Is the apex behind a CDN/WAF? ---
  const apexDns = await resolveDns(host).catch(() => null)
  const apexIp = apexDns?.a[0] ?? null
  let provider: string | null = apexIp && isValidIp(apexIp) ? cdnForIp(apexIp) : null

  let baseline: { status: number | null; title: string | null } = { status: null, title: null }
  try {
    const controller = new AbortController()
    const t = setTimeout(() => controller.abort(), 8000)
    const res = await fetch(`https://${host}`, { redirect: 'manual', signal: controller.signal })
    clearTimeout(t)
    provider = provider ?? wafFromHeaders(res.headers)
    const b = await probeHost(host)
    baseline = { status: b.status, title: b.title }
  } catch {
    /* ignore */
  }

  // --- Gather candidate origin IPs (non-CDN) ---
  const ipPool = new Set<string>()
  for (const s of listSubdomains(domainId)) if (s.ipAddress) ipPool.add(s.ipAddress)
  for (const ip of apexDns?.a ?? []) ipPool.add(ip)
  // Mail servers frequently live on the origin infrastructure.
  for (const mx of apexDns?.mx ?? []) {
    const mxDns = await resolveDns(mx.exchange).catch(() => null)
    for (const ip of mxDns?.a ?? []) ipPool.add(ip)
  }

  const candidates = originCandidates([...ipPool]).slice(0, MAX_CANDIDATES)

  // --- Verify candidates by connecting directly with Host = domain ---
  const probed = await mapLimit(
    candidates,
    5,
    async (ip) => {
      const r = await probeOrigin(ip, host)
      // "Confirmed" if it served a page and looks like the same site.
      const titleMatch =
        !!r.title && !!baseline.title && r.title.toLowerCase() === baseline.title.toLowerCase()
      const confirmed = r.reachable && (titleMatch || (r.status != null && r.status < 400 && r.status > 0))
      return { ...r, cdn: cdnForIp(ip), titleMatch, confirmed }
    },
    { ip: '', reachable: false, scheme: null, status: null, title: null, server: null, cdn: null, titleMatch: false, confirmed: false },
  )

  const confirmed = probed.filter((p) => p.confirmed)
  const finding = {
    kind: 'origin',
    domain: host,
    behindCdn: Boolean(provider),
    provider: provider ?? null,
    apexIp,
    baseline,
    candidatesChecked: candidates.length,
    confirmedOrigins: confirmed.map((c) => ({ ip: c.ip, status: c.status, title: c.title, server: c.server })),
    allCandidates: probed.filter((p) => p.ip),
  }

  // Score: high if we found a real origin behind a CDN/WAF (it defeats the edge
  // protection for the authorized scan), else informational.
  const score = provider && confirmed.length ? 85 : confirmed.length ? 45 : provider ? 25 : 10
  const tags = ['origin', ...(provider ? [`waf:${provider}`] : []), ...(confirmed.length ? ['origin-found'] : [])]
  addFinding({ domainId, type: 'origin', data: finding, tags, score })

  log.info({ domain: host, provider, confirmed: confirmed.length }, 'origin scan complete')
  return { domain: host, provider, behindCdn: Boolean(provider), confirmedOrigins: confirmed.length, candidatesChecked: candidates.length }
}
