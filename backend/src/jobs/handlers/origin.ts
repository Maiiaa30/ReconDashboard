import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { cdnForIp, wafFromHeaders } from '../../sources/cdn'
import { resolveDns } from '../../sources/dns'
import { originCandidates, probeOrigin } from '../../sources/origin'
import { guardedFetchRaw } from '../../sources/guard'
import { listSubdomains } from '../../subdomains/store'
import { mapLimit } from '../../util/async'
import { isValidIp } from '../../util/validate'
import type { JobContext } from '../worker'

const MAX_CANDIDATES = 15

// "WAF/Cloudflare bypass" = legitimate origin-server discovery for an authorized
// target: find the real IP behind the CDN/WAF so authorized active scans hit the
// origin, not the edge. Detection is passive; verification connects directly to
// candidate IPs (the target's own infrastructure).
export async function originHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const host = domain.host

  // --- Is the apex behind a CDN/WAF? ---
  const apexDns = await resolveDns(host).catch(() => null)
  const apexIp = apexDns?.a[0] ?? null
  let provider: string | null = apexIp && isValidIp(apexIp) ? cdnForIp(apexIp) : null

  let baseline: { status: number | null; title: string | null; server: string | null } = { status: null, title: null, server: null }
  try {
    progress(`capturing the ${host} edge signature`)
    const res = await guardedFetchRaw(`https://${host}`, { follow: true, timeoutMs: 8_000, maxBytes: 64 * 1024, signal })
    if (res) {
      provider = provider ?? wafFromHeaders(res.headers)
      const title = (res.body.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]
      baseline = {
        status: res.status,
        title: title ? title.replace(/\s+/g, ' ').trim().slice(0, 200) : null,
        server: res.headers.get('server'),
      }
    }
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
      if (signal.aborted) throw new Error('origin scan cancelled')
      progress(`checking origin candidate ${ip}`)
      const r = await probeOrigin(ip, host, signal)
      // "Confirmed" if it served a page and looks like the same site.
      const titleMatch =
        !!r.title && !!baseline.title && r.title.toLowerCase() === baseline.title.toLowerCase()
      const signatureMatch = titleMatch || (
        !baseline.title && !!r.server && !!baseline.server &&
        r.server.toLowerCase() === baseline.server.toLowerCase() && r.status === baseline.status
      )
      const confirmed = r.reachable && signatureMatch
      return { ...r, cdn: cdnForIp(ip), titleMatch, signatureMatch, confirmed }
    },
    { ip: '', reachable: false, scheme: null, status: null, title: null, server: null, cdn: null, titleMatch: false, signatureMatch: false, confirmed: false },
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

  // Route through the scorer (scoreOrigin) so scoring lives in one place and the
  // finding carries _scoreReasons like every other type.
  await addScoredFinding({ domainId, type: 'origin', data: finding, tags: ['origin'] })

  log.info({ domain: host, provider, confirmed: confirmed.length }, 'origin scan complete')
  return { domain: host, provider, behindCdn: Boolean(provider), confirmedOrigins: confirmed.length, candidatesChecked: candidates.length }
}
