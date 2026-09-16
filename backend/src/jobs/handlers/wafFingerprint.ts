import { getDomain } from '../../domains/store'
import { listSubdomains, updateWaf } from '../../subdomains/store'
import { fingerprintWaf } from '../../sources/wafFingerprint'
import { assertPublicHost } from '../../sources/guard'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

// Bound the fan-out: wafw00f is an active probe per host, so a domain-wide run
// covers the live estate up to a cap, a few hosts at a time.
const MAX_HOSTS = 20
const CONCURRENCY = 4

// Derive the passive slug (e.g. 'cloudflare') from a brand label so the existing
// WAF badge/filter keeps working after a fingerprint fills the richer fields.
function slugFromBrand(brand: string | null): string | null {
  if (!brand) return null
  return brand.toLowerCase().split(/[\s(]/)[0] || null
}

// Identify the WAF in front of one host or the whole live estate and persist the
// brand/version/source on each subdomain. A per-host failure (unreachable,
// internal, wafw00f error) is logged and skipped — the run still completes.
export async function wafFingerprintHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const single = typeof params.target === 'string' && params.target ? String(params.target) : null
  let targets: { host: string; scheme: string }[]
  if (single) {
    if (!isValidHostname(single) && !isValidDomain(single)) throw new Error(`invalid target: ${single}`)
    if (single !== domain.host && !hostBelongsToDomain(single, domain.host)) {
      throw new Error(`target ${single} does not belong to authorized domain ${domain.host}`)
    }
    targets = [{ host: single, scheme: 'https' }]
  } else {
    // Live hosts only (probed = has an http_status), bounded.
    targets = listSubdomains(domainId)
      .filter((s) => s.httpStatus != null)
      .slice(0, MAX_HOSTS)
      .map((s) => ({ host: s.host, scheme: s.scheme === 'http' ? 'http' : 'https' }))
    if (targets.length === 0) targets = [{ host: domain.host, scheme: 'https' }]
  }

  let scanned = 0
  let detected = 0
  const queue = [...targets]
  const worker = async () => {
    while (queue.length) {
      if (signal?.aborted) return
      const t = queue.shift()!
      try {
        await assertPublicHost(t.host) // SSRF guard, per host
        const fp = await fingerprintWaf(t.scheme, t.host, signal)
        updateWaf(domainId, t.host, {
          brand: fp.detected ? fp.brand : null,
          version: fp.detected ? fp.version : null,
          source: fp.detected ? fp.source : null,
          slug: slugFromBrand(fp.detected ? fp.brand : null),
        })
        if (fp.detected) detected++
      } catch (err) {
        log.warn({ host: t.host, err }, 'waf fingerprint failed for host')
      }
      scanned++
      progress(`WAF fingerprint ${scanned}/${targets.length} — ${detected} identified`)
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, targets.length) }, worker))

  log.info({ domainId, scanned, detected }, 'waf fingerprint complete')
  return { planned: targets.length, scanned, detected }
}
