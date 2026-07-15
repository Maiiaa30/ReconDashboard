import { getDomain } from '../../domains/store'
import { resolveDns } from '../../sources/dns'
import { buildPermutationCandidates, bruteResolve, isWildcardZone, type ResolveFn } from '../../sources/dnsPermute'
import { diffAndStore, listSubdomains } from '../../subdomains/store'
import type { JobContext } from '../worker'

// dns_permute: PASSIVE (DNS lookups only, no target HTTP) name permutation +
// brute-resolve. Generates candidates from the wordlist + existing inventory,
// then resolves them via public resolvers with bounded concurrency. A mandatory
// wildcard-zone guard runs first so a catch-all zone can't flood the inventory.
// Not loud, not scheduled (operator-triggered; DNS brute is low-noise but the
// spec's default is conservative). Honors ctx.signal.

const MAX_CANDIDATES = 1500
const CONCURRENCY = 12

export async function dnsPermuteHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const resolve: ResolveFn = async (host) => {
    if (signal.aborted) return []
    try {
      const r = await resolveDns(host)
      return [...r.a, ...r.aaaa]
    } catch {
      return []
    }
  }

  progress('checking for wildcard DNS')
  const wc = await isWildcardZone(domain.host, resolve)
  if (wc.wildcard) {
    log.info({ host: domain.host, wildcardIps: wc.ips }, 'dns_permute: wildcard zone — skipping brute-force')
    return { host: domain.host, wildcard: true, tested: 0, added: 0 }
  }
  if (signal.aborted) return { host: domain.host, aborted: true, added: 0 }

  const existing = listSubdomains(domainId).map((s) => s.host)
  const candidates = buildPermutationCandidates(domain.host, existing, { max: MAX_CANDIDATES })
  progress(`resolving ${candidates.length} permutation candidate(s)`)
  const hits = await bruteResolve(candidates, resolve, { concurrency: CONCURRENCY, wildcardIps: wc.ips })

  if (signal.aborted) return { host: domain.host, aborted: true, added: 0 }

  let added = 0
  if (hits.length) {
    added = diffAndStore(domainId, hits.map((h) => ({ host: h.host, source: 'dns-permute' }))).newHosts.length
  }
  log.info({ host: domain.host, tested: candidates.length, resolved: hits.length, added }, 'dns_permute complete')
  return { host: domain.host, wildcard: false, tested: candidates.length, resolved: hits.length, added }
}
