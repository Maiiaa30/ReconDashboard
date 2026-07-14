import { randomUUID } from 'node:crypto'
import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { guardedFetchRaw } from '../../sources/guard'
import { BUILTIN_PARAMS, discoverParams, type Probe } from '../../sources/paramDiscovery'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import { knownUrlsFor } from './owaspActive'
import type { JobContext } from '../worker'

const PARAM_RE = /^[a-zA-Z0-9_.-]{1,40}$/
const UA = 'recon-dashboard/0.1 (+authorized param discovery)'

// Extract query-param names the target is already known to use (from the wayback/
// katana/finding URL corpus) — the highest-yield seeds for the candidate list.
function observedParams(domainId: number): string[] {
  const out = new Set<string>()
  for (const u of knownUrlsFor(domainId)) {
    const qi = typeof u === 'string' ? u.indexOf('?') : -1
    if (qi < 0) continue
    for (const pair of u.slice(qi + 1).split('&')) {
      const name = pair.split('=')[0]
      if (name && PARAM_RE.test(name)) out.add(name)
    }
  }
  return [...out]
}

export async function paramDiscoveryHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const target = String(params.target ?? domain.host)
  if (!isValidHostname(target) && !isValidDomain(target)) throw new Error(`invalid target: ${target}`)
  if (target !== domain.host && !hostBelongsToDomain(target, domain.host)) throw new Error(`target ${target} does not belong to ${domain.host}`)

  const scheme = params.scheme === 'http' ? 'http' : 'https'
  const path = typeof params.path === 'string' && /^\/[a-zA-Z0-9_./~-]{0,128}$/.test(params.path) ? params.path : '/'
  const baseUrl = `${scheme}://${target}${path}`

  progress(`discovering parameters on ${target}${path}`)

  // Guarded probe: append the candidate params as query args and return the
  // response. All egress goes through guardedFetchRaw (per-hop SSRF check).
  const probe: Probe = async (qp) => {
    let u: URL
    try {
      u = new URL(baseUrl)
    } catch {
      return null
    }
    for (const [k, v] of Object.entries(qp)) u.searchParams.set(k, v)
    const res = await guardedFetchRaw(u.toString(), { headers: { 'User-Agent': UA }, follow: true, timeoutMs: 9_000, maxBytes: 512 * 1024, signal })
    return res ? { status: res.status, body: res.body } : null
  }

  // Observed params first (most likely honored), then the built-in catalog.
  const candidates = [...new Set([...observedParams(domainId), ...BUILTIN_PARAMS])]
  const hits = await discoverParams(candidates, probe, { signal, runToken: randomUUID().replace(/-/g, '').slice(0, 8) })

  if (signal.aborted) {
    log.warn({ target }, 'param discovery aborted before persisting')
    return { target, aborted: true, found: hits.length }
  }

  for (const h of hits) {
    await addScoredFinding({
      domainId,
      type: 'param',
      data: {
        url: baseUrl,
        param: h.param,
        reason: h.reason,
        severity: 'info',
        title: `Hidden parameter honored: ${h.param}`,
        detail: h.evidence,
        _scoreReasons: [`${h.evidence} (${h.reason})`, 'undocumented parameters expand the attack surface — test for IDOR/SSRF/injection'],
      },
      tags: ['param', 'param-discovery', 'needs-review', `param:${h.reason}`, 'sev:info'],
    })
  }

  log.info({ target, path, candidates: candidates.length, found: hits.length }, 'param discovery complete')
  return { target, path, tested: candidates.length, found: hits.length, params: hits.map((h) => h.param) }
}
