import { randomUUID } from 'node:crypto'
import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { guardedFetchRaw } from '../../sources/guard'
import { BUILTIN_PARAMS, discoverParams, HEADER_PARAMS, makeProbe, type ProbeFetch, type Transport } from '../../sources/paramDiscovery'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import { knownUrlsFor } from './owaspActive'
import type { JobContext } from '../worker'

const ALL_TRANSPORTS: readonly Transport[] = ['query', 'json', 'form', 'header']

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

  // Which transports to probe: query (default), plus JSON/form body and request
  // headers (mass-assignment / IDOR params live there). Operator-selectable.
  const requested = Array.isArray(params.transports)
    ? (params.transports as unknown[]).filter((t): t is Transport => ALL_TRANSPORTS.includes(t as Transport))
    : ALL_TRANSPORTS
  const transports = requested.length ? requested : ALL_TRANSPORTS

  // SSRF-guarded fetch the probe factory drives (per-hop check inside guardedFetchRaw).
  const doFetch: ProbeFetch = async (url, init) => {
    const res = await guardedFetchRaw(url, {
      method: init.method,
      headers: { 'User-Agent': UA, ...init.headers },
      body: init.body,
      follow: true,
      timeoutMs: 9_000,
      maxBytes: 512 * 1024,
      signal,
    })
    return res ? { status: res.status, body: res.body } : null
  }

  const queryish = [...new Set([...observedParams(domainId), ...BUILTIN_PARAMS])]
  const runToken = randomUUID().replace(/-/g, '').slice(0, 8)
  const hits: { param: string; reason: string; evidence: string; transport: Transport }[] = []
  let tested = 0

  for (const transport of transports) {
    if (signal.aborted) break
    progress(`discovering ${transport} parameters on ${target}${path}`)
    const candidates = transport === 'header' ? [...HEADER_PARAMS] : queryish
    tested += candidates.length
    const probe = makeProbe(transport, baseUrl, doFetch)
    const found = await discoverParams(candidates, probe, { signal, runToken })
    for (const h of found) hits.push({ ...h, transport })
  }

  if (signal.aborted) {
    log.warn({ target }, 'param discovery aborted before persisting')
    return { target, aborted: true, found: hits.length }
  }

  for (const h of hits) {
    const where = h.transport === 'query' ? 'query param' : h.transport === 'header' ? 'request header' : `${h.transport} body param`
    await addScoredFinding({
      domainId,
      type: 'param',
      data: {
        url: baseUrl,
        param: h.param,
        transport: h.transport,
        reason: h.reason,
        severity: 'info',
        title: `Hidden ${where} honored: ${h.param}`,
        detail: h.evidence,
        _scoreReasons: [`${h.evidence} (${h.reason}, ${h.transport})`, 'undocumented parameters expand the attack surface — test for IDOR/SSRF/mass-assignment/injection'],
      },
      // transport in the key so the same name found in query AND body dedupes apart.
      tags: ['param', 'param-discovery', 'needs-review', `param:${h.reason}`, `transport:${h.transport}`, 'sev:info'],
    })
  }

  log.info({ target, path, transports, tested, found: hits.length }, 'param discovery complete')
  return { target, path, transports, tested, found: hits.length, params: hits.map((h) => `${h.param} (${h.transport})`) }
}
