import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { listFindings } from '../../findings/store'
import { listCaptures } from '../../capture/store'
import { getCorpusUrls } from '../../corpus/store'
import { jsRecon } from '../../sources/jsRecon'
import { runActiveChecks, type OwaspChecksOptions } from '../../owasp/activeChecks'
import { analyzeJwtToken, findJwts } from '../../owasp/jwt'
import { safeJsonParse } from '../../util/json'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

const PARAM_RE = /^[a-zA-Z0-9_.[\]-]{1,64}$/

// Collect query-parameter names from URL strings.
function paramsFromUrls(urls: string[]): string[] {
  const out = new Set<string>()
  for (const u of urls) {
    const qi = typeof u === 'string' ? u.indexOf('?') : -1
    if (qi < 0) continue
    for (const pair of u.slice(qi + 1).split('&')) {
      const name = pair.split('=')[0]
      if (name && PARAM_RE.test(name)) out.add(name)
    }
  }
  return [...out]
}

// Pull the real query params this target is known to use, from URLs discovered
// by Wayback / Common Crawl / katana / ffuf / prior findings. This is what makes
// the checks "per target" — XSS/redirect probes hit parameters the app uses.
function discoveredParamsFor(domainId: number): string[] {
  return paramsFromUrls(knownUrlsFor(domainId)).slice(0, 40)
}

// All URL strings this target is known to have — the corpus for param mining and
// JS recon. The bulk comes from the persisted url_corpus (the full Wayback /
// Common Crawl / urlscan / OTX set, thousands of URLs); we still fold in the
// dynamic URLs the corpus doesn't hold: katana/ffuf tool hits and any url/matched
// on other findings. (Also reads the legacy wayback/commoncrawl blob samples as a
// fallback for domains scanned before the corpus table existed.)
export function knownUrlsFor(domainId: number): string[] {
  const urls = new Set<string>(getCorpusUrls(domainId, { limit: 20_000 }))
  const findings = listFindings({ domainId, limit: 2000 })
  for (const f of findings) {
    const d = f.data as any
    if (!d) continue
    if (f.type === 'tool' && Array.isArray(d.items)) for (const x of d.items) if (typeof x === 'string') urls.add(x)
    if (typeof d.url === 'string') urls.add(d.url)
    if (typeof d.matched === 'string') urls.add(d.matched)
    // Legacy fallback: pre-corpus osint findings kept ~50 URLs in their blob.
    for (const arr of [d?.wayback?.withParams, d?.wayback?.sample, d?.commoncrawl?.withParams, d?.commoncrawl?.sample]) {
      if (Array.isArray(arr)) for (const u of arr) if (typeof u === 'string') urls.add(u)
    }
  }
  return [...urls]
}

// Gather JWTs the tool already holds — the operator's auth header, JWTs mined
// from JS, and tokens seen in captured requests — mapped to a short source label
// (first source wins). Passive: reads local data only, no target traffic.
function gatherTokens(domainId: number, authHeader: string | undefined, jsJwts: string[]): Map<string, string> {
  const tokens = new Map<string, string>() // token -> source label
  const add = (token: string, source: string) => {
    if (!tokens.has(token)) tokens.set(token, source)
  }
  for (const t of findJwts(authHeader ?? '')) add(t, 'owaspConfig.authHeader')
  for (const t of jsJwts) add(t, 'JS bundle')
  for (const cap of listCaptures({ domainId, limit: 200 })) {
    const path = (() => {
      try {
        return new URL(cap.url).pathname
      } catch {
        return cap.url.slice(0, 60)
      }
    })()
    const source = `capture:${cap.method} ${path}`
    for (const [, value] of cap.headers) for (const t of findJwts(value)) add(t, source)
    for (const t of findJwts(cap.url)) add(t, source)
  }
  return tokens
}

// OWASP active checks: direct HTTP probes (headers, sensitive files, reflected
// XSS, open redirect, CORS, TRACE, directory listing) that don't depend on
// nuclei. Authorization (active_authorized OR confirm) is enforced at the route
// before enqueue; here we re-check the target belongs to the domain.
export async function owaspActiveHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const target = String(params.target ?? domain.host)
  if (!isValidHostname(target) && !isValidDomain(target)) throw new Error(`invalid target: ${target}`)
  if (target !== domain.host && !hostBelongsToDomain(target, domain.host)) {
    throw new Error(`target ${target} does not belong to authorized domain ${domain.host}`)
  }
  const scheme = params.scheme === 'http' ? 'http' : 'https'

  // JS recon: mine discovered .js files for endpoints, params and leaked secrets.
  // The params feed straight back into the target-aware checks below.
  let jsParams: string[] = []
  let jsJwts: string[] = []
  try {
    progress(`mining JS files on ${target}`)
    const js = await jsRecon(knownUrlsFor(domainId))
    jsParams = js.params
    // JWTs mined from JS — but only untruncated samples (a clipped token can't be
    // decoded or cracked).
    jsJwts = js.secrets.filter((s) => s.pattern === 'JWT' && !s.sample.includes('…')).map((s) => s.sample)
    if (js.secrets.length) {
      await addScoredFinding({
        domainId,
        type: 'tool',
        data: {
          tool: 'jsrecon',
          target,
          severity: 'high',
          title: `${js.secrets.length} potential secret(s) in JavaScript`,
          detail: `Scanned ${js.filesScanned} JS file(s) — verify each match`,
          items: js.secrets.map((s) => `${s.pattern}: ${s.sample} (${s.file})`),
        },
        tags: ['jsrecon', 'secret', 'needs-review', 'sev:high'],
      })
    }
    if (js.endpoints.length) {
      await addScoredFinding({
        domainId,
        type: 'tool',
        data: {
          tool: 'jsrecon',
          target,
          severity: 'info',
          title: `${js.endpoints.length} endpoint(s) referenced in JavaScript`,
          detail: `From ${js.filesScanned} JS file(s)`,
          items: js.endpoints.slice(0, 100),
        },
        tags: ['jsrecon', 'endpoints', 'sev:info'],
      })
    }
  } catch (err) {
    log.warn({ err }, 'js recon failed')
  }

  // Per-target tuning: operator's custom config + auto-discovered params.
  const cfg = safeJsonParse<OwaspChecksOptions>(domain.owaspConfig, {})
  const opts: OwaspChecksOptions = {
    xssParams: cfg.xssParams,
    xssPayloads: cfg.xssPayloads,
    redirectParams: cfg.redirectParams,
    sensitivePaths: cfg.sensitivePaths,
    authHeader: cfg.authHeader,
    discoveredParams: [...new Set([...discoveredParamsFor(domainId), ...jsParams])],
    jwtSecrets: cfg.jwtSecrets,
    signal,
  }

  // Passive JWT analysis + offline HMAC crack over the tokens we already hold.
  // Zero target traffic; a cracked secret is self-verifying proof, so these are
  // among the highest-signal findings the tool produces.
  try {
    const tokens = gatherTokens(domainId, cfg.authHeader, jsJwts)
    let jwtFindings = 0
    for (const [token, source] of tokens) {
      // A short token fingerprint keeps distinct tokens from the same source from
      // collapsing under the owasp dedupe key (owasp:cat:name@url).
      const fp = token.slice(-6)
      for (const f of analyzeJwtToken(token, source, cfg.jwtSecrets ?? [])) {
        await addScoredFinding({
          domainId,
          type: 'owasp',
          data: { target, category: 'A07', name: f.name, severity: f.severity, url: `${source} [${fp}]`, evidence: f.evidence },
          tags: ['owasp', 'jwt', 'owasp:A07', `sev:${f.severity}`, ...(f.name.includes('cracked') ? ['cracked'] : [])],
        })
        jwtFindings++
      }
    }
    if (jwtFindings) log.info({ target, tokens: tokens.size, jwtFindings }, 'jwt analysis complete')
  } catch (err) {
    log.warn({ err }, 'jwt analysis failed')
  }

  progress(`running active checks on ${target}`)
  const { findings, reachable, targetedParams } = await runActiveChecks(scheme, target, opts)
  if (!reachable) {
    log.warn({ target }, 'owasp active checks: target not reachable / internal')
    return { reachable: false, target, count: 0 }
  }

  for (const f of findings) {
    await addScoredFinding({
      domainId,
      type: 'owasp',
      data: { target, category: f.category, name: f.name, severity: f.severity, url: f.url, evidence: f.evidence, repro: f.repro },
      tags: ['owasp', 'active', `owasp:${f.category}`, `sev:${f.severity}`],
    })
  }

  log.info({ target, findings: findings.length, targetedParams }, 'owasp active checks complete')
  return {
    reachable: true,
    target,
    count: findings.length,
    targetedParams,
    categories: [...new Set(findings.map((f) => f.category))],
  }
}
