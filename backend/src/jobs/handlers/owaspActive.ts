import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { listFindings } from '../../findings/store'
import { jsRecon } from '../../sources/jsRecon'
import { runActiveChecks, type OwaspChecksOptions } from '../../owasp/activeChecks'
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

// All URL strings this target is known to have (wayback / commoncrawl / katana /
// prior findings) — the corpus for both param mining and JS recon.
export function knownUrlsFor(domainId: number): string[] {
  const findings = listFindings({ domainId, limit: 2000 })
  const urls: string[] = []
  for (const f of findings) {
    const d = f.data as any
    if (!d) continue
    if (Array.isArray(d?.wayback?.withParams)) urls.push(...d.wayback.withParams)
    if (Array.isArray(d?.wayback?.sample)) urls.push(...d.wayback.sample)
    if (Array.isArray(d?.commoncrawl?.withParams)) urls.push(...d.commoncrawl.withParams)
    if (Array.isArray(d?.commoncrawl?.sample)) urls.push(...d.commoncrawl.sample)
    if (f.type === 'tool' && Array.isArray(d.items)) urls.push(...d.items.filter((x: unknown) => typeof x === 'string'))
    if (typeof d.url === 'string') urls.push(d.url)
    if (typeof d.matched === 'string') urls.push(d.matched)
  }
  return [...new Set(urls)]
}

// OWASP active checks: direct HTTP probes (headers, sensitive files, reflected
// XSS, open redirect, CORS, TRACE, directory listing) that don't depend on
// nuclei. Authorization (active_authorized OR confirm) is enforced at the route
// before enqueue; here we re-check the target belongs to the domain.
export async function owaspActiveHandler({ params, log, progress }: JobContext) {
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
  try {
    progress(`mining JS files on ${target}`)
    const js = await jsRecon(knownUrlsFor(domainId))
    jsParams = js.params
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
