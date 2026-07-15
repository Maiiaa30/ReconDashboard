import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { findingByKey, linkFindings, recordCveVerification } from '../../findings/store'
import { assertPublicHost } from '../../sources/guard'
import { run, toolExists } from '../../util/exec'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

// Nuclei-driven CVE verification. cveWatch produces `cve_new` findings from
// PASSIVE Shodan/InternetDB signal — "an IP runs a CPE with CVE-X." That is
// presence, not proof (banners lie, distros backport fixes). This runs the exact
// matching nuclei template to turn presence into CONFIRMED-exploitable, attaches
// the PoC as evidence, and upgrades the originating cve_new finding in place.
//
// LOUD + gated: enqueued only from POST /api/domains/:id/verify-cve behind
// assertScanAllowed (long cooldown). Never fired by cveWatch, exposure, chains,
// or the scheduler — a negative result must never silently re-run at a target.

// Strict CVE id — validated before it ever reaches argv (argv-only, no shell,
// same posture as the other scanners). Rejects anything that isn't CVE-YYYY-NNNN+.
const CVE_ID_RE = /^CVE-\d{4}-\d{4,10}$/i

export type VerifyResult = 'confirmed' | 'not_reproduced' | 'no_template'

// nuclei prints template-load diagnostics to stderr. When an -id matches no
// installed template it loads zero and says so — that's "no template exists",
// which must be distinguished from "template ran but did not match" so a missing
// template is never read as "not vulnerable".
function looksLikeNoTemplate(stderr: string): boolean {
  return (
    /Templates loaded for current scan:\s*0\b/i.test(stderr) ||
    /No templates? (?:provided|found|were found)/i.test(stderr) ||
    /could not find templates/i.test(stderr)
  )
}

// Pure classification of a verification run. Kept separate (and exported) so the
// three-way outcome — the subtle part, since a missing template and a
// non-reproducing one both yield zero matches — is unit-testable without nuclei.
export function classifyCveVerify(matchCount: number, stderr: string): VerifyResult {
  if (matchCount > 0) return 'confirmed'
  return looksLikeNoTemplate(stderr) ? 'no_template' : 'not_reproduced'
}

export async function cveVerifyHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const target = String(params.target ?? domain.host)
  if (!isValidHostname(target) && !isValidDomain(target)) throw new Error(`invalid target: ${target}`)
  if (target !== domain.host && !hostBelongsToDomain(target, domain.host)) {
    throw new Error(`target ${target} does not belong to authorized domain ${domain.host}`)
  }
  // SSRF: an in-scope subdomain whose DNS the target controls could resolve to an
  // internal/Tailscale address — refuse before nuclei touches it.
  await assertPublicHost(target)

  const cveId = String(params.cveId ?? '').toUpperCase()
  if (!CVE_ID_RE.test(cveId)) throw new Error(`invalid CVE id: ${params.cveId}`)
  const ip = typeof params.ip === 'string' ? params.ip : undefined
  const kev = params.kev === true

  if (!(await toolExists('nuclei'))) {
    return { available: false, note: 'nuclei binary not installed' }
  }

  const scheme = params.scheme === 'http' ? 'http' : 'https'
  const url = `${scheme}://${target}`

  // One nuclei run with the given selector args; parses the JSONL matches and
  // returns them plus stderr (which carries the "0 templates loaded" diagnostic).
  const baseArgs = ['-u', url, '-jsonl', '-silent', '-no-color']
  const runOnce = async (extra: string[]): Promise<{ matches: any[]; stderr: string }> => {
    let stdout = ''
    let stderr = ''
    try {
      const res = await run('nuclei', [...baseArgs, ...extra], { timeoutMs: 600_000, signal })
      stdout = res.stdout
      stderr = res.stderr
    } catch (err) {
      const e = err as Error & { stdout?: string; stderr?: string }
      stdout = e.stdout ?? ''
      stderr = e.stderr ?? ''
      if (!stdout && !stderr) throw err
    }
    const matches: any[] = []
    for (const line of stdout.split('\n')) {
      const t = line.trim()
      if (!t) continue
      try {
        matches.push(JSON.parse(t))
      } catch {
        /* ignore non-JSON diagnostic lines */
      }
    }
    return { matches, stderr }
  }

  // Primary: run ONLY the template(s) whose id is this CVE (argv-only; validated).
  progress(`verifying ${cveId} against ${target} with nuclei (-id)`)
  let { matches, stderr } = await runOnce(['-id', cveId])
  let selector = 'id'

  // Fallback: for the minority where template-id ≠ CVE-id, -id loads nothing.
  // Retry once filtering by the CVE tag before concluding "no template exists".
  if (!signal.aborted && classifyCveVerify(matches.length, stderr) === 'no_template') {
    progress(`no template for -id ${cveId}; retrying via -tags`)
    const retry = await runOnce(['-tags', cveId.toLowerCase()])
    // Adopt the retry only if it actually loaded a template (matched, or ran but
    // didn't reproduce) — a still-empty load leaves the original no_template.
    if (retry.matches.length > 0 || !looksLikeNoTemplate(retry.stderr)) {
      matches = retry.matches
      stderr = retry.stderr
      selector = 'tags'
    }
  }

  if (signal.aborted) {
    log.warn({ target, cveId }, 'cve verify aborted before persisting; discarding')
    return { available: true, aborted: true, target, cveId }
  }

  const result = classifyCveVerify(matches.length, stderr)
  const at = new Date().toISOString()

  // Locate the passive cve_new finding this verification is about, so we can
  // annotate (any result) or upgrade it (confirmed). Keyed cvenew:${ip}:${cveId}.
  const existing = ip ? findingByKey(domainId, 'cve_new', `cvenew:${ip}:${cveId}`) : undefined

  if (result === 'confirmed') {
    const hit = matches[0]
    const matchedAt = hit['matched-at'] ?? hit.matched ?? url
    const curl = typeof hit['curl-command'] === 'string' ? hit['curl-command'] : `nuclei -u ${url} -id ${cveId}`
    const severity = hit.info?.severity ?? 'high'
    // Richer evidence straight from the JSONL hit: which matcher fired, any
    // extracted values, and the matched response line.
    const matcherName = typeof hit['matcher-name'] === 'string' ? hit['matcher-name'] : undefined
    const extracted = Array.isArray(hit['extracted-results']) ? hit['extracted-results'].slice(0, 5).map(String) : undefined
    const matchedLine = typeof hit['matched-line'] === 'string' ? hit['matched-line'].slice(0, 300) : undefined

    // Standalone nuclei evidence finding (the PoC), scored by the normal scorer.
    const pocId = await addScoredFinding({
      domainId,
      type: 'nuclei',
      data: {
        target,
        templateId: hit['template-id'] ?? hit.templateID ?? cveId,
        name: hit.info?.name ?? `${cveId} verification`,
        severity,
        matched: matchedAt,
        cveId,
        verifiesCveNew: true,
        selector,
        matcherName,
        extracted,
        matchedLine,
        info: hit.info,
        repro: { request: `GET ${url}`, curl, matchedAt, matcherName, matchedLine, extracted, at },
      },
      tags: ['nuclei', 'active', 'cve-verify', `cve:${cveId}`, ...(kev ? ['kev'] : [])],
    })

    // Upgrade the originating cve_new finding in place: confirmed + score floor.
    if (existing) {
      const kevKnown = kev || (existing.data as any)?.kev === true
      recordCveVerification(
        existing.id,
        { result, templateId: hit['template-id'] ?? cveId, matchedAt, curl, at },
        { confirm: true, score: kevKnown ? 100 : 95 },
      )
      // Relational edge: this PoC confirms that cve_new (queryable, not by naming).
      linkFindings(pocId, existing.id, 'confirms')
    }
    log.info({ target, cveId, matchedAt }, 'cve verify: CONFIRMED exploitable')
  } else {
    // Negative — annotate only, never downgrade. no_template ≠ not_reproduced ≠ safe.
    if (existing) recordCveVerification(existing.id, { result, at })
    log.info({ target, cveId, result }, `cve verify: ${result}`)
  }

  return { available: true, target, cveId, result, selector, matched: matches.length, upgraded: result === 'confirmed' && !!existing }
}
