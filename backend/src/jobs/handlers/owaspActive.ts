import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { runActiveChecks } from '../../owasp/activeChecks'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

// OWASP active checks: direct HTTP probes (headers, sensitive files, reflected
// XSS, open redirect, CORS, TRACE, directory listing) that don't depend on
// nuclei. Authorization (active_authorized OR confirm) is enforced at the route
// before enqueue; here we re-check the target belongs to the domain.
export async function owaspActiveHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const target = String(params.target ?? domain.host)
  if (!isValidHostname(target) && !isValidDomain(target)) throw new Error(`invalid target: ${target}`)
  if (target !== domain.host && !hostBelongsToDomain(target, domain.host)) {
    throw new Error(`target ${target} does not belong to authorized domain ${domain.host}`)
  }
  const scheme = params.scheme === 'http' ? 'http' : 'https'

  const { findings, reachable } = await runActiveChecks(scheme, target)
  if (!reachable) {
    log.warn({ target }, 'owasp active checks: target not reachable / internal')
    return { reachable: false, target, count: 0 }
  }

  for (const f of findings) {
    await addScoredFinding({
      domainId,
      type: 'owasp',
      data: { target, category: f.category, name: f.name, severity: f.severity, url: f.url, evidence: f.evidence },
      tags: ['owasp', 'active', `owasp:${f.category}`, `sev:${f.severity}`],
    })
  }

  log.info({ target, findings: findings.length }, 'owasp active checks complete')
  return { reachable: true, target, count: findings.length, categories: [...new Set(findings.map((f) => f.category))] }
}
