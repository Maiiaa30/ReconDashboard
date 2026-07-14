import { getDomain } from '../../domains/store'
import { addFinding } from '../../findings/store'
import { searchCodeLeaks } from '../../sources/codeLeaks'
import type { JobContext } from '../worker'

// Passive code-leak search: query public code (GitHub) for the target's domain
// (+ optional operator/org seeds) and record matches as 'secret' findings for
// review. Queries GitHub, never the target — safe on any domain.
export async function codeLeakHandler({ params, log, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const seeds = Array.isArray(params.seeds) ? (params.seeds as unknown[]).filter((s): s is string => typeof s === 'string') : []
  progress(`searching public code for ${domain.host}`)
  const res = await searchCodeLeaks(domain.host, seeds)
  if (!res.available) return { available: false, reason: res.reason, hits: 0 }

  let created = 0
  for (const h of res.hits) {
    addFinding({
      domainId,
      type: 'secret',
      data: {
        source: 'github-code',
        repo: h.repo,
        path: h.path,
        url: h.url,
        term: h.term,
        fragments: h.fragments,
        secretHint: h.secretHint,
        _scoreReasons: [
          `Public code in ${h.repo} references ${h.term}`,
          h.secretHint
            ? 'Matched code contains secret-like keywords — review for a leaked credential'
            : 'Review the file for sensitive data or internal URLs',
        ],
      },
      // Explicit score (not the deterministic scorer, which has no 'secret' rule):
      // a keyword-flagged hit is high, a plain domain mention is medium.
      score: h.secretHint ? 70 : 45,
      tags: ['secret', 'code-leak', 'needs-review', ...(h.secretHint ? ['sev:high', 'possible-secret'] : ['sev:medium'])],
    })
    created++
  }

  log.info({ domain: domain.host, searched: res.searched.length, hits: res.hits.length }, 'code-leak search complete')
  return { available: true, searched: res.searched, hits: res.hits.length, findings: created }
}
