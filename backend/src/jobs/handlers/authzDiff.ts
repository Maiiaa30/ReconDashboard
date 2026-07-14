import { getDomain } from '../../domains/store'
import { addFinding } from '../../findings/store'
import { applyId, authzVerdict, type IdentityResult } from '../../replay/authz'
import { sendRawRequest, withoutCredentialHeaders, type ReplayRequest } from '../../replay/send'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

// authz_diff: replay one object request under three identities (A = template creds,
// B = operator-supplied second account, anonymous = credential-stripped), mutating
// the {{ID}} object id, and diff the responses. Every finding is needs-review —
// "should A see B's object" is a judgment call the operator makes; the tool only
// surfaces the candidates. LOUD + gated; SSRF-guarded via sendRawRequest per hop.

const MAX_IDS = 200

export async function authzDiffHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const template = params.template as ReplayRequest | undefined
  if (!template || typeof template.url !== 'string') throw new Error('authz_diff: missing request template')
  const ids = (Array.isArray(params.ids) ? (params.ids as string[]) : []).slice(0, MAX_IDS)
  if (ids.length === 0) throw new Error('authz_diff: no object ids to test')
  const identityB = params.identityBHeaders && typeof params.identityBHeaders === 'object' ? (params.identityBHeaders as Record<string, string>) : undefined

  const host = new URL(template.url).hostname
  if (!isValidHostname(host) && !isValidDomain(host)) throw new Error(`invalid host: ${host}`)
  if (host !== domain.host && !hostBelongsToDomain(host, domain.host)) throw new Error(`host ${host} does not belong to ${domain.host}`)

  const method = (template.method || 'GET').toUpperCase()
  // A non-idempotent method mutates state on the target — loudly flag it; the
  // operator asked for this, but each object id becomes a real write.
  if (method !== 'GET' && method !== 'HEAD') log.warn({ method }, 'authz_diff: template method is not GET/HEAD — this will send state-changing requests per id')

  const aHeaders = template.headers ?? {}
  const anonHeaders = withoutCredentialHeaders(aHeaders)
  const bHeaders = identityB ? { ...anonHeaders, ...identityB } : null

  const send = async (id: string, headers: Record<string, string>): Promise<IdentityResult> => {
    try {
      const req: ReplayRequest = { ...template, url: applyId(template.url, id)!, headers, body: applyId(template.body, id) }
      const res = await sendRawRequest(req, { signal })
      return { status: res.status, length: res.bodyBytes }
    } catch (err) {
      return { status: 0, length: 0, error: (err instanceof Error ? err.message : String(err)).slice(0, 120) }
    }
  }

  const counts: Record<string, number> = {}
  let flagged = 0
  for (const id of ids) {
    if (signal.aborted) break
    progress(`authz diff object ${id}`)
    const a = await send(id, aHeaders)
    const b = bHeaders ? await send(id, bHeaders) : null
    const anon = await send(id, anonHeaders)
    const { verdict, reason } = authzVerdict(a, b, anon)
    counts[verdict] = (counts[verdict] ?? 0) + 1

    if (verdict === 'likely_idor' || verdict === 'missing_authz') {
      flagged++
      const sev = verdict === 'missing_authz' ? 'critical' : 'high'
      addFinding({
        domainId,
        type: 'authz',
        // url is the templated endpoint (stable dedupe key); objectId is the id.
        data: {
          url: template.url,
          endpoint: applyId(template.url, id),
          objectId: id,
          method,
          verdict,
          reason,
          identities: { a, b, anonymous: anon },
          writeMethod: method !== 'GET' && method !== 'HEAD',
          _scoreReasons: [reason, 'needs-review: confirm the object truly belongs to another identity'],
        },
        score: verdict === 'missing_authz' ? 90 : 80,
        tags: ['authz', 'idor', 'needs-review', `authz:${verdict}`, `sev:${sev}`, ...(method !== 'GET' && method !== 'HEAD' ? ['write-method'] : [])],
      })
    }
  }

  log.info({ host, tested: ids.length, flagged, counts }, 'authz_diff complete')
  return { host, tested: ids.length, flagged, verdicts: counts }
}
