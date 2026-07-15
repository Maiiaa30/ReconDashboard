import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { booleanConfirmed, timingConfirmed } from '../../owasp/injection'
import { sendRawRequest, type ReplayRequest } from '../../replay/send'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

// inject_confirm: PROVE a blind SQLi/cmdi. The operator marks the injection point
// with {{INJ}} and supplies the differential payloads; we send them and confirm
// via the pure differentials (boolean: true≈baseline & false diverges; time:
// median sleep-delay ≈ k). LOUD + gated; all egress via sendRawRequest (per-hop
// SSRF guard); a confirmed result is self-verifying → high A03 finding.

const INJ_MARKER = '{{INJ}}'
const MAX_SAMPLES = 5

function applyInj(template: ReplayRequest, payload: string): ReplayRequest {
  const sub = (s: string | undefined) => (s == null ? s : s.split(INJ_MARKER).join(payload))
  const headers = template.headers ? Object.fromEntries(Object.entries(template.headers).map(([k, v]) => [k, sub(v) ?? v])) : undefined
  return { ...template, url: sub(template.url) ?? template.url, headers, body: sub(template.body) }
}

export async function injectConfirmHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const template = params.template as ReplayRequest | undefined
  if (!template || typeof template.url !== 'string') throw new Error('inject_confirm: missing request template')
  const host = new URL(template.url).hostname
  if (!isValidHostname(host) && !isValidDomain(host)) throw new Error(`invalid host: ${host}`)
  if (host !== domain.host && !hostBelongsToDomain(host, domain.host)) throw new Error(`host ${host} does not belong to ${domain.host}`)

  const baseValue = typeof params.baseValue === 'string' ? params.baseValue : ''
  const truePayload = typeof params.truePayload === 'string' ? params.truePayload : ''
  const falsePayload = typeof params.falsePayload === 'string' ? params.falsePayload : ''
  const sleepPayload = typeof params.sleepPayload === 'string' ? params.sleepPayload : ''
  const sleepSeconds = Math.max(0, Math.min(15, Number(params.sleepSeconds) || 0))
  const samples = Math.max(2, Math.min(MAX_SAMPLES, Number(params.samples) || 3))

  const send = async (payload: string, timeoutMs?: number): Promise<{ body: string; timeMs: number }> => {
    const t0 = Date.now()
    try {
      const res = await sendRawRequest(applyInj({ ...template, timeoutMs }, payload), { signal })
      return { body: res.body, timeMs: res.timeMs }
    } catch {
      return { body: '', timeMs: Date.now() - t0 }
    }
  }

  const confirmed: { name: string; evidence: string }[] = []

  // Boolean-based: baseline vs true vs false.
  if (truePayload && falsePayload && !signal.aborted) {
    progress('boolean-based injection differential')
    const base = await send(baseValue)
    const t = await send(truePayload)
    const fb = await send(falsePayload)
    if (booleanConfirmed(base.body, t.body, fb.body)) {
      confirmed.push({
        name: 'Boolean-based injection confirmed',
        evidence: `TRUE payload rendered like the baseline (${t.body.length}B vs ${base.body.length}B) while the FALSE payload diverged (${fb.body.length}B) — the condition is evaluated server-side`,
      })
    }
  }

  // Time-based: N baseline vs N sleep timings (the only path to blind bugs pre-OAST).
  if (sleepPayload && sleepSeconds > 0 && !signal.aborted) {
    progress(`time-based injection (${samples}× SLEEP ${sleepSeconds}s)`)
    const timeoutMs = (sleepSeconds + 8) * 1000
    const baseTimes: number[] = []
    const sleepTimes: number[] = []
    for (let i = 0; i < samples && !signal.aborted; i++) baseTimes.push((await send(baseValue, timeoutMs)).timeMs)
    for (let i = 0; i < samples && !signal.aborted; i++) sleepTimes.push((await send(sleepPayload, timeoutMs)).timeMs)
    if (timingConfirmed(baseTimes, sleepTimes, sleepSeconds)) {
      const med = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]
      confirmed.push({
        name: 'Time-based (blind) injection confirmed',
        evidence: `SLEEP(${sleepSeconds}) payload delayed the response by ~${Math.round((med(sleepTimes) - med(baseTimes)) / 1000)}s (median ${med(sleepTimes)}ms vs baseline ${med(baseTimes)}ms) — server-side execution`,
      })
    }
  }

  if (signal.aborted) {
    log.warn({ host }, 'inject_confirm aborted before persisting')
    return { host, aborted: true, confirmed: 0 }
  }

  for (const c of confirmed) {
    await addScoredFinding({
      domainId,
      type: 'owasp',
      data: { target: host, category: 'A03', name: c.name, severity: 'high', url: template.url, evidence: c.evidence },
      tags: ['owasp', 'injection', 'confirmed', 'owasp:A03', 'sev:high'],
    })
  }

  log.info({ host, confirmed: confirmed.length }, 'inject_confirm complete')
  return { host, confirmed: confirmed.length, findings: confirmed.map((c) => c.name) }
}
