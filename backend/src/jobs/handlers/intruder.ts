import { getDomain } from '../../domains/store'
import { expandAttack, runIntruder, type AttackMode, type GrepConfig } from '../../replay/intruder'
import type { ReplayRequest } from '../../replay/send'
import type { JobContext } from '../worker'

// Intruder job: expand the attack (mode × positions × payload lists) into concrete
// assignments, then fire them through the template with bounded concurrency, per-
// worker throttle, and abort support. The route already validated + capped the
// attack and gated the run (assertScanAllowed); the handler executes and records.
export async function intruderHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const template = params.template as ReplayRequest | undefined
  if (!template || typeof template.url !== 'string') throw new Error('intruder: missing request template')

  const mode = (params.mode as AttackMode) ?? 'sniper'
  const positions = Array.isArray(params.positions) ? (params.positions as number[]) : []
  const lists = Array.isArray(params.lists) ? (params.lists as string[][]) : []
  if (positions.length === 0) throw new Error('intruder: no marked positions')

  const assignments = expandAttack(mode, positions, lists)
  const throttleMs = Number(params.throttleMs) || 0
  const concurrency = Number(params.concurrency) || 1
  const grep = (params.grep as GrepConfig | undefined) ?? undefined

  const result = await runIntruder(template, assignments, {
    positions,
    throttleMs,
    concurrency,
    grep,
    signal,
    onProgress: (i, total) => progress(`intruder ${i}/${total}`),
  })

  log.info(
    { domain: domain.host, mode, sent: result.sent, total: result.total, interesting: result.interesting.length, aborted: result.aborted },
    'intruder complete',
  )
  return result
}
