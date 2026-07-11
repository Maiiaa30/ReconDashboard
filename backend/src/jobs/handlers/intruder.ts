import { getDomain } from '../../domains/store'
import { runIntruder } from '../../replay/intruder'
import type { ReplayRequest } from '../../replay/send'
import type { JobContext } from '../worker'

// Intruder job: iterate the pre-expanded payload list through the request
// template, sequentially + throttled, honouring the abort signal (operator
// cancel / timeout). The route already expanded + capped the payloads and gated
// the run (assertScanAllowed); the handler just executes and records.
export async function intruderHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const template = params.template as ReplayRequest | undefined
  const payloads = Array.isArray(params.payloads) ? (params.payloads as string[]) : []
  if (!template || typeof template.url !== 'string') throw new Error('intruder: missing request template')
  if (payloads.length === 0) throw new Error('intruder: no payloads')
  const throttleMs = Number(params.throttleMs) || 0

  const result = await runIntruder(template, payloads, {
    throttleMs,
    signal,
    onProgress: (i, total) => progress(`intruder ${i}/${total}`),
  })

  log.info(
    { domain: domain.host, sent: result.sent, total: result.total, interesting: result.interesting.length, aborted: result.aborted },
    'intruder complete',
  )
  return result
}
