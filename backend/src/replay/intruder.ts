import { sendRawRequest, type ReplayRequest } from './send'

// Intruder: take a request template with a {{PAYLOAD}} marker, iterate a bounded
// set of payloads through it, and record status/size/timing per attempt so the
// operator can spot the one response that deviates (the OTP that verified, the
// filter that let a value through, the endpoint with no rate limiting). Runs as a
// gated LOUD job — sequential + throttled by design, never a parallel flood.

export const PAYLOAD_MARKER = '{{PAYLOAD}}'
export const MAX_PAYLOADS = 10_000

export interface IntruderAttempt {
  payload: string
  status: number
  length: number
  timeMs: number
  error?: string
}

export interface IntruderResult {
  total: number
  sent: number
  aborted: boolean
  attempts: IntruderAttempt[]
  // Attempts whose (status,length) differs from the dominant "baseline" response —
  // the high-signal rows to look at first.
  interesting: IntruderAttempt[]
  baseline: { status: number; length: number } | null
}

// Substitute the marker everywhere it appears in the template (url, header
// values, body). Multiple markers all get the same payload (sniper-style).
export function applyPayload(template: ReplayRequest, payload: string): ReplayRequest {
  const sub = (s: string | undefined) => (s == null ? s : s.split(PAYLOAD_MARKER).join(payload))
  const headers: Record<string, string> | undefined = template.headers
    ? Object.fromEntries(Object.entries(template.headers).map(([k, v]) => [k, sub(v) ?? v]))
    : undefined
  return { ...template, url: sub(template.url) ?? template.url, headers, body: sub(template.body) }
}

// Expand the operator's payload spec into a concrete, bounded list. Throws if the
// spec would exceed MAX_PAYLOADS (better an explicit error than a silent truncation).
export function expandPayloads(spec: {
  mode: 'list' | 'range'
  list?: string
  from?: number
  to?: number
  pad?: number
}): string[] {
  if (spec.mode === 'range') {
    const from = Math.floor(Number(spec.from))
    const to = Math.floor(Number(spec.to))
    if (!Number.isFinite(from) || !Number.isFinite(to)) throw new Error('range needs numeric from/to')
    if (to < from) throw new Error('range "to" must be >= "from"')
    const count = to - from + 1
    if (count > MAX_PAYLOADS) throw new Error(`range of ${count} exceeds the ${MAX_PAYLOADS} payload cap — narrow it`)
    const pad = Math.max(0, Math.min(20, Math.floor(Number(spec.pad) || 0)))
    const out: string[] = []
    for (let i = from; i <= to; i++) out.push(pad ? String(i).padStart(pad, '0') : String(i))
    return out
  }
  const items = (spec.list ?? '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
  if (items.length === 0) throw new Error('payload list is empty')
  if (items.length > MAX_PAYLOADS) throw new Error(`${items.length} payloads exceed the ${MAX_PAYLOADS} cap — trim the list`)
  return items
}

// The most common (status,length) pair is treated as the baseline; anything else
// is flagged. Capped so a wildly-varying target can't return a giant list.
function findInteresting(attempts: IntruderAttempt[]): {
  interesting: IntruderAttempt[]
  baseline: { status: number; length: number } | null
} {
  const ok = attempts.filter((a) => !a.error)
  if (ok.length < 2) return { interesting: [], baseline: null }
  const counts = new Map<string, number>()
  for (const a of ok) counts.set(`${a.status}:${a.length}`, (counts.get(`${a.status}:${a.length}`) ?? 0) + 1)
  let baseKey = ''
  let baseN = -1
  for (const [k, n] of counts) if (n > baseN) [baseN, baseKey] = [n, k]
  const [bStatus, bLength] = baseKey.split(':').map(Number)
  const interesting = attempts.filter((a) => `${a.status}:${a.length}` !== baseKey || a.error).slice(0, 200)
  return { interesting, baseline: { status: bStatus, length: bLength } }
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (ms <= 0 || signal.aborted) return resolve()
    const t = setTimeout(resolve, ms)
    signal.addEventListener('abort', () => {
      clearTimeout(t)
      resolve()
    }, { once: true })
  })
}

export async function runIntruder(
  template: ReplayRequest,
  payloads: string[],
  opts: { throttleMs?: number; signal: AbortSignal; onProgress?: (i: number, total: number) => void },
): Promise<IntruderResult> {
  const throttleMs = Math.max(0, Math.min(10_000, Math.floor(opts.throttleMs ?? 0)))
  const attempts: IntruderAttempt[] = []
  let aborted = false
  for (let i = 0; i < payloads.length; i++) {
    if (opts.signal.aborted) {
      aborted = true
      break
    }
    opts.onProgress?.(i + 1, payloads.length)
    const p = payloads[i]
    const t0 = Date.now()
    try {
      const res = await sendRawRequest(applyPayload(template, p), { signal: opts.signal })
      attempts.push({ payload: p, status: res.status, length: res.bodyBytes, timeMs: res.timeMs })
    } catch (err) {
      attempts.push({ payload: p, status: 0, length: 0, timeMs: Date.now() - t0, error: (err instanceof Error ? err.message : String(err)).slice(0, 160) })
    }
    if (throttleMs && i < payloads.length - 1) await delay(throttleMs, opts.signal)
  }
  const { interesting, baseline } = findInteresting(attempts)
  return { total: payloads.length, sent: attempts.length, aborted, attempts, interesting, baseline }
}
