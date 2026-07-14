import { sendRawRequest, type ReplayRequest } from './send'

// Intruder: iterate payloads through a request template with one or more marked
// positions ({{P1}}, {{P2}}, …; {{PAYLOAD}} is a back-compat alias for {{P1}}) and
// record status/size/words/time per attempt so the operator can spot the response
// that deviates (the code that verified, the filter that let a value through, the
// blind-injection that ran long). Runs as a gated LOUD job — bounded concurrency,
// throttled, abortable; never an unbounded flood.

export const PAYLOAD_MARKER = '{{PAYLOAD}}' // legacy single-position marker → P1
export const MAX_PAYLOADS = 10_000
export const MAX_CONCURRENCY = 10

export type AttackMode = 'sniper' | 'battering-ram' | 'pitchfork' | 'cluster-bomb'

// assignment maps a 1-based position index to the payload placed there.
export type Assignment = Record<number, string>

export interface GrepConfig {
  extract?: string // regex; capture group 1 (or whole match) pulled into a column
  match?: string[] // phrases; a response containing any is flagged `matched`
}

export interface IntruderAttempt {
  payload: string // display string (single payload, or "a | b" across positions)
  status: number
  length: number
  words: number
  timeMs: number
  extract?: string // grep-extract capture
  matched?: boolean // grep-match hit
  assignment?: Record<string, string> // position→payload, for multi-position attacks
  error?: string
}

export interface IntruderResult {
  total: number
  sent: number
  aborted: boolean
  attempts: IntruderAttempt[]
  // Attempts that deviate from the response baseline (median across status/length/
  // words/time via a MAD outlier test), errored, or matched a grep phrase — the
  // high-signal rows to look at first.
  interesting: IntruderAttempt[]
  baseline: { status: number; length: number } | null
}

// --- markers & positions -----------------------------------------------------

// {{PAYLOAD}} is P1. Normalize so the rest of the engine only sees {{Pn}}.
function normalizeMarkers(s: string): string {
  return s.split(PAYLOAD_MARKER).join('{{P1}}')
}

const POSITION_RE = /\{\{P(\d+)\}\}/g

// Distinct position indices used anywhere in the template (sorted, 1-based).
export function positionsInTemplate(template: ReplayRequest): number[] {
  const found = new Set<number>()
  const scan = (s: string | undefined) => {
    if (!s) return
    for (const m of normalizeMarkers(s).matchAll(POSITION_RE)) found.add(Number(m[1]))
  }
  scan(template.url)
  scan(template.body ?? undefined)
  if (template.headers) for (const v of Object.values(template.headers)) scan(v)
  return [...found].sort((a, b) => a - b)
}

// Substitute every {{Pi}} (and legacy {{PAYLOAD}} = P1) with its assigned payload.
export function applyPayloads(template: ReplayRequest, assignment: Assignment): ReplayRequest {
  const sub = (s: string | undefined): string | undefined => {
    if (s == null) return s
    return normalizeMarkers(s).replace(POSITION_RE, (_, n) => assignment[Number(n)] ?? '')
  }
  const headers: Record<string, string> | undefined = template.headers
    ? Object.fromEntries(Object.entries(template.headers).map(([k, v]) => [k, sub(v) ?? v]))
    : undefined
  return { ...template, url: sub(template.url) ?? template.url, headers, body: sub(template.body) }
}

// Back-compat shim for the single-position case (used by older callers/tests):
// place `payload` in every marked position.
export function applyPayload(template: ReplayRequest, payload: string): ReplayRequest {
  const positions = positionsInTemplate(template)
  const assignment: Assignment = {}
  for (const p of positions) assignment[p] = payload
  return applyPayloads(template, assignment)
}

// --- payload expansion (single list from a list/range spec) ------------------

export function expandPayloads(spec: { mode: 'list' | 'range'; list?: string; from?: number; to?: number; pad?: number }): string[] {
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

// --- attack expansion (mode × positions × lists → assignments) ---------------

// How many requests an attack will fire — computed without materializing the
// product, so the route can enforce the cap and surface blast radius up front.
export function attackCount(mode: AttackMode, positions: number[], lists: string[][]): number {
  const nPos = positions.length
  if (nPos === 0) return 0
  switch (mode) {
    case 'battering-ram':
      return lists[0]?.length ?? 0
    case 'sniper':
      return nPos * (lists[0]?.length ?? 0)
    case 'pitchfork':
      return Math.min(...positions.map((_, i) => lists[i]?.length ?? 0))
    case 'cluster-bomb':
      return positions.reduce((acc, _, i) => acc * (lists[i]?.length ?? 0), 1)
  }
}

// Materialize the concrete per-request assignments for an attack. Throws if the
// count would exceed MAX_PAYLOADS (an explicit error beats a silent truncation).
export function expandAttack(mode: AttackMode, positions: number[], lists: string[][]): Assignment[] {
  if (positions.length === 0) throw new Error('template has no {{Pn}} positions')
  const count = attackCount(mode, positions, lists)
  if (count === 0) throw new Error('attack expands to zero requests — check the payload lists')
  if (count > MAX_PAYLOADS) throw new Error(`attack of ${count} requests exceeds the ${MAX_PAYLOADS} cap — narrow the payload lists`)

  const out: Assignment[] = []
  if (mode === 'battering-ram') {
    for (const p of lists[0]) {
      const a: Assignment = {}
      for (const pos of positions) a[pos] = p
      out.push(a)
    }
  } else if (mode === 'sniper') {
    // Vary one position at a time; hold the others empty (no base value exists for
    // a whole-value marker). One list drives every position in turn.
    for (const pos of positions) {
      for (const p of lists[0]) {
        const a: Assignment = {}
        for (const other of positions) a[other] = other === pos ? p : ''
        out.push(a)
      }
    }
  } else if (mode === 'pitchfork') {
    const n = attackCount('pitchfork', positions, lists)
    for (let j = 0; j < n; j++) {
      const a: Assignment = {}
      positions.forEach((pos, i) => (a[pos] = lists[i][j]))
      out.push(a)
    }
  } else {
    // cluster-bomb: Cartesian product, odometer over the per-position lists.
    const idx = new Array(positions.length).fill(0)
    for (let k = 0; k < count; k++) {
      const a: Assignment = {}
      positions.forEach((pos, i) => (a[pos] = lists[i][idx[i]]))
      out.push(a)
      // increment odometer
      for (let i = positions.length - 1; i >= 0; i--) {
        if (++idx[i] < lists[i].length) break
        idx[i] = 0
      }
    }
  }
  return out
}

// --- anomaly detection (median + MAD) ----------------------------------------

function median(xs: number[]): number {
  if (xs.length === 0) return 0
  const s = [...xs].sort((a, b) => a - b)
  const mid = Math.floor(s.length / 2)
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2
}

// Modified z-score threshold. Above ~3.5 is the conventional outlier cutoff.
const MAD_Z = 3.5

// Flag attempts that deviate from the baseline. Uses median + MAD (robust to a
// few outliers) across status/length/words/time; when a dimension has zero spread
// (MAD 0) any non-median value is flagged, recovering the old exact-match behavior.
// Also always flags errors and grep-match hits.
function findInteresting(attempts: IntruderAttempt[]): { interesting: IntruderAttempt[]; baseline: { status: number; length: number } | null } {
  const ok = attempts.filter((a) => !a.error)
  if (ok.length < 2) {
    const interesting = attempts.filter((a) => a.error || a.matched).slice(0, 200)
    return { interesting, baseline: ok.length === 1 ? { status: ok[0].status, length: ok[0].length } : null }
  }
  const dims: (keyof IntruderAttempt)[] = ['status', 'length', 'words', 'timeMs']
  const stats = dims.map((d) => {
    const vals = ok.map((a) => Number(a[d] ?? 0))
    const med = median(vals)
    const mad = median(vals.map((v) => Math.abs(v - med)))
    return { d, med, mad }
  })
  const isOutlier = (a: IntruderAttempt): boolean =>
    stats.some(({ d, med, mad }) => {
      const v = Number(a[d] ?? 0)
      if (mad === 0) return v !== med
      return Math.abs(v - med) / (1.4826 * mad) > MAD_Z
    })
  const interesting = attempts.filter((a) => a.error || a.matched || isOutlier(a)).slice(0, 200)
  const statusMed = stats.find((s) => s.d === 'status')!.med
  const lengthMed = stats.find((s) => s.d === 'length')!.med
  return { interesting, baseline: { status: Math.round(statusMed), length: Math.round(lengthMed) } }
}

// --- grep --------------------------------------------------------------------

function compileGrep(cfg: GrepConfig | undefined): { extract: RegExp | null; match: string[] } {
  let extract: RegExp | null = null
  if (cfg?.extract) {
    try {
      extract = new RegExp(cfg.extract.slice(0, 500))
    } catch {
      extract = null // a bad regex is ignored, not fatal to the run
    }
  }
  const match = (cfg?.match ?? []).map((p) => p.slice(0, 500)).filter(Boolean).slice(0, 25)
  return { extract, match }
}

// --- runner ------------------------------------------------------------------

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

function displayPayload(assignment: Assignment, positions: number[]): string {
  return positions.map((p) => assignment[p] ?? '').join(' | ')
}

export async function runIntruder(
  template: ReplayRequest,
  assignments: Assignment[],
  opts: {
    positions: number[]
    throttleMs?: number
    concurrency?: number
    grep?: GrepConfig
    signal: AbortSignal
    onProgress?: (i: number, total: number) => void
  },
): Promise<IntruderResult> {
  const throttleMs = Math.max(0, Math.min(10_000, Math.floor(opts.throttleMs ?? 0)))
  const concurrency = Math.max(1, Math.min(MAX_CONCURRENCY, Math.floor(opts.concurrency ?? 1)))
  const { extract, match } = compileGrep(opts.grep)
  const positions = opts.positions
  const multi = positions.length > 1
  const attempts: IntruderAttempt[] = new Array(assignments.length)
  let aborted = false
  let next = 0
  let done = 0

  async function worker(): Promise<void> {
    for (;;) {
      if (opts.signal.aborted) {
        aborted = true
        return
      }
      const i = next++
      if (i >= assignments.length) return
      const assignment = assignments[i]
      const display = multi ? displayPayload(assignment, positions) : (assignment[positions[0]] ?? '')
      const t0 = Date.now()
      try {
        const res = await sendRawRequest(applyPayloads(template, assignment), { signal: opts.signal })
        const words = res.body ? res.body.split(/\s+/).filter(Boolean).length : 0
        const attempt: IntruderAttempt = { payload: display, status: res.status, length: res.bodyBytes, words, timeMs: res.timeMs }
        if (extract) {
          const m = extract.exec(res.body)
          if (m) attempt.extract = (m[1] ?? m[0]).slice(0, 200)
        }
        if (match.length && res.body) attempt.matched = match.some((p) => res.body.includes(p))
        if (multi) attempt.assignment = Object.fromEntries(positions.map((p) => [`P${p}`, assignment[p] ?? '']))
        attempts[i] = attempt
      } catch (err) {
        attempts[i] = { payload: display, status: 0, length: 0, words: 0, timeMs: Date.now() - t0, error: (err instanceof Error ? err.message : String(err)).slice(0, 160) }
      }
      opts.onProgress?.(++done, assignments.length)
      if (throttleMs) await delay(throttleMs, opts.signal)
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()))
  // Compact out any holes left by an abort (indices never reached).
  const settled = attempts.filter(Boolean)
  const { interesting, baseline } = findInteresting(settled)
  return { total: assignments.length, sent: settled.length, aborted, attempts: settled, interesting, baseline }
}
