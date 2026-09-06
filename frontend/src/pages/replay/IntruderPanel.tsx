import { Fragment, useEffect, useMemo, useState } from 'react'
import { Crosshair, StopCircle, AlertTriangle } from 'lucide-react'
import { api, ApiError, type IntruderResult, type IntruderAttempt, type Job, type Wordlist } from '../../api'
import { Badge, Button, Card, Spinner } from '../../components/ui'
import { useToast } from '../../components/Toast'
import { type BuiltRequest, NumField, PAYLOAD_MARKER, statusTone } from './shared'
import { PayloadLibrary } from './PayloadLibrary'
import { EncoderBar } from './EncoderBar'

const ATTACK_MODES = ['sniper', 'battering-ram', 'pitchfork', 'cluster-bomb'] as const
type AttackMode = (typeof ATTACK_MODES)[number]

// Distinct 1-based payload positions marked in the composed request ({{P1}}…, or
// legacy {{PAYLOAD}} = P1). Mirrors the server's positionsInTemplate.
function detectPositions(req: BuiltRequest): number[] {
  const text = [req.url, req.body ?? '', ...Object.values(req.headers)].join('\n')
  const set = new Set<number>()
  if (text.includes(PAYLOAD_MARKER)) set.add(1)
  for (const m of text.matchAll(/\{\{P(\d+)\}\}/g)) set.add(Number(m[1]))
  return [...set].sort((a, b) => a - b)
}


// --- Intruder ---------------------------------------------------------------
export function IntruderPanel({
  domainId,
  passive,
  confirmActive,
  build,
  identityId,
  toast,
}: {
  domainId: number
  passive: boolean
  confirmActive: (title: string, what: string) => Promise<boolean>
  build: () => BuiltRequest
  identityId?: number | null
  toast: ReturnType<typeof useToast>
}) {
  const [payloadMode, setPayloadMode] = useState<'list' | 'range' | 'wordlist'>('list')
  const [list, setList] = useState('')
  const [from, setFrom] = useState('0')
  const [to, setTo] = useState('99')
  const [pad, setPad] = useState('0')
  const [throttle, setThrottle] = useState('0')
  const [wordlists, setWordlists] = useState<Wordlist[]>([])
  const [wordlist, setWordlist] = useState('')
  const [attackMode, setAttackMode] = useState<AttackMode>('sniper')
  const [posLists, setPosLists] = useState<Record<number, string>>({}) // pitchfork/cluster-bomb: one list per position
  const [grepExtract, setGrepExtract] = useState('')
  const [grepMatch, setGrepMatch] = useState('')
  const [concurrency, setConcurrency] = useState('1')

  // Positions marked in the current request drive the multi-list UI. Multi-list
  // modes (pitchfork/cluster-bomb) need one list per position.
  const positions = detectPositions(build())
  const multiList = attackMode === 'pitchfork' || attackMode === 'cluster-bomb'

  useEffect(() => {
    api
      .meta()
      .then((m) => setWordlists(m.wordlists ?? []))
      .catch(() => setWordlists([]))
  }, [])

  const [jobId, setJobId] = useState<number | null>(null)
  const [job, setJob] = useState<Job | null>(null)
  const [busy, setBusy] = useState(false)
  const [sortKey, setSortKey] = useState<'order' | 'status' | 'length' | 'timeMs'>('order')

  // Poll the running intruder job until it finishes.
  useEffect(() => {
    if (jobId == null) return
    let stop = false
    const tick = async () => {
      try {
        const { job: j } = await api.job(jobId)
        if (stop) return
        setJob(j)
        if (['done', 'error', 'cancelled', 'dead'].includes(j.status)) return
      } catch {
        /* transient — keep polling */
      }
      if (!stop) timer = setTimeout(tick, 1500)
    }
    let timer = setTimeout(tick, 600)
    return () => {
      stop = true
      clearTimeout(timer)
    }
  }, [jobId])

  const result = (job?.status === 'done' ? (job.result as IntruderResult | null) : null) ?? null
  const running = job != null && ['queued', 'running'].includes(job.status)

  async function start() {
    if (busy || running) return
    const req = build()
    if (!req.url) return toast.error('Enter a URL first.')
    const pos = detectPositions(req)
    if (pos.length === 0) return toast.error('Add a {{P1}} (or {{PAYLOAD}}) marker to the request first.')
    if (!multiList && payloadMode === 'wordlist' && !wordlist) return toast.error('Pick a wordlist first.')
    if (multiList && pos.some((p) => !(posLists[p] ?? '').trim())) return toast.error(`${attackMode} needs a payload list for each position (P${pos.join(', P')}).`)
    if (!(await confirmActive('Start this attack?', 'Intruder'))) return

    const singleSpec =
      payloadMode === 'range'
        ? { mode: 'range' as const, from: Number(from), to: Number(to), pad: Number(pad) }
        : payloadMode === 'wordlist'
          ? { mode: 'wordlist' as const, wordlist }
          : { mode: 'list' as const, list }
    const match = grepMatch.split(/[\n,]/).map((l) => l.trim()).filter(Boolean)

    setBusy(true)
    setJob(null)
    try {
      const { jobId: id, count } = await api.intruder(domainId, {
        template: req,
        mode: attackMode,
        ...(multiList
          ? { payloads: pos.map((p) => ({ mode: 'list' as const, list: posLists[p] ?? '' })) }
          : { payload: singleSpec }),
        grep: grepExtract.trim() || match.length ? { extract: grepExtract.trim() || undefined, match } : undefined,
        concurrency: Number(concurrency) || 1,
        throttleMs: Number(throttle) || 0,
        identityId: identityId ?? undefined,
        confirm: passive,
      })
      setJobId(id)
      toast.success(`Intruder queued (job #${id}) — ${count} requests.`)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to start attack.')
    } finally {
      setBusy(false)
    }
  }

  async function cancel() {
    if (jobId == null) return
    try {
      await api.cancelJob(jobId)
      toast.info('Cancel requested.')
    } catch {
      toast.error('Could not cancel.')
    }
  }

  const attempts = useMemo(() => {
    const a = result?.attempts ? [...result.attempts] : []
    if (sortKey === 'order') return a
    return a.sort((x, y) => (sortKey === 'status' ? x.status - y.status : sortKey === 'length' ? x.length - y.length : x.timeMs - y.timeMs))
  }, [result, sortKey])

  return (
    <Card className="flex h-full min-h-0 flex-col overflow-auto">
      {/* Payload config */}
      <div className="mb-3 space-y-2">
        {/* Attack mode */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={attackMode}
            onChange={(e) => setAttackMode(e.target.value as AttackMode)}
            className="rounded-lg border border-hair bg-ink-950 px-2 py-1.5 text-xs outline-none focus:border-accent-500"
          >
            {ATTACK_MODES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <span className="text-[11px] text-zinc-500">
            {positions.length ? `${positions.length} position${positions.length > 1 ? 's' : ''}: P${positions.join(', P')}` : 'no positions marked'}
          </span>
        </div>
        {!multiList && (
          <>
            <div className="inline-flex rounded-lg border border-hair bg-ink-950 p-0.5 text-xs">
              {(['list', 'range', 'wordlist'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setPayloadMode(m)}
                  className={`rounded px-2.5 py-1 capitalize ${payloadMode === m ? 'bg-accent-500/15 text-accent-fg' : 'text-zinc-400'}`}
                >
                  {m === 'range' ? 'Number range' : m}
                </button>
              ))}
            </div>
            {payloadMode === 'list' && (
          <>
            <PayloadLibrary
              currentList={list}
              onLoad={(payloads) => setList((prev) => (prev.trim() ? `${prev.replace(/\n+$/, '')}\n${payloads.join('\n')}` : payloads.join('\n')))}
              toast={toast}
            />
            <textarea
              value={list}
              onChange={(e) => setList(e.target.value)}
              placeholder={'one payload per line\nadmin\ntest\n0000'}
              rows={4}
              spellCheck={false}
              className="block w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
            />
            <EncoderBar toast={toast} />
          </>
        )}
        {payloadMode === 'range' && (
          <div className="flex flex-wrap items-end gap-2 text-xs">
            <NumField label="from" value={from} onChange={setFrom} />
            <NumField label="to" value={to} onChange={setTo} />
            <NumField label="zero-pad width" value={pad} onChange={setPad} />
            <span className="text-zinc-600">e.g. 0000–9999 with pad 4</span>
          </div>
        )}
        {payloadMode === 'wordlist' &&
          (wordlists.length === 0 ? (
            <p className="text-xs text-zinc-500">
              No wordlists installed — they ship in the Docker image (<span className="font-mono">/usr/share/wordlists</span>), not the
              local dev backend. Use List or Range here.
            </p>
          ) : (
            <select
              value={wordlist}
              onChange={(e) => setWordlist(e.target.value)}
              className="block w-full rounded-lg border border-hair bg-ink-950 px-2 py-2 text-xs outline-none focus:border-accent-500"
            >
              <option value="">choose a wordlist…</option>
              {(['payload', 'content'] as const).map((cat) => {
                const items = wordlists.filter((w) => (w.category ?? 'content') === cat)
                if (!items.length) return null
                return (
                  <optgroup key={cat} label={cat === 'payload' ? 'Payloads (values)' : 'Content discovery (paths)'}>
                    {items.map((w) => (
                      <option key={w.path} value={w.path}>
                        {w.name} ({w.sizeKb} KB)
                      </option>
                    ))}
                  </optgroup>
                )
              })}
            </select>
          ))}
            {payloadMode === 'wordlist' && wordlists.length > 0 && (
              <p className="text-[11px] text-zinc-600">Large lists are capped at the first 10,000 entries.</p>
            )}
          </>
        )}
        {multiList && (
          <div className="space-y-2">
            {positions.length === 0 && <p className="text-xs text-zinc-500">Mark positions with {'{{P1}}'}, {'{{P2}}'}, … first.</p>}
            {positions.map((p) => (
              <div key={p}>
                <label className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">P{p} payloads (one per line)</label>
                <textarea
                  value={posLists[p] ?? ''}
                  onChange={(e) => setPosLists((prev) => ({ ...prev, [p]: e.target.value }))}
                  rows={3}
                  spellCheck={false}
                  className="block w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
                />
              </div>
            ))}
            <p className="text-[11px] text-zinc-600">
              {attackMode === 'pitchfork' ? 'Lists advance in lockstep (min length).' : 'Every combination is tried (product of list lengths).'}
            </p>
          </div>
        )}
        {/* Grep + concurrency */}
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <label className="block">
            <span className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">Grep-extract (regex → column)</span>
            <input
              value={grepExtract}
              onChange={(e) => setGrepExtract(e.target.value)}
              placeholder={'e.g. "csrf":"([^"]+)"'}
              spellCheck={false}
              className="block w-full rounded-lg border border-hair bg-ink-950 px-2 py-1.5 font-mono text-xs outline-none focus:border-accent-500"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">Grep-match (comma/newline separated)</span>
            <input
              value={grepMatch}
              onChange={(e) => setGrepMatch(e.target.value)}
              placeholder={'SQL syntax, Traceback'}
              spellCheck={false}
              className="block w-full rounded-lg border border-hair bg-ink-950 px-2 py-1.5 font-mono text-xs outline-none focus:border-accent-500"
            />
          </label>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <NumField label="throttle ms / req" value={throttle} onChange={setThrottle} />
          <NumField label="concurrency (1–10)" value={concurrency} onChange={setConcurrency} />
          {running ? (
            <Button variant="danger" onClick={cancel}>
              <StopCircle size={15} /> Cancel
            </Button>
          ) : (
            <Button variant="loud" onClick={start} disabled={busy}>
              <Crosshair size={15} /> {busy ? 'Queuing…' : 'Start attack'}
            </Button>
          )}
          {running && (
            <span className="inline-flex items-center gap-1.5 text-amber-300">
              <Spinner /> {job?.progress ?? 'running…'}
            </span>
          )}
        </div>
      </div>

      {/* Results */}
      {job?.status === 'error' && <p className="text-sm text-red-300">Attack failed: {job.error}</p>}
      {result && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-400">
            <span>
              <span className="font-semibold text-zinc-200">{result.sent}</span>/{result.total} sent
            </span>
            {result.baseline && (
              <span>
                baseline <span className="font-mono text-zinc-300">{result.baseline.status}</span> · {result.baseline.length} B
              </span>
            )}
            {result.aborted && <Badge tone="amber">cancelled early</Badge>}
            <span className="ml-auto inline-flex items-center gap-1">
              sort
              <select
                value={sortKey}
                onChange={(e) => setSortKey(e.target.value as typeof sortKey)}
                className="rounded border border-hair bg-ink-950 px-1.5 py-0.5 text-[11px] outline-none"
              >
                <option value="order">order</option>
                <option value="status">status</option>
                <option value="length">length</option>
                <option value="timeMs">time</option>
              </select>
            </span>
          </div>

          {result.interesting.length > 0 && (
            <div className="rounded-lg border border-amber-900/40 bg-amber-950/15 p-2">
              <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-amber-200">
                <AlertTriangle size={13} className="text-amber-400" /> {result.interesting.length} response(s) deviate from the baseline —
                look here first
              </div>
              <AttemptTable rows={result.interesting} highlight explainJobId={jobId ?? undefined} toast={toast} />
            </div>
          )}

          <div>
            <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">All attempts</div>
            <AttemptTable rows={attempts} />
          </div>
        </div>
      )}
    </Card>
  )
}
const ATTEMPT_PAGE = 500
function AttemptTable({
  rows,
  highlight = false,
  explainJobId,
  toast,
}: {
  rows: IntruderAttempt[]
  highlight?: boolean
  explainJobId?: number
  toast?: ReturnType<typeof useToast>
}) {
  // Cap the DOM: a 10k-payload run would otherwise commit 10k <tr> at once and
  // jank the tab. Render a page at a time; deviating rows are surfaced separately.
  const [limit, setLimit] = useState(ATTEMPT_PAGE)
  const [explains, setExplains] = useState<Record<number, string>>({})
  const [explaining, setExplaining] = useState<number | null>(null)
  const shown = rows.slice(0, limit)
  const hasWords = rows.some((r) => r.words != null)
  const hasExtract = rows.some((r) => r.extract != null)
  const hasMatched = rows.some((r) => r.matched)
  const canExplain = explainJobId != null

  async function explain(i: number) {
    if (explainJobId == null || explaining != null) return
    setExplaining(i)
    try {
      const r = await api.explainIntruderRow(explainJobId, i)
      if (r.enabled && r.explanation) setExplains((m) => ({ ...m, [i]: r.explanation! }))
      else toast?.info(r.note ?? 'No explanation available.')
    } catch {
      toast?.error('Could not get an explanation.')
    } finally {
      setExplaining(null)
    }
  }

  return (
    <div>
      <div className="max-h-72 overflow-auto rounded-lg border border-hair/60">
        <table className="w-full text-left font-mono text-[11px]">
          <thead className="sticky top-0 bg-ink-900 text-zinc-500">
            <tr>
              <th className="px-2 py-1 font-medium">payload</th>
              <th className="px-2 py-1 font-medium">status</th>
              <th className="px-2 py-1 font-medium">length</th>
              {hasWords && <th className="px-2 py-1 font-medium">words</th>}
              <th className="px-2 py-1 font-medium">time</th>
              {hasExtract && <th className="px-2 py-1 font-medium">extract</th>}
              {hasMatched && <th className="px-2 py-1 font-medium">match</th>}
              {canExplain && <th className="px-2 py-1 font-medium">AI</th>}
            </tr>
          </thead>
          <tbody>
            {shown.map((r, i) => (
              <Fragment key={i}>
              <tr
                title={r.bodyExcerpt ? `Response excerpt:\n${r.bodyExcerpt}` : undefined}
                className={`border-t border-hair/40 ${highlight ? 'text-amber-100' : 'text-zinc-300'} ${r.bodyExcerpt ? 'cursor-help' : ''}`}
              >
                <td className="px-2 py-1 break-all">{r.payload}</td>
                <td className="px-2 py-1">
                  <Badge tone={statusTone(r.status)}>{r.error ? 'err' : r.status}</Badge>
                </td>
                <td className="px-2 py-1">{r.length}</td>
                {hasWords && <td className="px-2 py-1 text-zinc-500">{r.words ?? ''}</td>}
                <td className="px-2 py-1 text-zinc-500">{r.timeMs}ms</td>
                {hasExtract && (
                  <td className="px-2 py-1 break-all text-accent-fg" title={r.extractAll?.join('\n')}>
                    {r.extract ?? ''}
                    {r.extractAll && r.extractAll.length > 1 && <span className="ml-1 text-zinc-500">+{r.extractAll.length - 1}</span>}
                  </td>
                )}
                {hasMatched && <td className="px-2 py-1">{r.matched ? <Badge tone="red">hit</Badge> : ''}</td>}
                {canExplain && (
                  <td className="px-2 py-1">
                    <button onClick={() => explain(i)} disabled={explaining != null} className="text-accent-fg hover:underline disabled:opacity-40">
                      {explaining === i ? '…' : 'explain'}
                    </button>
                  </td>
                )}
              </tr>
              {explains[i] && (
                <tr className="border-t border-hair/20">
                  <td colSpan={9} className="px-2 py-1.5 text-[11px] italic text-zinc-400">
                    🤖 {explains[i]}
                  </td>
                </tr>
              )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > limit && (
        <button
          onClick={() => setLimit((l) => l + ATTEMPT_PAGE * 4)}
          className="mt-1 text-[11px] text-zinc-500 hover:text-zinc-300"
        >
          showing {limit} of {rows.length} — show more
        </button>
      )}
    </div>
  )
}
