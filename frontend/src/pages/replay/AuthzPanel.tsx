import { useEffect, useState } from 'react'
import { KeyRound, StopCircle } from 'lucide-react'
import { api, ApiError, type Job, type Identity } from '../../api'
import { Badge, Button, Card, Spinner } from '../../components/ui'
import { useToast } from '../../components/Toast'
import { type BuiltRequest, NumField, parseHeaders } from './shared'

// --- Authz (IDOR) diff -------------------------------------------------------
export function AuthzPanel({
  domainId,
  passive,
  confirmActive,
  build,
  identities,
  toast,
}: {
  domainId: number
  passive: boolean
  confirmActive: (title: string, what: string) => Promise<boolean>
  build: () => BuiltRequest
  identities: Identity[]
  toast: ReturnType<typeof useToast>
}) {
  const [idsMode, setIdsMode] = useState<'list' | 'range'>('range')
  const [list, setList] = useState('')
  const [from, setFrom] = useState('1')
  const [to, setTo] = useState('50')
  const [identityBId, setIdentityBId] = useState<number | null>(null)
  const [identityB, setIdentityB] = useState('')
  const [jobId, setJobId] = useState<number | null>(null)
  const [job, setJob] = useState<Job | null>(null)
  const [busy, setBusy] = useState(false)

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
        /* keep polling */
      }
      if (!stop) timer = setTimeout(tick, 1500)
    }
    let timer = setTimeout(tick, 600)
    return () => {
      stop = true
      clearTimeout(timer)
    }
  }, [jobId])

  const result = (job?.status === 'done' ? (job.result as { host: string; tested: number; flagged: number; verdicts: Record<string, number> } | null) : null) ?? null
  const running = job != null && ['queued', 'running'].includes(job.status)

  async function start() {
    if (busy || running) return
    const req = build()
    if (!req.url) return toast.error('Enter a URL first.')
    const hasId = [req.url, req.body ?? '', ...Object.values(req.headers)].some((s) => String(s).includes('{{ID}}'))
    if (!hasId) return toast.error('Mark the object id with {{ID}} in the request first.')
    if (!(await confirmActive('Run authorization diff?', 'Authz diff'))) return
    setBusy(true)
    setJob(null)
    try {
      const { jobId: id, count } = await api.authzDiff(domainId, {
        template: req,
        ids: idsMode === 'range' ? { mode: 'range', from: Number(from), to: Number(to) } : { mode: 'list', list },
        // A named identity B (resolved server-side) takes precedence over ad-hoc headers.
        identityBId: identityBId ?? undefined,
        identityB: identityBId == null && identityB.trim() ? { headers: parseHeaders(identityB) } : undefined,
        confirm: passive,
      })
      setJobId(id)
      toast.success(`Authz diff queued (#${id}) — ${count} objects.`)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to start authz diff.')
    } finally {
      setBusy(false)
    }
  }
  async function cancel() {
    if (jobId == null) return
    await api.cancelJob(jobId).then(() => toast.info('Cancel requested.')).catch(() => toast.error('Could not cancel.'))
  }

  return (
    <Card className="flex h-full min-h-0 flex-col gap-3 overflow-auto">
      <div>
        <label className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">Identity B</label>
        {identities.length > 0 && (
          <select
            value={identityBId ?? ''}
            onChange={(e) => setIdentityBId(e.target.value ? Number(e.target.value) : null)}
            className="mb-2 block w-full rounded-lg border border-hair bg-ink-950 px-2 py-1.5 text-xs outline-none focus:border-accent-500"
          >
            <option value="">Ad-hoc headers (below)</option>
            {identities.map((i) => (
              <option key={i.id} value={i.id}>
                {i.name}
                {i.isAnon ? ' (anon)' : ''}
              </option>
            ))}
          </select>
        )}
        <textarea
          value={identityB}
          onChange={(e) => setIdentityB(e.target.value)}
          disabled={identityBId != null}
          placeholder={'Cookie: session=OTHER_USER…\nAuthorization: Bearer OTHER…'}
          rows={3}
          spellCheck={false}
          className="block w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500 disabled:opacity-40"
        />
        <p className="mt-1 text-[11px] text-zinc-600">
          Pick a saved identity or paste headers. Leave both empty to test only anonymous (credential-stripped) access.
        </p>
      </div>

      <div className="space-y-2">
        <div className="inline-flex rounded-lg border border-hair bg-ink-950 p-0.5 text-xs">
          {(['range', 'list'] as const).map((m) => (
            <button key={m} onClick={() => setIdsMode(m)} className={`rounded px-2.5 py-1 capitalize ${idsMode === m ? 'bg-accent-500/15 text-accent-fg' : 'text-zinc-400'}`}>
              {m === 'range' ? 'ID range' : 'ID list'}
            </button>
          ))}
        </div>
        {idsMode === 'range' ? (
          <div className="flex flex-wrap items-end gap-2 text-xs">
            <NumField label="from" value={from} onChange={setFrom} />
            <NumField label="to" value={to} onChange={setTo} />
            <span className="text-zinc-600">object ids substituted into {'{{ID}}'}</span>
          </div>
        ) : (
          <textarea
            value={list}
            onChange={(e) => setList(e.target.value)}
            placeholder={'one object id per line\n1001\n1002\nuuid-…'}
            rows={4}
            spellCheck={false}
            className="block w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
          />
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        {running ? (
          <Button variant="danger" onClick={cancel}>
            <StopCircle size={15} /> Cancel
          </Button>
        ) : (
          <Button variant="loud" onClick={start} disabled={busy}>
            <KeyRound size={15} /> {busy ? 'Queuing…' : 'Run authz diff'}
          </Button>
        )}
        {running && (
          <span className="inline-flex items-center gap-1.5 text-amber-300">
            <Spinner /> {job?.progress ?? 'running…'}
          </span>
        )}
      </div>

      {job?.status === 'error' && <p className="text-sm text-red-300">Failed: {job.error}</p>}
      {result && (
        <div className="space-y-2 text-xs">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-zinc-400">
            <span>
              <span className="font-semibold text-zinc-200">{result.tested}</span> objects tested
            </span>
            {result.flagged > 0 ? (
              <Badge tone="red">{result.flagged} needs-review finding(s)</Badge>
            ) : (
              <Badge tone="green">nothing flagged</Badge>
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(result.verdicts).map(([v, n]) => (
              <Badge key={v} tone={v === 'missing_authz' ? 'red' : v === 'likely_idor' ? 'amber' : v === 'enforced' ? 'green' : 'zinc'}>
                {v}: {n}
              </Badge>
            ))}
          </div>
          {result.flagged > 0 && <p className="text-zinc-500">Flagged objects are on the Findings page (type: authz) — every one is needs-review; confirm the object truly belongs to another identity.</p>}
        </div>
      )}
    </Card>
  )
}
