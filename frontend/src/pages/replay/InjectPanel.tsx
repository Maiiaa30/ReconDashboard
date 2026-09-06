import { useEffect, useState } from 'react'
import { FlaskConical, StopCircle } from 'lucide-react'
import { api, ApiError, type Job } from '../../api'
import { Badge, Button, Card, Spinner } from '../../components/ui'
import { useToast } from '../../components/Toast'
import { type BuiltRequest, NumField } from './shared'

// --- Blind-injection confirmation --------------------------------------------
export function InjectPanel({
  domainId,
  passive,
  confirmActive,
  build,
  toast,
}: {
  domainId: number
  passive: boolean
  confirmActive: (title: string, what: string) => Promise<boolean>
  build: () => BuiltRequest
  toast: ReturnType<typeof useToast>
}) {
  const [baseValue, setBaseValue] = useState('1')
  const [truePayload, setTruePayload] = useState("1' AND '1'='1")
  const [falsePayload, setFalsePayload] = useState("1' AND '1'='2")
  const [sleepPayload, setSleepPayload] = useState("1' AND SLEEP(5)-- -")
  const [sleepSeconds, setSleepSeconds] = useState('5')
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

  const result = (job?.status === 'done' ? (job.result as { host: string; confirmed: number; findings: string[] } | null) : null) ?? null
  const running = job != null && ['queued', 'running'].includes(job.status)

  async function start() {
    if (busy || running) return
    const req = build()
    if (!req.url) return toast.error('Enter a URL first.')
    if (![req.url, req.body ?? '', ...Object.values(req.headers)].some((s) => String(s).includes('{{INJ}}'))) {
      return toast.error('Mark the injection point with {{INJ}} first.')
    }
    if (!(await confirmActive('Confirm injection?', 'Injection confirmation'))) return
    setBusy(true)
    setJob(null)
    try {
      const { jobId: id } = await api.injectConfirm(domainId, {
        template: req,
        baseValue,
        truePayload: truePayload || undefined,
        falsePayload: falsePayload || undefined,
        sleepPayload: sleepPayload || undefined,
        sleepSeconds: Number(sleepSeconds) || 0,
        confirm: passive,
      })
      setJobId(id)
      toast.success(`Injection confirmation queued (#${id}).`)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to start.')
    } finally {
      setBusy(false)
    }
  }
  async function cancel() {
    if (jobId == null) return
    await api.cancelJob(jobId).then(() => toast.info('Cancel requested.')).catch(() => toast.error('Could not cancel.'))
  }

  const field = (label: string, value: string, on: (s: string) => void, mono = true) => (
    <label className="block">
      <span className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">{label}</span>
      <input
        value={value}
        onChange={(e) => on(e.target.value)}
        spellCheck={false}
        className={`block w-full rounded-lg border border-hair bg-ink-950 px-2 py-1.5 text-xs outline-none focus:border-accent-500 ${mono ? 'font-mono' : ''}`}
      />
    </label>
  )

  return (
    <Card className="flex h-full min-h-0 flex-col gap-3 overflow-auto">
      <p className="text-xs text-zinc-500">Boolean: true renders like the baseline while false diverges. Time-based: the SLEEP payload delays the response ~k seconds (median of several samples). A confirmed hit is a high A03 finding.</p>
      {field('Baseline value ({{INJ}} = normal input)', baseValue, setBaseValue)}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {field('TRUE payload', truePayload, setTruePayload)}
        {field('FALSE payload', falsePayload, setFalsePayload)}
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <div className="sm:col-span-2">{field('SLEEP payload', sleepPayload, setSleepPayload)}</div>
        <NumField label="sleep seconds" value={sleepSeconds} onChange={setSleepSeconds} />
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        {running ? (
          <Button variant="danger" onClick={cancel}>
            <StopCircle size={15} /> Cancel
          </Button>
        ) : (
          <Button variant="loud" onClick={start} disabled={busy}>
            <FlaskConical size={15} /> {busy ? 'Queuing…' : 'Confirm injection'}
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
        <div className="space-y-1 text-xs">
          {result.confirmed > 0 ? (
            <>
              <Badge tone="red">{result.confirmed} confirmed</Badge>
              <ul className="mt-1 space-y-1">
                {result.findings.map((n, i) => (
                  <li key={i} className="text-red-200">✓ {n}</li>
                ))}
              </ul>
              <p className="text-zinc-500">Filed as high A03 finding(s) on the Findings page.</p>
            </>
          ) : (
            <Badge tone="green">not confirmed (no differential)</Badge>
          )}
        </div>
      )}
    </Card>
  )
}
