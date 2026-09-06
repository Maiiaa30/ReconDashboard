import { useEffect, useState } from 'react'
import { Fingerprint, StopCircle } from 'lucide-react'
import { api, ApiError, type Job } from '../../api'
import { Badge, Button, Card, Spinner } from '../../components/ui'
import { useToast } from '../../components/Toast'
import { type BuiltRequest } from './shared'

// --- JWT RS256->HS256 alg-confusion confirm ----------------------------------
export function JwtPanel({
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
  const [token, setToken] = useState('')
  const [publicKeyPem, setPublicKeyPem] = useState('')
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

  const result =
    (job?.status === 'done' ? (job.result as { host: string; confirmed: number; source?: string; reason?: string } | null) : null) ?? null
  const running = job != null && ['queued', 'running'].includes(job.status)

  async function start() {
    if (busy || running) return
    const req = build()
    if (!req.url) return toast.error('Enter a URL first.')
    if (![req.url, req.body ?? '', ...Object.values(req.headers)].some((s) => String(s).includes('{{JWT}}'))) {
      return toast.error('Mark the token slot with {{JWT}} first.')
    }
    if (!token.trim()) return toast.error('Paste the original RS256 token.')
    if (!(await confirmActive('Confirm JWT alg confusion?', 'JWT confusion confirm'))) return
    setBusy(true)
    setJob(null)
    try {
      const { jobId: id } = await api.jwtConfuse(domainId, {
        template: req,
        token: token.trim(),
        publicKeyPem: publicKeyPem.trim() || undefined,
        confirm: passive,
      })
      setJobId(id)
      toast.success(`JWT confusion confirm queued (#${id}).`)
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

  return (
    <Card className="flex h-full min-h-0 flex-col gap-3 overflow-auto">
      <p className="text-xs text-zinc-500">
        Forges an HS256 token signed with the server’s <span className="text-zinc-300">public</span> key (fetched from{' '}
        <code className="rounded bg-ink-800 px-1 font-mono">/.well-known/jwks.json</code>, <code className="rounded bg-ink-800 px-1 font-mono">/jwks.json</code>, or the
        TLS cert) and confirms via a differential: forged accepted like the valid token while a wrong-key control is rejected. A hit is a critical A07 finding.
      </p>
      <label className="block">
        <span className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">Original token (RS256/ES256/PS256, {'{{JWT}}'} in the request)</span>
        <textarea
          value={token}
          onChange={(e) => setToken(e.target.value)}
          spellCheck={false}
          rows={3}
          placeholder="eyJhbGciOiJSUzI1Ni...."
          className="block w-full rounded-lg border border-hair bg-ink-950 px-2 py-1.5 font-mono text-xs outline-none focus:border-accent-500"
        />
      </label>
      <label className="block">
        <span className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">Public key PEM (optional — override jwks/cert lookup)</span>
        <textarea
          value={publicKeyPem}
          onChange={(e) => setPublicKeyPem(e.target.value)}
          spellCheck={false}
          rows={3}
          placeholder="-----BEGIN PUBLIC KEY-----"
          className="block w-full rounded-lg border border-hair bg-ink-950 px-2 py-1.5 font-mono text-xs outline-none focus:border-accent-500"
        />
      </label>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        {running ? (
          <Button variant="danger" onClick={cancel}>
            <StopCircle size={15} /> Cancel
          </Button>
        ) : (
          <Button variant="loud" onClick={start} disabled={busy}>
            <Fingerprint size={15} /> {busy ? 'Queuing…' : 'Confirm alg confusion'}
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
              <Badge tone="red">confirmed</Badge>
              <p className="text-red-200">✓ Forged HS256(public key) token accepted — key source: {result.source}.</p>
              <p className="text-zinc-500">Filed as a critical A07 finding on the Findings page.</p>
            </>
          ) : (
            <Badge tone="green">not confirmed{result.reason ? ` (${result.reason})` : ''}</Badge>
          )}
        </div>
      )}
    </Card>
  )
}
