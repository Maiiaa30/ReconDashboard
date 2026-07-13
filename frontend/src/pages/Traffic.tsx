import { useMemo, useState } from 'react'
import { Repeat, ChevronRight, Trash2, Search, Lock, AlertTriangle } from 'lucide-react'
import { api, type Capture } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, SkeletonList } from '../components/ui'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/Confirm'
import { timeAgo } from '../lib/format'
import { setPendingReplay } from '../lib/replayHandoff'

const METHOD_TONE: Record<string, 'green' | 'blue' | 'amber' | 'red' | 'zinc'> = {
  GET: 'green',
  POST: 'blue',
  PUT: 'amber',
  PATCH: 'amber',
  DELETE: 'red',
}

function shortUrl(u: string): string {
  try {
    const x = new URL(u)
    return x.pathname + x.search
  } catch {
    return u
  }
}

// Paths that tend to be worth a closer look on an engagement.
const SENSITIVE_RE =
  /(login|logout|signin|sign-in|auth|oauth|sso|token|jwt|password|passwd|pwd|reset|otp|2fa|mfa|verify|admin|account|payment|checkout|order|invoice|upload|import|export|graphql|wp-json|wp-admin|wp-login|session|secret|api[-_/]?key|debug|actuator)/i

type Tone = 'amber' | 'blue' | 'purple' | 'green' | 'red' | 'zinc'
function header(c: Capture, name: string): string | undefined {
  return c.headers.find(([k]) => k.toLowerCase() === name)?.[1]
}

// Derive at-a-glance signals so the eye lands on the requests worth testing:
// state-changing methods, query params (injection surface), request bodies,
// and sensitive-looking paths. `interesting` drives the row highlight.
function analyze(c: Capture): { tags: { label: string; tone: Tone }[]; interesting: boolean; authed: boolean } {
  const tags: { label: string; tone: Tone }[] = []
  let interesting = false
  const method = c.method.toUpperCase()
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    tags.push({ label: 'write', tone: 'amber' })
    interesting = true
  }
  let params = 0
  let path = c.url
  try {
    const u = new URL(c.url)
    params = [...u.searchParams].length
    path = u.pathname + u.search
  } catch {
    /* keep raw */
  }
  if (params) {
    tags.push({ label: `${params} param${params > 1 ? 's' : ''}`, tone: 'blue' })
    interesting = true
  }
  if (c.body) {
    const ct = (header(c, 'content-type') || '').toLowerCase()
    const label = ct.includes('json')
      ? 'json'
      : ct.includes('form-data')
        ? 'multipart'
        : ct.includes('urlencoded')
          ? 'form'
          : ct.includes('graphql')
            ? 'graphql'
            : 'body'
    tags.push({ label, tone: 'green' })
    interesting = true
  }
  if (SENSITIVE_RE.test(path)) {
    tags.push({ label: 'sensitive', tone: 'red' })
    interesting = true
  }
  const authed = !!(header(c, 'authorization') || header(c, 'cookie'))
  return { tags, interesting, authed }
}

export function Traffic({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const toast = useToast()
  const ask = useConfirm()
  const [captures, setCaptures] = useState<Capture[]>([])
  const [loaded, setLoaded] = useState(false)
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<{ enabled: boolean; extensionSeenAt: number | null } | null>(null)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return captures
    return captures.filter((c) => `${c.method} ${c.host} ${c.url}`.toLowerCase().includes(q))
  }, [captures, query])

  // Warn if capture can't work: disabled on the server, or no recent sign of the
  // extension (it polls /targets every ~60s while enabled).
  const extAlert = useMemo(() => {
    if (!status) return null
    if (!status.enabled) return 'Capture is disabled on the server — set CAPTURE_TOKEN in the dashboard .env and recreate the backend.'
    if (!status.extensionSeenAt || Date.now() - status.extensionSeenAt > 90_000)
      return 'Capture extension not detected. Install it, turn it on, and point it at this dashboard (see extension/README.md).'
    return null
  }, [status])

  usePoll(
    () => {
      if (!selected) return
      api
        .captures(selected.id, 300)
        .then((r) => setCaptures(r.captures))
        .catch(() => {})
        .finally(() => setLoaded(true))
      api
        .captureStatus()
        .then(setStatus)
        .catch(() => {})
    },
    2000, // poll briskly so captures appear ~live as you browse
    !!selected,
    selected?.id,
  )

  function sendToReplay(c: Capture) {
    setPendingReplay({ method: c.method, url: c.url, headers: c.headers, body: c.body })
    navigate('replay')
  }

  async function clearAll() {
    if (!selected) return
    const ok = await ask({
      title: 'Clear captured traffic?',
      message: `Delete all ${captures.length} captured request(s) for ${selected.host}. This can't be undone.`,
      confirmLabel: 'Clear',
      tone: 'danger',
    })
    if (!ok) return
    try {
      const { cleared } = await api.clearCaptures(selected.id)
      toast.success(`Cleared ${cleared} request(s).`)
      setCaptures([])
    } catch {
      toast.error('Failed to clear.')
    }
  }

  async function deleteOne(id: number) {
    try {
      await api.deleteCapture(id)
      setCaptures((prev) => prev.filter((c) => c.id !== id))
    } catch {
      toast.error('Failed to delete request.')
    }
  }

  if (!selected) return <Empty>Select a domain to see captured traffic for it.</Empty>

  return (
    <div>
      <PageHeader
        title="Traffic"
        subtitle={`${selected.host} — requests captured by the browser extension, ready to replay`}
        actions={
          captures.length > 0 ? (
            <Button variant="ghost" onClick={clearAll}>
              <Trash2 size={15} /> Clear
            </Button>
          ) : undefined
        }
      />

      {extAlert && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-amber-900/50 bg-amber-950/20 p-3 text-sm text-amber-200">
          <AlertTriangle size={16} className="mt-0.5 shrink-0 text-amber-400" />
          <span>{extAlert}</span>
        </div>
      )}

      {!loaded ? (
        <SkeletonList rows={5} />
      ) : captures.length === 0 ? (
        <Empty>
          <div className="space-y-1.5">
            <div>No captured requests yet for this target.</div>
            <div className="text-xs leading-relaxed text-zinc-500">
              Traffic is fed by the <span className="text-zinc-300">capture browser extension</span>: install it, set your dashboard
              URL + the <span className="font-mono">CAPTURE_TOKEN</span>, turn it on, and browse the target. Requests to hosts within a
              tracked domain show up here — click <span className="text-zinc-300">Send to Replay</span> to open one in the Repeater.
            </div>
          </div>
        </Empty>
      ) : (
        <div className="space-y-2">
          <div className="relative">
            <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by method, host or URL…"
              spellCheck={false}
              className="w-full rounded-lg border border-hair bg-ink-950 py-2 pl-8 pr-3 font-mono text-xs outline-none focus:border-accent-500"
            />
            {query && (
              <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[11px] text-zinc-600">
                {filtered.length}/{captures.length}
              </span>
            )}
          </div>
          {filtered.length === 0 ? (
            <Empty>No captured requests match “{query}”.</Empty>
          ) : (
            filtered.map((c) => (
              <CaptureRow key={c.id} c={c} onSend={() => sendToReplay(c)} onDelete={() => deleteOne(c.id)} />
            ))
          )}
        </div>
      )}
    </div>
  )
}

function CaptureRow({ c, onSend, onDelete }: { c: Capture; onSend: () => void; onDelete: () => void }) {
  const [open, setOpen] = useState(false)
  const { tags, interesting, authed } = useMemo(() => analyze(c), [c])
  return (
    <Card className={interesting ? 'border-l-2 border-l-accent-500' : ''}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={METHOD_TONE[c.method] ?? 'zinc'}>{c.method}</Badge>
        <span className="font-mono text-xs text-zinc-500">{c.host}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-sm text-zinc-200" title={c.url}>
          {shortUrl(c.url)}
        </span>
        {authed && <Lock size={12} className="text-zinc-500" aria-label="sends Cookie/Authorization" />}
        {tags.map((t, i) => (
          <Badge key={i} tone={t.tone}>
            {t.label}
          </Badge>
        ))}
        <span className="text-[11px] text-zinc-600">{timeAgo(new Date(c.createdAt).getTime())}</span>
        <Button variant="ghost" onClick={onSend}>
          <Repeat size={14} /> Send to Replay
        </Button>
        <button
          onClick={onDelete}
          title="Delete this request"
          className="rounded p-1.5 text-zinc-500 transition hover:bg-red-950/40 hover:text-red-300"
        >
          <Trash2 size={14} />
        </button>
      </div>
      <button
        onClick={() => setOpen((v) => !v)}
        className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
      >
        <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
        {c.headers.length} header(s){c.body ? ' · has body' : ''}
      </button>
      {open && (
        <div className="mt-2 space-y-2">
          <pre className="max-h-40 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 font-mono text-[11px] text-zinc-300">
            {c.headers.map(([k, v]) => `${k}: ${v}`).join('\n') || '(no headers captured)'}
          </pre>
          {c.body && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">Body</div>
              <pre className="max-h-40 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 font-mono text-[11px] text-zinc-300 whitespace-pre-wrap break-all">
                {c.body}
              </pre>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
