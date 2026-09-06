import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Repeat, ChevronRight, Trash2, Search, Lock, AlertTriangle } from 'lucide-react'
import { api, type Capture } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, SkeletonList } from '../components/ui'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/Confirm'
import { AttachToFinding } from '../components/AttachToFinding'
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
  if (c.hasBody || c.body) {
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

// Server-side page size for keyset pagination; "Load more" fetches older pages.
const PAGE_SIZE = 100

export function Traffic({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const toast = useToast()
  const ask = useConfirm()
  const [captures, setCaptures] = useState<Capture[]>([])
  const [loaded, setLoaded] = useState(false)
  const [query, setQuery] = useState('')
  const [method, setMethod] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const [summary, setSummary] = useState<{ total: number; byMethod: Record<string, number> } | null>(null)
  // The live 2s poll refreshes the newest page. Once the operator pages into
  // history it pauses so appended older pages aren't clobbered; a filter change
  // or Refresh resumes it.
  const [pagedBack, setPagedBack] = useState(false)
  const [status, setStatus] = useState<{ enabled: boolean; extensionSeenAt: number | null } | null>(null)
  const cursorRef = useRef<string | null>(null)
  cursorRef.current = nextCursor

  const q = useMemo(() => ({ method: method || undefined, q: query.trim() || undefined }), [method, query])

  // Warn if capture can't work: disabled on the server, or no recent sign of the
  // extension (it polls /targets every ~60s while enabled).
  const extAlert = useMemo(() => {
    if (!status) return null
    if (!status.enabled) return 'Capture is disabled on the server — set CAPTURE_TOKEN in the dashboard .env and recreate the backend.'
    if (!status.extensionSeenAt || Date.now() - status.extensionSeenAt > 90_000)
      return 'Capture extension not detected. Install it, turn it on, and point it at this dashboard (see extension/README.md).'
    return null
  }, [status])

  // Load (or refresh) the newest page for the current filter.
  const load = useCallback(() => {
    if (!selected) return
    api
      .captures(selected.id, { ...q, limit: PAGE_SIZE })
      .then((r) => {
        setCaptures(r.captures)
        setNextCursor(r.nextCursor)
        setPagedBack(false)
      })
      .catch(() => {})
      .finally(() => setLoaded(true))
  }, [selected, q])

  const loadMore = useCallback(() => {
    const cursor = cursorRef.current
    if (!selected || !cursor || loadingMore) return
    setLoadingMore(true)
    setPagedBack(true) // pause the live poll while browsing history
    api
      .captures(selected.id, { ...q, limit: PAGE_SIZE, cursor })
      .then((r) => {
        setCaptures((prev) => [...prev, ...r.captures])
        setNextCursor(r.nextCursor)
      })
      .catch(() => toast.error('Failed to load more requests.'))
      .finally(() => setLoadingMore(false))
  }, [selected, q, loadingMore, toast])

  const loadSummary = useCallback(() => {
    if (!selected) return
    api
      .capturesSummary(selected.id, { q: q.q })
      .then(setSummary)
      .catch(() => setSummary(null))
  }, [selected, q.q])

  // Debounced so typing in the search box doesn't fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      load()
      loadSummary()
    }, 200)
    return () => clearTimeout(t)
  }, [load, loadSummary])

  // Live tail: refresh the newest page + summary every 2s, but only while the
  // operator is on the first page (not paging back through history).
  usePoll(
    () => {
      if (!selected) return
      if (!pagedBack) {
        load()
        loadSummary()
      }
      api.captureStatus().then(setStatus).catch(() => {})
    },
    2000, // poll briskly so captures appear ~live as you browse
    !!selected,
    selected?.id,
  )

  async function sendToReplay(c: Capture) {
    // The list omits the body — fetch the full capture so Replay gets it.
    let body = c.body ?? null
    if (c.hasBody && body == null) {
      try {
        body = (await api.capture(c.id)).capture.body
      } catch {
        /* fall back to no body */
      }
    }
    setPendingReplay({ method: c.method, url: c.url, headers: c.headers, body })
    navigate('replay')
  }

  async function clearAll() {
    if (!selected) return
    const ok = await ask({
      title: 'Clear captured traffic?',
      message: `Delete all ${summary?.total ?? captures.length} captured request(s) for ${selected.host}. This can't be undone.`,
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
      ) : captures.length === 0 && !query && !method ? (
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
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[16rem] flex-1">
              <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by method, host or URL…"
                spellCheck={false}
                className="w-full rounded-lg border border-hair bg-ink-950 py-2 pl-8 pr-3 font-mono text-xs outline-none focus:border-accent-500"
              />
            </div>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="rounded-lg border border-hair bg-ink-950 px-3 py-2 text-xs outline-none focus:border-accent-500"
            >
              <option value="">All methods{summary ? ` (${summary.total})` : ''}</option>
              {summary &&
                Object.entries(summary.byMethod)
                  .sort((a, b) => b[1] - a[1])
                  .map(([m, n]) => (
                    <option key={m} value={m}>
                      {m} ({n})
                    </option>
                  ))}
            </select>
            {summary && (
              <span className="text-[11px] text-zinc-600">
                {captures.length}
                {summary.total > captures.length ? ` of ${summary.total}` : ''} shown
              </span>
            )}
          </div>
          {captures.length === 0 ? (
            <Empty>No captured requests match this filter.</Empty>
          ) : (
            captures.map((c) => (
              <CaptureRow
                key={c.id}
                c={c}
                domainId={c.domainId ?? selected.id}
                onSend={() => sendToReplay(c)}
                onDelete={() => deleteOne(c.id)}
              />
            ))
          )}
          {nextCursor && (
            <div className="flex justify-center pt-1">
              <button
                onClick={loadMore}
                disabled={loadingMore}
                className="rounded-lg border border-hair px-4 py-1.5 text-sm text-zinc-300 transition hover:border-hair-strong hover:bg-ink-800 disabled:opacity-50"
              >
                {loadingMore ? 'Loading…' : 'Load more'}
              </button>
            </div>
          )}
          {pagedBack && (
            <div className="flex justify-center">
              <button onClick={load} className="text-[11px] text-zinc-500 hover:text-zinc-300">
                Live paused while browsing history — jump to latest
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function CaptureRow({
  c,
  domainId,
  onSend,
  onDelete,
}: {
  c: Capture
  domainId: number
  onSend: () => void
  onDelete: () => void
}) {
  const [open, setOpen] = useState(false)
  const [body, setBody] = useState<string | null>(c.body)
  const [bodyLoading, setBodyLoading] = useState(false)
  const { tags, interesting, authed } = useMemo(() => analyze(c), [c])

  // Plain-text request for attaching as evidence. Includes the body when it's
  // already loaded (expand the row to fetch it); request-only is fine otherwise.
  const reqStr = useMemo(() => {
    const headerLines = c.headers.map(([k, v]) => `${k}: ${v}`).join('\n')
    return `${c.method} ${c.url}\n${headerLines}${body ? `\n\n${body}` : ''}`.trimEnd()
  }, [c, body])

  async function toggle() {
    const next = !open
    setOpen(next)
    // Body is omitted from the list — fetch it the first time the row expands.
    if (next && c.hasBody && body == null && !bodyLoading) {
      setBodyLoading(true)
      try {
        setBody((await api.capture(c.id)).capture.body)
      } catch {
        /* leave body null */
      } finally {
        setBodyLoading(false)
      }
    }
  }

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
        <AttachToFinding domainId={domainId} request={reqStr} />
        <button
          onClick={onDelete}
          title="Delete this request"
          className="rounded p-1.5 text-zinc-500 transition hover:bg-red-950/40 hover:text-red-300"
        >
          <Trash2 size={14} />
        </button>
      </div>
      <button
        onClick={toggle}
        className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
      >
        <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
        {c.headers.length} header(s){c.hasBody || c.body ? ' · has body' : ''}
      </button>
      {open && (
        <div className="mt-2 space-y-2">
          <pre className="max-h-40 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 font-mono text-[11px] text-zinc-300">
            {c.headers.map(([k, v]) => `${k}: ${v}`).join('\n') || '(no headers captured)'}
          </pre>
          {(c.hasBody || body) && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">Body</div>
              <pre className="max-h-40 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 font-mono text-[11px] text-zinc-300 whitespace-pre-wrap break-all">
                {bodyLoading ? 'loading…' : (body ?? '(body unavailable)')}
              </pre>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
