import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Send, Crosshair, Repeat, ChevronRight, AlertTriangle, Clock, Ruler, StopCircle, History, Network } from 'lucide-react'
import { api, ApiError, type ReplayResponse, type IntruderResult, type IntruderAttempt, type Job, type Wordlist, type ReplayHistoryItem, type SitemapHost } from '../api'
import { useApp } from '../state'
import { Badge, Button, Card, Empty, PageHeader, Spinner } from '../components/ui'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/Confirm'
import { AttachToFinding } from '../components/AttachToFinding'
import { takePendingReplay } from '../lib/replayHandoff'
import { timeAgo } from '../lib/format'
import { copyText } from '../lib/clipboard'

export type BuiltReq = { method: string; url: string; headers: [string, string][]; body?: string | null }

function shortUrl(u: string): string {
  try {
    const x = new URL(u)
    return x.pathname + x.search
  } catch {
    return u
  }
}

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const
const PAYLOAD_MARKER = '{{PAYLOAD}}'
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

function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim()
    if (!t) continue
    const idx = t.indexOf(':')
    if (idx <= 0) continue
    const name = t.slice(0, idx).trim()
    if (name) out[name] = t.slice(idx + 1).trim()
  }
  return out
}

function statusTone(s: number): 'green' | 'amber' | 'red' | 'blue' | 'zinc' {
  if (s === 0) return 'red'
  if (s >= 200 && s < 300) return 'green'
  if (s >= 300 && s < 400) return 'blue'
  if (s === 401 || s === 403 || s === 429) return 'amber'
  if (s >= 400) return 'red'
  return 'zinc'
}

export function Replay() {
  const { selected } = useApp()
  const toast = useToast()
  const ask = useConfirm()
  const [mode, setMode] = useState<'repeater' | 'intruder' | 'sitemap'>('repeater')

  // Shared request editor state.
  const [method, setMethod] = useState<(typeof METHODS)[number]>('GET')
  const [url, setUrl] = useState('')
  const [headersText, setHeadersText] = useState('')
  const [bodyText, setBodyText] = useState('')
  const [followRedirects, setFollowRedirects] = useState(false)

  // Load a request (from the Traffic handoff or a history entry) into the editor.
  const applyRequest = useCallback((r: BuiltReq) => {
    if ((METHODS as readonly string[]).includes(r.method)) setMethod(r.method as (typeof METHODS)[number])
    setUrl(r.url)
    setHeadersText(r.headers.map(([k, v]) => `${k}: ${v}`).join('\n'))
    setBodyText(typeof r.body === 'string' ? r.body : '')
  }, [])

  // Prefill the URL from the selected target the first time (and when switching to
  // a target while the box is still empty/pointing at the old host).
  const lastHost = useRef<string | null>(null)
  useEffect(() => {
    if (!selected) return
    const prevDefault = `https://${lastHost.current}/`
    // Functional update reads the CURRENT url, not a stale closure — so it won't
    // clobber a URL just set by the "Send to Replay" handoff (and stays correct
    // under React StrictMode's double-invoked effects).
    setUrl((cur) => (!cur || cur === prevDefault ? `https://${selected.host}/` : cur))
    lastHost.current = selected.host
  }, [selected]) // eslint-disable-line react-hooks/exhaustive-deps

  // Consume a request handed over from the Traffic page ("Send to Replay").
  useEffect(() => {
    const p = takePendingReplay()
    if (!p) return
    setMode('repeater')
    applyRequest({ method: p.method, url: p.url, headers: p.headers, body: p.body })
  }, [applyRequest])

  if (!selected) return <Empty>Select a domain to compose and replay requests against it.</Empty>

  const passive = selected.mode !== 'active_authorized'

  async function confirmActive(title: string, what: string): Promise<boolean> {
    if (!passive) return true
    return ask({
      title,
      message: `${selected!.host} is passive_only.\n\n${what} sends real traffic to the target. Only continue if you are authorized to actively test it.`,
      confirmLabel: 'Send anyway',
      tone: 'danger',
    })
  }

  return (
    <div className="flex min-h-[calc(100dvh-7rem)] flex-col">
      <PageHeader
        title="Replay"
        subtitle={`${selected.host} — compose, send and fuzz requests (server-side, scoped to this target)`}
        actions={
          <div className="inline-flex rounded-lg border border-hair bg-ink-850 p-0.5">
            <ModeTab active={mode === 'repeater'} onClick={() => setMode('repeater')} icon={<Repeat size={14} />} label="Repeater" />
            <ModeTab active={mode === 'intruder'} onClick={() => setMode('intruder')} icon={<Crosshair size={14} />} label="Intruder" />
            <ModeTab active={mode === 'sitemap'} onClick={() => setMode('sitemap')} icon={<Network size={14} />} label="Sitemap" />
          </div>
        }
      />

      {mode === 'sitemap' ? (
        <SitemapPanel
          domainId={selected.id}
          onOpen={(m, u) => {
            if ((METHODS as readonly string[]).includes(m)) setMethod(m as (typeof METHODS)[number])
            setUrl(u)
            setMode('repeater')
          }}
        />
      ) : (
      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-2 lg:grid-rows-1">
        <RequestEditor
          mode={mode}
          method={method}
          setMethod={setMethod}
          url={url}
          setUrl={setUrl}
          headersText={headersText}
          setHeadersText={setHeadersText}
          bodyText={bodyText}
          setBodyText={setBodyText}
          followRedirects={followRedirects}
          setFollowRedirects={setFollowRedirects}
        />
        {mode === 'repeater' ? (
          <RepeaterPanel
            domainId={selected.id}
            passive={passive}
            confirmActive={confirmActive}
            applyRequest={applyRequest}
            reqStr={`${method} ${url}\n${headersText}\n\n${bodyText}`.trimEnd()}
            build={() => ({
              method,
              url,
              headers: parseHeaders(headersText),
              body: method === 'GET' || method === 'HEAD' ? undefined : bodyText || undefined,
              followRedirects,
            })}
            toast={toast}
          />
        ) : (
          <IntruderPanel
            domainId={selected.id}
            passive={passive}
            confirmActive={confirmActive}
            build={() => ({
              method,
              url,
              headers: parseHeaders(headersText),
              body: method === 'GET' || method === 'HEAD' ? undefined : bodyText || undefined,
              followRedirects,
            })}
            toast={toast}
          />
        )}
      </div>
      )}
    </div>
  )
}

function ModeTab({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition ${
        active ? 'bg-accent-500/15 text-accent-fg' : 'text-zinc-400 hover:text-zinc-200'
      }`}
    >
      {icon} {label}
    </button>
  )
}

const SITEMAP_METHOD_TONE: Record<string, string> = {
  GET: 'text-green-300 bg-green-500/10',
  POST: 'text-blue-300 bg-blue-500/10',
  PUT: 'text-amber-300 bg-amber-500/10',
  PATCH: 'text-amber-300 bg-amber-500/10',
  DELETE: 'text-red-300 bg-red-500/10',
}

// Endpoint tree assembled from captured traffic + fuzz hits + discovery. Clicking
// a row loads that method+URL into the Repeater.
function SitemapPanel({ domainId, onOpen }: { domainId: number; onOpen: (method: string, url: string) => void }) {
  const [hosts, setHosts] = useState<SitemapHost[]>([])
  const [loaded, setLoaded] = useState(false)
  const [filter, setFilter] = useState('')
  useEffect(() => {
    setLoaded(false)
    api
      .sitemap(domainId)
      .then((r) => setHosts(r.hosts))
      .catch(() => setHosts([]))
      .finally(() => setLoaded(true))
  }, [domainId])

  const q = filter.trim().toLowerCase()
  const shown = useMemo(
    () =>
      hosts
        .map((h) => ({
          ...h,
          endpoints: q ? h.endpoints.filter((e) => e.path.toLowerCase().includes(q) || e.method.toLowerCase().includes(q)) : h.endpoints,
        }))
        .filter((h) => h.endpoints.length),
    [hosts, q],
  )
  const total = shown.reduce((n, h) => n + h.endpoints.length, 0)

  return (
    <Card className="flex min-h-0 flex-1 flex-col">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Network size={15} className="text-accent-fg" />
        <h2 className="text-sm font-semibold text-zinc-200">Sitemap</h2>
        <span className="text-xs text-zinc-500">{total} endpoint(s) — captured, fuzzed & discovered. Click one to load it.</span>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter path/method…"
          className="ml-auto w-56 rounded-lg border border-hair bg-ink-950 px-3 py-1 text-xs outline-none focus:border-accent-500"
        />
      </div>
      {!loaded ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : shown.length === 0 ? (
        <Empty>No endpoints yet. Capture traffic (extension), run API discovery, or fuzz to populate the sitemap.</Empty>
      ) : (
        <div className="min-h-0 flex-1 space-y-3 overflow-auto">
          {shown.map((h) => (
            <div key={h.host}>
              <div className="mb-1 flex items-center gap-2">
                <span className="font-mono text-sm text-zinc-200">{h.host}</span>
                <span className="text-xs text-zinc-500">{h.endpoints.length}</span>
              </div>
              <div className="space-y-0.5">
                {h.endpoints.map((e, i) => (
                  <button
                    key={i}
                    onClick={() => onOpen(e.method, e.url)}
                    title={`Load ${e.method} ${e.url} into the Repeater`}
                    className="flex w-full items-center gap-2 rounded border border-hair bg-ink-900/50 px-2 py-1 text-left transition hover:border-accent-500/40 hover:bg-ink-850"
                  >
                    <span className={`w-14 shrink-0 rounded px-1 text-center font-mono text-[10px] ${SITEMAP_METHOD_TONE[e.method] ?? 'text-zinc-300 bg-ink-800'}`}>
                      {e.method}
                    </span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-300">{e.path}</span>
                    {e.status != null && <span className="shrink-0 font-mono text-[10px] text-zinc-500">{e.status}</span>}
                    <span className="shrink-0 text-[10px] text-zinc-600">{e.source}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

type BuiltRequest = { method: string; url: string; headers: Record<string, string>; body?: string; followRedirects: boolean }

function RequestEditor(props: {
  mode: 'repeater' | 'intruder'
  method: (typeof METHODS)[number]
  setMethod: (m: (typeof METHODS)[number]) => void
  url: string
  setUrl: (s: string) => void
  headersText: string
  setHeadersText: (s: string) => void
  bodyText: string
  setBodyText: (s: string) => void
  followRedirects: boolean
  setFollowRedirects: (b: boolean) => void
}) {
  const bodyless = props.method === 'GET' || props.method === 'HEAD'
  return (
    <Card className="flex h-full min-h-0 flex-col">
      <div className="mb-2 flex items-center gap-2">
        <select
          value={props.method}
          onChange={(e) => props.setMethod(e.target.value as (typeof METHODS)[number])}
          className="rounded-lg border border-hair bg-ink-950 px-2 py-2 font-mono text-xs outline-none focus:border-accent-500"
        >
          {METHODS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <input
          value={props.url}
          onChange={(e) => props.setUrl(e.target.value)}
          placeholder="https://host/path"
          spellCheck={false}
          className="min-w-0 flex-1 rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
        />
      </div>
      {props.mode === 'intruder' && (
        <p className="mb-2 text-xs text-zinc-500">
          Mark payload positions with <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{'{{P1}}'}</code>,{' '}
          <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{'{{P2}}'}</code>, … (or{' '}
          <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{PAYLOAD_MARKER}</code> = P1) — in the URL, a
          header value, or the body.
        </p>
      )}
      <label className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">Headers (one per line: Name: Value)</label>
      <textarea
        value={props.headersText}
        onChange={(e) => props.setHeadersText(e.target.value)}
        placeholder={'Cookie: session=…\nAuthorization: Bearer …\nContent-Type: application/json'}
        rows={5}
        spellCheck={false}
        className="mb-2 block min-h-0 w-full flex-1 resize-none rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
      />
      <label className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">
        Body {bodyless && <span className="text-zinc-600">(ignored for {props.method})</span>}
      </label>
      <textarea
        value={props.bodyText}
        onChange={(e) => props.setBodyText(e.target.value)}
        placeholder={bodyless ? '' : '{"code":"' + PAYLOAD_MARKER + '"}'}
        rows={6}
        spellCheck={false}
        disabled={bodyless}
        className="block min-h-0 w-full flex-1 resize-none rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500 disabled:opacity-50"
      />
    </Card>
  )
}

// --- Repeater ---------------------------------------------------------------
function RepeaterPanel({
  domainId,
  passive,
  confirmActive,
  applyRequest,
  reqStr,
  build,
  toast,
}: {
  domainId: number
  passive: boolean
  confirmActive: (title: string, what: string) => Promise<boolean>
  applyRequest: (r: BuiltReq) => void
  reqStr: string
  build: () => BuiltRequest
  toast: ReturnType<typeof useToast>
}) {
  const [busy, setBusy] = useState(false)
  const [resp, setResp] = useState<ReplayResponse | null>(null)
  const [showHeaders, setShowHeaders] = useState(false)
  const [view, setView] = useState<'body' | 'preview'>('body')
  const [runScripts, setRunScripts] = useState(false)
  const [history, setHistory] = useState<ReplayHistoryItem[]>([])

  const loadHistory = useCallback(() => {
    api
      .replayHistory(domainId, 100)
      .then((r) => setHistory(r.history))
      .catch(() => {})
  }, [domainId])
  useEffect(loadHistory, [loadHistory])

  async function send() {
    if (busy) return
    const req = build()
    if (!req.url) return toast.error('Enter a URL first.')
    if (!(await confirmActive('Send this request?', 'Replay'))) return
    setBusy(true)
    try {
      const { response } = await api.replaySend({ domainId, ...req, confirm: passive })
      setResp(response)
      loadHistory() // the send was recorded server-side — refresh the list
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Request failed.')
    } finally {
      setBusy(false)
    }
  }

  // Open a past request: restore it into the editor and show its stored response.
  async function openHistory(h: ReplayHistoryItem) {
    applyRequest({ method: h.method, url: h.url, headers: h.reqHeaders, body: h.reqBody })
    try {
      const { entry } = await api.replayHistoryDetail(h.id)
      setResp({
        status: entry.status ?? 0,
        statusText: entry.statusText ?? '',
        headers: entry.respHeaders ?? [],
        body: entry.respBody ?? '',
        bodyBytes: entry.respBytes ?? 0,
        truncated: false,
        timeMs: entry.timeMs ?? 0,
        finalUrl: entry.url,
        redirects: [],
      })
      setView('body')
    } catch {
      /* detail fetch failed — the request is still restored */
    }
  }

  async function clearHistory() {
    try {
      await api.clearReplayHistory(domainId)
      setHistory([])
    } catch {
      toast.error('Failed to clear history.')
    }
  }

  // Response as a plain-text blob for attaching as evidence (body capped).
  const respStr = resp
    ? `HTTP ${resp.status} ${resp.statusText}\n${resp.headers.map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${(
        resp.body ?? ''
      ).slice(0, 10000)}`.trimEnd()
    : undefined

  return (
    <Card className="flex h-full min-h-0 flex-col">
      <div className="mb-3 flex items-center gap-2">
        <Button variant="loud" onClick={send} disabled={busy}>
          <Send size={15} /> {busy ? 'Sending…' : 'Send'}
        </Button>
        {resp && (
          <div className="flex items-center gap-3 text-xs text-zinc-400">
            <Badge tone={statusTone(resp.status)}>
              {resp.status} {resp.statusText}
            </Badge>
            <span className="inline-flex items-center gap-1">
              <Clock size={12} /> {resp.timeMs}ms
            </span>
            <span className="inline-flex items-center gap-1">
              <Ruler size={12} /> {resp.bodyBytes} B{resp.truncated ? '+' : ''}
            </span>
          </div>
        )}
        <div className="ml-auto">
          <AttachToFinding domainId={domainId} request={reqStr} response={respStr} />
        </div>
      </div>

      {!resp ? (
        <div className="flex flex-1 items-center justify-center rounded-lg border border-dashed border-hair bg-ink-900/50 p-6 text-sm text-zinc-500">
          Compose a request on the left and hit Send — the response appears here.
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-2">
          {resp.redirects.length > 0 && (
            <div className="text-xs text-zinc-500">
              followed {resp.redirects.length} redirect(s) → <span className="font-mono text-zinc-400 break-all">{resp.finalUrl}</span>
            </div>
          )}
          <button
            onClick={() => setShowHeaders((v) => !v)}
            className="inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
          >
            <ChevronRight size={12} className={showHeaders ? 'rotate-90 transition' : 'transition'} /> {resp.headers.length} response
            headers
          </button>
          {showHeaders && (
            <pre className="max-h-40 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 font-mono text-[11px] text-zinc-300">
              {resp.headers.map(([k, v]) => `${k}: ${v}`).join('\n')}
            </pre>
          )}
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="mb-1 flex flex-wrap items-center gap-2">
              <div className="inline-flex rounded-lg border border-hair bg-ink-950 p-0.5 text-xs">
                <button
                  onClick={() => setView('body')}
                  className={`rounded px-2.5 py-1 ${view === 'body' ? 'bg-accent-500/15 text-accent-fg' : 'text-zinc-400'}`}
                >
                  Body
                </button>
                <button
                  onClick={() => setView('preview')}
                  className={`rounded px-2.5 py-1 ${view === 'preview' ? 'bg-accent-500/15 text-accent-fg' : 'text-zinc-400'}`}
                >
                  Preview
                </button>
              </div>
              {resp.truncated && <span className="text-[10px] text-amber-400">truncated</span>}
              {view === 'preview' && (
                <>
                  <label className="inline-flex cursor-pointer items-center gap-1.5 text-[11px] text-zinc-400">
                    <input type="checkbox" checked={runScripts} onChange={(e) => setRunScripts(e.target.checked)} />
                    Run scripts
                  </label>
                  <span className="text-[10px] text-zinc-600">
                    {runScripts
                      ? 'scripts run in an isolated origin — still cannot touch this app'
                      : 'scripts disabled (JS-driven pages show only their pre-JS shell)'}
                  </span>
                </>
              )}
            </div>
            {view === 'body' ? (
              /* Rendered as inert text — never as HTML — so a hostile response body can't execute here. */
              <pre className="min-h-0 flex-1 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 whitespace-pre-wrap break-all">
                {resp.body || '(empty body)'}
              </pre>
            ) : (
              /* Fills the panel. The iframe sandbox NEVER includes allow-same-origin,
                 so even with allow-scripts the page runs in an opaque origin and
                 cannot read this app's cookies/DOM. Keyed by runScripts so toggling
                 remounts the frame with the new sandbox. */
              <div className="min-h-0 flex-1 overflow-auto rounded-lg border border-hair/60 bg-white">
                <iframe
                  key={runScripts ? 'js' : 'nojs'}
                  title="response preview"
                  sandbox={runScripts ? 'allow-scripts' : ''}
                  srcDoc={resp.body}
                  className="h-full w-full border-0"
                />
              </div>
            )}
          </div>
        </div>
      )}

      {history.length > 0 && (
        <div className="mt-3 border-t border-hair/50 pt-2">
          <div className="mb-1 flex items-center justify-between">
            <span className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-zinc-500">
              <History size={12} /> History ({history.length})
            </span>
            <button onClick={clearHistory} className="text-[11px] text-zinc-500 transition hover:text-red-300">
              clear
            </button>
          </div>
          <div className="max-h-56 space-y-0.5 overflow-auto">
            {history.map((h) => (
              <button
                key={h.id}
                onClick={() => openHistory(h)}
                className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left font-mono text-[11px] transition hover:bg-ink-800"
                title={h.url}
              >
                <span className="w-11 shrink-0 text-zinc-400">{h.method}</span>
                <span className="min-w-0 flex-1 truncate text-zinc-300">{shortUrl(h.url)}</span>
                {h.status != null && (
                  <span
                    className={`shrink-0 ${statusTone(h.status) === 'green' ? 'text-green-300' : statusTone(h.status) === 'amber' ? 'text-amber-300' : statusTone(h.status) === 'blue' ? 'text-sky-300' : statusTone(h.status) === 'red' ? 'text-red-300' : 'text-zinc-400'}`}
                  >
                    {h.status}
                  </span>
                )}
                <span className="w-14 shrink-0 text-right text-zinc-600">{h.timeMs != null ? `${h.timeMs}ms` : ''}</span>
                <span className="w-14 shrink-0 text-right text-zinc-600">{timeAgo(new Date(h.createdAt).getTime())}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

// --- Intruder ---------------------------------------------------------------
function IntruderPanel({
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
              <AttemptTable rows={result.interesting} highlight />
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

function NumField({ label, value, onChange }: { label: string; value: string; onChange: (s: string) => void }) {
  return (
    <label className="inline-flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-wide text-zinc-600">{label}</span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/[^\d]/g, ''))}
        inputMode="numeric"
        className="w-24 rounded-lg border border-hair bg-ink-950 px-2 py-1 font-mono text-xs outline-none focus:border-accent-500"
      />
    </label>
  )
}

const ATTEMPT_PAGE = 500
function AttemptTable({ rows, highlight = false }: { rows: IntruderAttempt[]; highlight?: boolean }) {
  // Cap the DOM: a 10k-payload run would otherwise commit 10k <tr> at once and
  // jank the tab. Render a page at a time; deviating rows are surfaced separately.
  const [limit, setLimit] = useState(ATTEMPT_PAGE)
  const shown = rows.slice(0, limit)
  const hasWords = rows.some((r) => r.words != null)
  const hasExtract = rows.some((r) => r.extract != null)
  const hasMatched = rows.some((r) => r.matched)
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
            </tr>
          </thead>
          <tbody>
            {shown.map((r, i) => (
              <tr key={i} className={`border-t border-hair/40 ${highlight ? 'text-amber-100' : 'text-zinc-300'}`}>
                <td className="px-2 py-1 break-all">{r.payload}</td>
                <td className="px-2 py-1">
                  <Badge tone={statusTone(r.status)}>{r.error ? 'err' : r.status}</Badge>
                </td>
                <td className="px-2 py-1">{r.length}</td>
                {hasWords && <td className="px-2 py-1 text-zinc-500">{r.words ?? ''}</td>}
                <td className="px-2 py-1 text-zinc-500">{r.timeMs}ms</td>
                {hasExtract && <td className="px-2 py-1 break-all text-accent-fg">{r.extract ?? ''}</td>}
                {hasMatched && <td className="px-2 py-1">{r.matched ? <Badge tone="red">hit</Badge> : ''}</td>}
              </tr>
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

// --- Payload library ---------------------------------------------------------
type PayloadData = Awaited<ReturnType<typeof api.payloads>>

// Pick a built-in or saved payload set and load it into the Intruder list, or
// save the current list as a new reusable set.
function PayloadLibrary({
  currentList,
  onLoad,
  toast,
}: {
  currentList: string
  onLoad: (payloads: string[]) => void
  toast: ReturnType<typeof useToast>
}) {
  const [data, setData] = useState<PayloadData | null>(null)
  const [pick, setPick] = useState('')
  const [saving, setSaving] = useState(false)

  const load = useCallback(() => {
    api.payloads().then(setData).catch(() => {})
  }, [])
  useEffect(() => load(), [load])

  function loadSet(key: string) {
    setPick(key)
    if (!data || !key) return
    const [kind, id] = key.split(':')
    const set = kind === 'b' ? data.builtins.find((s) => s.id === id) : data.custom.find((s) => String(s.id) === id)
    if (set) {
      onLoad(set.payloads)
      toast.success(`Loaded ${set.payloads.length} payloads from "${set.name}".`)
    }
  }

  async function saveCurrent() {
    const payloads = currentList.split('\n').map((l) => l.trim()).filter(Boolean)
    if (!payloads.length) return toast.error('Nothing to save — the list is empty.')
    const name = window.prompt('Save current list as a payload set named:')
    if (!name) return
    setSaving(true)
    try {
      await api.createPayloadSet({ name: name.trim(), category: 'custom', payloads })
      toast.success(`Saved "${name}" (${payloads.length} payloads).`)
      load()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Could not save set.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <select
        value={pick}
        onChange={(e) => loadSet(e.target.value)}
        className="rounded-lg border border-hair bg-ink-950 px-2 py-1.5 outline-none focus:border-accent-500"
      >
        <option value="">＋ Load from library…</option>
        <optgroup label="Built-in">
          {data?.builtins.map((s) => (
            <option key={s.id} value={`b:${s.id}`}>
              {s.name} ({s.payloads.length})
            </option>
          ))}
        </optgroup>
        {data && data.custom.length > 0 && (
          <optgroup label="Saved">
            {data.custom.map((s) => (
              <option key={s.id} value={`c:${s.id}`}>
                {s.name} ({s.payloads.length})
              </option>
            ))}
          </optgroup>
        )}
      </select>
      <button onClick={saveCurrent} disabled={saving} className="rounded-lg border border-hair px-2 py-1.5 text-zinc-400 hover:text-zinc-200 disabled:opacity-50">
        Save list as set
      </button>
    </div>
  )
}

// --- Encoder bar -------------------------------------------------------------
// Build an encoder chain and preview the encoded form live (server-side transform
// via /api/payloads/encode — no egress). A pure convenience for crafting payloads.
function EncoderBar({ toast }: { toast: ReturnType<typeof useToast> }) {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState('')
  const [chain, setChain] = useState<string[]>([])
  const [output, setOutput] = useState('')
  const [transforms, setTransforms] = useState<string[]>([])

  useEffect(() => {
    if (open && transforms.length === 0) api.payloads().then((d) => setTransforms(d.transforms)).catch(() => {})
  }, [open, transforms.length])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    if (!input || chain.length === 0) {
      setOutput('')
      return
    }
    api
      .encodePayload(input, chain)
      .then((r) => !cancelled && setOutput(r.output))
      .catch(() => !cancelled && setOutput(''))
    return () => {
      cancelled = true
    }
  }, [open, input, chain])

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-[11px] text-zinc-500 hover:text-zinc-300">
        ▸ encoder
      </button>
    )
  }

  return (
    <div className="space-y-1.5 rounded-lg border border-hair bg-ink-900/50 p-2 text-xs">
      <div className="flex items-center justify-between">
        <span className="uppercase tracking-wide text-zinc-500">Encoder chain</span>
        <button onClick={() => setOpen(false)} className="text-zinc-500 hover:text-zinc-300">
          ▾ hide
        </button>
      </div>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="text to encode"
        className="block w-full rounded border border-hair bg-ink-950 px-2 py-1 font-mono outline-none focus:border-accent-500"
      />
      <div className="flex flex-wrap gap-1">
        {transforms.map((t) => (
          <button
            key={t}
            onClick={() => setChain((c) => [...c, t])}
            className="rounded border border-hair px-1.5 py-0.5 text-[10px] text-zinc-400 hover:text-accent-fg"
          >
            {t}
          </button>
        ))}
      </div>
      {chain.length > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-zinc-500">chain:</span>
          {chain.map((t, i) => (
            <Badge key={i} tone="zinc">
              {t}
            </Badge>
          ))}
          <button onClick={() => setChain([])} className="text-zinc-500 hover:text-zinc-300">
            clear
          </button>
        </div>
      )}
      {output && (
        <div className="flex items-start gap-2">
          <code className="min-w-0 flex-1 break-all rounded bg-ink-950 px-2 py-1 font-mono text-accent-fg">{output}</code>
          <button
            onClick={() => {
              copyText(output).then((ok) => ok && toast.success('Copied.'))
            }}
            className="shrink-0 rounded border border-hair px-1.5 py-1 text-zinc-400 hover:text-zinc-200"
          >
            copy
          </button>
        </div>
      )}
    </div>
  )
}
