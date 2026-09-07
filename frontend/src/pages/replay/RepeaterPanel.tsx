import { useCallback, useEffect, useState } from 'react'
import { Send, Clock, Ruler, ChevronRight, History } from 'lucide-react'
import { api, ApiError, type ReplayResponse, type ReplayHistoryItem } from '../../api'
import { Badge, Button, Card } from '../../components/ui'
import { Tabs } from '../../components/Tabs'
import { useToast } from '../../components/Toast'
import { AttachToFinding } from '../../components/AttachToFinding'
import { timeAgo } from '../../lib/format'
import { type BuiltReq, type BuiltRequest, statusTone } from './shared'

function isolatedPreviewDocument(body: string, runScripts: boolean): string {
  const scriptPolicy = runScripts ? "script-src 'unsafe-inline'" : "script-src 'none'"
  const csp = `default-src 'none'; ${scriptPolicy}; connect-src 'none'; img-src data: blob:; media-src data: blob:; font-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-src 'none'`
  return `<!doctype html><meta http-equiv="Content-Security-Policy" content="${csp}">${body}`
}

function shortUrl(u: string): string {
  try {
    const x = new URL(u)
    return x.pathname + x.search
  } catch {
    return u
  }
}

export function RepeaterPanel({
  domainId,
  passive,
  confirmActive,
  applyRequest,
  reqStr,
  build,
  identityId,
  toast,
}: {
  domainId: number
  passive: boolean
  confirmActive: (title: string, what: string) => Promise<boolean>
  applyRequest: (r: BuiltReq) => void
  reqStr: string
  build: () => BuiltRequest
  identityId?: number | null
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
      const { response } = await api.replaySend({ domainId, ...req, identityId: identityId ?? undefined, confirm: passive })
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
            {resp.cloudflareSolved && (
              <span title="A Cloudflare challenge was auto-solved in a headless browser and the request replayed with the cf_clearance cookie.">
                <Badge tone="amber">Cloudflare solved</Badge>
              </span>
            )}
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
              <Tabs
                label="Response view"
                value={view}
                onChange={setView}
                className="inline-flex rounded-lg border border-hair bg-ink-950 p-0.5 text-xs"
                items={[
                  { key: 'body', label: 'Body' },
                  { key: 'preview', label: 'Preview' },
                ]}
              />
              {resp.truncated && <span className="text-[10px] text-amber-400">truncated</span>}
              {view === 'preview' && (
                <>
                  <label className="inline-flex cursor-pointer items-center gap-1.5 text-[11px] text-zinc-400">
                    <input type="checkbox" checked={runScripts} onChange={(e) => setRunScripts(e.target.checked)} />
                    Run scripts
                  </label>
                  <span className="text-[10px] text-zinc-600">
                    {runScripts
                      ? 'scripts run in an isolated origin with network access blocked'
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
                  srcDoc={isolatedPreviewDocument(resp.body, runScripts)}
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
