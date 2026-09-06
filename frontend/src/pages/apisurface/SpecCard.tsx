import { useState } from 'react'
import { Braces, ChevronRight } from 'lucide-react'
import { Badge, Card } from '../../components/ui'
import { timeAgo } from '../../lib/format'
import { safeHttpUrl } from '../../lib/url'
import { type PendingReplay } from '../../lib/replayHandoff'
import type { SpecData, SpecEndpoint } from './types'

function pickServer(d: SpecData): string {
  const abs = (d.servers ?? []).find((s) => /^https?:\/\//i.test(s))
  if (abs) return abs.replace(/\/+$/, '')
  const rel = (d.servers ?? [])[0]
  const base = `https://${d.host}`
  return rel && rel.startsWith('/') ? base + rel.replace(/\/+$/, '') : base
}
function sampleForType(t: string): unknown {
  if (t.endsWith('[]')) return []
  const b = t.replace(/\[\]$/, '')
  if (/^(number|integer|int|float|double|long)$/i.test(b)) return 0
  if (/^bool/i.test(b)) return false
  if (/^string$/i.test(b)) return ''
  return null
}
function specToReplay(d: SpecData, e: SpecEndpoint): PendingReplay {
  const path = e.path.startsWith('/') ? e.path : '/' + e.path
  const url = pickServer(d) + path
  const headers: [string, string][] = []
  let body: string | null = null
  if (e.body?.fields?.length) {
    headers.push(['Content-Type', e.body.contentType || 'application/json'])
    body = JSON.stringify(Object.fromEntries(e.body.fields.map((f) => [f.name, sampleForType(f.type)])), null, 2)
  }
  const auth = d.authSchemes ?? []
  if (auth.some((s) => /bearer|oauth2|http|jwt/i.test(s))) headers.push(['Authorization', 'Bearer <token>'])
  else if (auth.some((s) => /apikey|api_key/i.test(s))) headers.push(['X-API-Key', '<key>'])
  return { method: e.method, url, headers, body }
}

const METHOD_TONE: Record<string, string> = {
  GET: 'text-green-300 bg-green-500/10',
  POST: 'text-blue-300 bg-blue-500/10',
  PUT: 'text-amber-300 bg-amber-500/10',
  PATCH: 'text-amber-300 bg-amber-500/10',
  DELETE: 'text-red-300 bg-red-500/10',
}

export function SpecCard({
  d,
  at,
  score,
  onReplay,
}: {
  d: SpecData
  at: string
  score: number | null
  onReplay: (r: PendingReplay) => void
}) {
  const [open, setOpen] = useState(false)
  const [openOps, setOpenOps] = useState<Set<number>>(new Set())
  const toggleOp = (i: number) =>
    setOpenOps((cur) => {
      const next = new Set(cur)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })
  // Defend against any legacy/partial finding missing these arrays.
  const endpoints = Array.isArray(d.endpoints) ? d.endpoints : []
  const servers = Array.isArray(d.servers) ? d.servers : []
  const authSchemes = Array.isArray(d.authSchemes) ? d.authSchemes : []
  const shown = open ? endpoints : endpoints.slice(0, 8)
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <Braces size={16} className="text-accent-400" />
        <Badge tone="indigo">{d.format ?? 'openapi'}</Badge>
        <span className="text-sm font-medium text-zinc-100">{d.title ?? 'API'}</span>
        {d.apiVersion && <span className="text-xs text-zinc-500">v{d.apiVersion}</span>}
        {authSchemes.length === 0 && <Badge tone="amber">no auth scheme</Badge>}
        {score != null && <span className="ml-auto text-xs text-zinc-500">score {score}</span>}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-400">
        <a href={safeHttpUrl(d.specUrl)} target="_blank" rel="noreferrer" className="font-mono text-sky-400 hover:underline break-all">
          {d.specUrl} ↗
        </a>
        <span className="ml-auto">{d.operationCount ?? endpoints.length} operations</span>
      </div>
      {authSchemes.length > 0 && (
        <div className="mt-1 text-xs text-zinc-500">auth: {authSchemes.join(', ')}</div>
      )}
      {servers.length > 0 && (
        <div className="mt-1 text-xs text-zinc-500 break-all">servers: {servers.slice(0, 4).join(', ')}</div>
      )}

      {endpoints.length > 0 && (
        <div className="mt-2.5 space-y-1">
          {shown.map((e, i) => {
            const hasDetail = !!(e.summary || e.params?.length || e.body?.fields?.length)
            const isOpen = openOps.has(i)
            return (
              <div key={i} className="rounded border border-hair bg-ink-900/50">
                <div className="flex items-center gap-2 px-2 py-1">
                  <button
                    type="button"
                    onClick={() => hasDetail && toggleOp(i)}
                    className={`flex min-w-0 flex-1 items-center gap-2 text-left ${hasDetail ? 'cursor-pointer' : 'cursor-default'}`}
                  >
                    <span className={`rounded px-1 font-mono text-[11px] ${METHOD_TONE[e.method] ?? 'text-zinc-300 bg-ink-800'}`}>
                      {e.method}
                    </span>
                    <span className="truncate font-mono text-[11px] text-zinc-300">{e.path}</span>
                    {hasDetail && (
                      <ChevronRight size={11} className={`shrink-0 text-zinc-600 transition ${isOpen ? 'rotate-90' : ''}`} />
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => onReplay(specToReplay(d, e))}
                    className="shrink-0 rounded px-1.5 py-0.5 text-[10px] text-sky-400 hover:bg-ink-800 hover:text-sky-300"
                    title="Send a starter request to Replay"
                  >
                    → Replay
                  </button>
                </div>
                {isOpen && hasDetail && (
                  <div className="space-y-1.5 border-t border-hair/60 px-2 py-1.5 text-[11px]">
                    {e.summary && <div className="text-zinc-400">{e.summary}</div>}
                    {e.params?.length ? (
                      <div>
                        <div className="text-[10px] uppercase tracking-wide text-zinc-600">Params</div>
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {e.params.map((p, j) => (
                            <span key={j} className="rounded bg-ink-800/70 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300">
                              {p.name}
                              <span className="text-zinc-500">
                                {' '}
                                ({p.in}
                                {p.required ? ', required' : ''})
                              </span>
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}
                    {e.body?.fields?.length ? (
                      <div>
                        <div className="text-[10px] uppercase tracking-wide text-zinc-600">Body ({e.body.contentType})</div>
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {e.body.fields.map((f, j) => (
                            <span key={j} className="rounded bg-ink-800/70 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300">
                              {f.name}: <span className="text-accent-fg">{f.type}</span>
                              {f.required && <span className="text-red-400">*</span>}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            )
          })}
          {endpoints.length > 8 && (
            <button onClick={() => setOpen((v) => !v)} className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300">
              <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
              {open ? 'show fewer' : `show all ${endpoints.length}`}
            </button>
          )}
        </div>
      )}
      <div className="mt-2 text-right text-[11px] text-zinc-600">{timeAgo(new Date(at).getTime())}</div>
    </Card>
  )
}
