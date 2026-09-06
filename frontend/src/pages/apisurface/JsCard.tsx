import { useState } from 'react'
import { Code, ChevronRight, AlertTriangle } from 'lucide-react'
import { Badge, Card } from '../../components/ui'
import { timeAgo } from '../../lib/format'
import type { JsData } from './types'

export function JsCard({ d, at, score }: { d: JsData; at: string; score: number | null }) {
  const [open, setOpen] = useState(false)
  const [routesOpen, setRoutesOpen] = useState(false)
  const endpoints = Array.isArray(d.endpoints) ? d.endpoints : []
  const params = Array.isArray(d.params) ? d.params : []
  const secrets = Array.isArray(d.secrets) ? d.secrets : []
  const frameworks = Array.isArray(d.frameworks) ? d.frameworks : []
  const routes = Array.isArray(d.routes) ? d.routes : []
  const env = Array.isArray(d.env) ? d.env : []
  const shown = open ? endpoints : endpoints.slice(0, 12)
  const shownRoutes = routesOpen ? routes : routes.slice(0, 20)
  return (
    <Card className={secrets.length ? 'border-red-900/50' : ''}>
      <div className="flex flex-wrap items-center gap-2">
        <Code size={16} className="text-green-400" />
        <Badge tone="green">JS recon</Badge>
        <span className="font-mono text-sm text-zinc-100 break-all">{d.host}</span>
        {frameworks.map((f) => (
          <Badge key={f} tone="purple">
            {f}
          </Badge>
        ))}
        {secrets.length > 0 && <Badge tone="red">{secrets.length} secret(s)</Badge>}
        {score != null && <span className="ml-auto text-xs text-zinc-500">score {score}</span>}
      </div>
      <div className="mt-1 text-xs text-zinc-500">
        {endpoints.length} API endpoint(s) · {params.length} param(s) · from {d.filesScanned ?? 0} JS file(s)
        {d.fromCorpus ? ` + ${d.fromCorpus} from passive URLs (wayback/crawl)` : ''}
      </div>

      {/* Baked-in public env config the frontend exposes (base URLs, keys, flags) */}
      {env.length > 0 && (
        <div className="mt-2 space-y-1 rounded-lg border border-hair/60 bg-ink-900/40 p-2">
          <div className="text-[10px] uppercase tracking-wide text-zinc-500">Exposed config ({env.length})</div>
          {env.slice(0, 30).map((e, i) => (
            <div key={i} className="flex flex-wrap items-center gap-x-2 font-mono text-[11px]">
              <span className="text-accent-fg">{e.key}</span>
              {e.value != null && (
                <>
                  <span className="text-zinc-600">=</span>
                  <span className="break-all text-zinc-300">{e.value}</span>
                </>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Client-side routes lifted from the bundle */}
      {routes.length > 0 && (
        <div className="mt-2">
          <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">Client routes ({routes.length})</div>
          <div className="flex flex-wrap gap-1">
            {shownRoutes.map((r, i) => (
              <span key={i} className="rounded border border-hair bg-ink-900/50 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300 break-all">
                {r}
              </span>
            ))}
          </div>
          {routes.length > 20 && (
            <button onClick={() => setRoutesOpen((v) => !v)} className="mt-1 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300">
              <ChevronRight size={12} className={routesOpen ? 'rotate-90 transition' : 'transition'} />
              {routesOpen ? 'show fewer' : `show all ${routes.length}`}
            </button>
          )}
        </div>
      )}

      {/* Leaked secrets — highest signal, shown first */}
      {secrets.length > 0 && (
        <div className="mt-2 space-y-1 rounded-lg border border-red-900/40 bg-red-950/20 p-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-red-200">
            <AlertTriangle size={13} className="text-red-400" /> Possible secrets (review — may be false positives)
          </div>
          {secrets.slice(0, 15).map((s, i) => (
            <div key={i} className="flex flex-wrap items-center gap-x-2 font-mono text-[11px] text-red-200/90">
              <span className="text-red-300">{s.pattern}:</span>
              <span className="break-all">{s.sample}</span>
              <span className="text-zinc-500 break-all">({s.file})</span>
            </div>
          ))}
        </div>
      )}

      {endpoints.length > 0 && (
        <div className="mt-2.5">
          <div className="flex flex-wrap gap-1">
            {shown.map((e, i) => (
              <span key={i} className="rounded border border-hair bg-ink-900/50 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300 break-all">
                {e}
              </span>
            ))}
          </div>
          {endpoints.length > 12 && (
            <button onClick={() => setOpen((v) => !v)} className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300">
              <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
              {open ? 'show fewer' : `show all ${endpoints.length}`}
            </button>
          )}
        </div>
      )}

      {params.length > 0 && (
        <div className="mt-2">
          <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">Parameters</div>
          <div className="flex flex-wrap gap-1">
            {params.slice(0, 40).map((p, i) => (
              <span key={i} className="rounded bg-ink-800/70 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">{p}</span>
            ))}
          </div>
        </div>
      )}
      <div className="mt-2 text-right text-[11px] text-zinc-600">{timeAgo(new Date(at).getTime())}</div>
    </Card>
  )
}

