import { useState } from 'react'
import { Braces, ChevronRight } from 'lucide-react'
import { Badge, Card } from '../../components/ui'
import { timeAgo } from '../../lib/format'
import { type PendingReplay } from '../../lib/replayHandoff'
import type { GqlData, GqlOperation } from './types'

function gqlToReplay(d: GqlData, op: GqlOperation): PendingReplay {
  const argHint = op.args.length ? `  # args: ${op.args.map((a) => `${a.name}: ${a.type}`).join(', ')}` : ''
  const query = `${op.kind} {\n  ${op.name}${argHint}\n}`
  return { method: 'POST', url: d.endpoint, headers: [['Content-Type', 'application/json']], body: JSON.stringify({ query }, null, 2) }
}

export function GraphqlCard({
  d,
  at,
  score,
  onReplay,
}: {
  d: GqlData
  at: string
  score: number | null
  onReplay: (r: PendingReplay) => void
}) {
  const [opsOpen, setOpsOpen] = useState(false)
  const operations = Array.isArray(d.operations) ? d.operations : []
  const shownOps = opsOpen ? operations : operations.slice(0, 12)
  return (
    <Card className={d.introspectionEnabled ? 'border-red-900/50' : ''}>
      <div className="flex flex-wrap items-center gap-2">
        <Braces size={16} className="text-purple-400" />
        <Badge tone="purple">GraphQL</Badge>
        <span className="font-mono text-sm text-zinc-100 break-all">{d.endpoint}</span>
        {d.introspectionEnabled ? (
          <Badge tone="red">introspection enabled</Badge>
        ) : (
          <Badge tone="green">introspection disabled</Badge>
        )}
        {score != null && <span className="ml-auto text-xs text-zinc-500">score {score}</span>}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-400">
        <span>host: <span className="font-mono text-zinc-300">{d.host}</span></span>
        {d.queryType && <span>query type: <span className="font-mono text-zinc-300">{d.queryType}</span></span>}
        {d.typeCount > 0 && <span>{d.typeCount} schema types</span>}
        <span className="ml-auto text-zinc-600">{timeAgo(new Date(at).getTime())}</span>
      </div>
      {d.introspectionEnabled && (
        <p className="mt-2 text-xs text-red-300/90">
          Introspection exposes the entire schema (queries, mutations, types) to anyone — usually disabled in production.
        </p>
      )}

      {operations.length > 0 && (
        <div className="mt-2.5">
          <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">Callable operations ({operations.length})</div>
          <div className="space-y-1">
            {shownOps.map((op, i) => (
              <div key={i} className="flex items-center gap-2 rounded border border-hair bg-ink-900/50 px-2 py-1">
                <Badge tone={op.kind === 'mutation' ? 'amber' : 'green'}>{op.kind}</Badge>
                <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-zinc-200">
                  {op.name}
                  {op.args.length > 0 && (
                    <span className="text-zinc-500">({op.args.map((a) => `${a.name}: ${a.type}`).join(', ')})</span>
                  )}
                </span>
                <button
                  type="button"
                  onClick={() => onReplay(gqlToReplay(d, op))}
                  className="shrink-0 rounded px-1.5 py-0.5 text-[10px] text-sky-400 hover:bg-ink-800 hover:text-sky-300"
                  title="Send a starter query to Replay"
                >
                  → Replay
                </button>
              </div>
            ))}
          </div>
          {operations.length > 12 && (
            <button
              onClick={() => setOpsOpen((v) => !v)}
              className="mt-1 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
            >
              <ChevronRight size={12} className={opsOpen ? 'rotate-90 transition' : 'transition'} />
              {opsOpen ? 'show fewer' : `show all ${operations.length}`}
            </button>
          )}
        </div>
      )}
    </Card>
  )
}
