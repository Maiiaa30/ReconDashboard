import { useCallback, useMemo, useState } from 'react'
import { api, type Finding } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Card, Empty, PageHeader, ScoreBadge } from '../components/ui'
import { riskFromScore, summarizeFinding, timeAgo, type RiskLevel } from '../lib/format'

// Rules-based triage ("big filter"): pulls every finding, ranks by the scorer,
// and surfaces what to look at first. No AI — pure heuristics for now.
export function Intel() {
  const { domains, selected } = useApp()
  const [findings, setFindings] = useState<Finding[]>([])

  // Scoped to the selected domain (matches the header target). No selection =
  // triage across all domains.
  const load = useCallback(() => {
    api.findings({ domainId: selected?.id, limit: 500 }).then((r) => setFindings(r.findings)).catch(() => {})
  }, [selected])
  usePoll(load, 8000, true)

  const hostOf = useCallback(
    (id: number | null) => (id == null ? 'global' : domains.find((d) => d.id === id)?.host ?? `#${id}`),
    [domains],
  )

  const buckets = useMemo(() => {
    const b: Record<RiskLevel, Finding[]> = { high: [], medium: [], low: [], none: [] }
    for (const f of findings) b[riskFromScore(f.score)].push(f)
    return b
  }, [findings])

  // A few headline signals worth being aware of.
  const signals = useMemo(() => {
    const cveHosts = new Set<string>()
    let cves = 0
    let adminish = 0
    let critical = 0
    for (const f of findings) {
      if (f.type === 'exposure' && Array.isArray(f.data?.vulns) && f.data.vulns.length) {
        cves += f.data.vulns.length
        cveHosts.add(f.data.ip ?? '')
      }
      if (f.tags?.some((t) => t.startsWith('kw:') || t.startsWith('admin-port:'))) adminish++
      if (f.tags?.includes('sev:critical') || (f.score ?? 0) >= 90) critical++
    }
    return { cves, cveHosts: cveHosts.size, adminish, critical }
  }, [findings])

  return (
    <div>
      <PageHeader
        title="Intel"
        subtitle={`Rules-based triage — ${selected ? selected.host : 'all domains'}`}
      />

      {/* Headline signal tiles */}
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <SignalTile label="Priority items" value={buckets.high.length + buckets.medium.length} tone="amber" />
        <SignalTile label="Critical-ish" value={signals.critical} tone="red" />
        <SignalTile label="CVEs seen" value={signals.cves} tone="red" />
        <SignalTile label="Admin/interesting" value={signals.adminish} tone="blue" />
      </div>

      {findings.length === 0 ? (
        <Empty>No findings yet. Run discovery / exposure / OSINT on a domain to populate intel.</Empty>
      ) : (
        <div className="space-y-6">
          <Section title="🔴 Look at first" tone="red" items={buckets.high} hostOf={hostOf} />
          <Section title="🟠 Worth a look" tone="amber" items={buckets.medium} hostOf={hostOf} />
          <Section title="🔵 Context" tone="blue" items={buckets.low} hostOf={hostOf} collapsedCount />
        </div>
      )}
    </div>
  )
}

function SignalTile({ label, value, tone }: { label: string; value: number; tone: 'red' | 'amber' | 'blue' }) {
  const color = { red: 'text-red-400', amber: 'text-amber-400', blue: 'text-blue-400' }[tone]
  return (
    <Card className="py-3">
      <div className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</div>
      <div className={`text-2xl font-semibold ${value > 0 ? color : 'text-zinc-300'}`}>{value}</div>
    </Card>
  )
}

function Section({
  title,
  tone,
  items,
  hostOf,
  collapsedCount,
}: {
  title: string
  tone: 'red' | 'amber' | 'blue'
  items: Finding[]
  hostOf: (id: number | null) => string
  collapsedCount?: boolean
}) {
  const [showAll, setShowAll] = useState(false)
  if (items.length === 0) return null
  const limit = collapsedCount && !showAll ? 8 : items.length
  const border = { red: 'border-red-900/50', amber: 'border-amber-900/50', blue: 'border-blue-900/40' }[tone]

  return (
    <div>
      <h2 className="mb-2 text-sm font-semibold text-zinc-200">
        {title} <span className="text-zinc-500">({items.length})</span>
      </h2>
      <div className={`overflow-hidden rounded-xl border ${border}`}>
        {items.slice(0, limit).map((f, i) => (
          <div
            key={f.id}
            className={`flex items-center gap-3 px-3 py-2 text-sm ${i > 0 ? 'border-t border-zinc-800/60' : ''}`}
          >
            <ScoreBadge score={f.score} />
            <Badge>{f.type.replace('_', ' ')}</Badge>
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-200">
              {summarizeFinding(f.type, f.data)}
            </span>
            <span className="hidden shrink-0 text-xs text-zinc-500 sm:inline">{hostOf(f.domainId)}</span>
            <span className="hidden shrink-0 text-[10px] text-zinc-600 md:inline">
              {timeAgo(new Date(f.createdAt).getTime())}
            </span>
          </div>
        ))}
      </div>
      {collapsedCount && items.length > limit && (
        <button onClick={() => setShowAll(true)} className="mt-2 text-xs text-zinc-500 hover:text-zinc-300">
          Show {items.length - limit} more…
        </button>
      )}
    </div>
  )
}
