import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, type AttackPath, type Finding } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Card, Empty, PageHeader, ScoreBadge } from '../components/ui'
import { riskFromScore, summarizeFinding, timeAgo, type RiskLevel } from '../lib/format'

// Rules-based triage ("big filter"): pulls every finding, ranks by the scorer,
// and surfaces what to look at first. No AI — pure heuristics for now.
export function Intel() {
  const { domains, selected } = useApp()
  const [findings, setFindings] = useState<Finding[]>([])
  const [paths, setPaths] = useState<AttackPath[]>([])

  // Scoped to the selected domain (matches the header target). No selection =
  // triage across all domains.
  const load = useCallback(() => {
    api.findings({ domainId: selected?.id, limit: 500 }).then((r) => setFindings(r.findings)).catch(() => {})
  }, [selected])
  usePoll(load, 8000, true)

  // Attack-path correlation is per-domain (needs a selected target).
  useEffect(() => {
    if (!selected) {
      setPaths([])
      return
    }
    api.correlate(selected.id).then((r) => setPaths(r.paths)).catch(() => setPaths([]))
  }, [selected, findings])

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

      {selected && paths.length > 0 && <AttackPaths paths={paths} host={selected.host} />}

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

// IP-centric join: host(s) -> IP (ASN) -> ports -> CVEs, worst first.
function AttackPaths({ paths, host }: { paths: AttackPath[]; host: string }) {
  return (
    <div className="mb-6">
      <h2 className="mb-2 text-sm font-semibold text-zinc-200">
        🧭 Attack paths <span className="text-zinc-500">— {host} ({paths.length} asset{paths.length > 1 ? 's' : ''})</span>
      </h2>
      <div className="overflow-hidden rounded-xl border border-hair">
        <table className="w-full text-sm">
          <thead className="bg-ink-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
            <tr>
              <th className="px-3 py-2">Host(s)</th>
              <th className="px-3 py-2 w-40">IP</th>
              <th className="px-3 py-2 w-32">ASN</th>
              <th className="px-3 py-2">Ports</th>
              <th className="px-3 py-2 w-28">CVEs</th>
            </tr>
          </thead>
          <tbody>
            {paths.slice(0, 40).map((p) => (
              <tr key={p.ip} className="border-t border-hair/60 align-top">
                <td className="px-3 py-2 font-mono text-xs text-zinc-200">
                  {p.hosts.length ? p.hosts.slice(0, 4).join(', ') + (p.hosts.length > 4 ? ` +${p.hosts.length - 4}` : '') : '—'}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-zinc-300">
                  {p.ip}
                  {p.cdn && <span className="ml-1 text-[10px] text-zinc-600">({p.cdn})</span>}
                </td>
                <td className="px-3 py-2 text-xs text-zinc-400" title={p.asnName ?? ''}>
                  {p.asn ? `AS${p.asn}` : '—'}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-zinc-400 break-all">
                  {p.ports.length ? p.ports.slice(0, 12).join(', ') : '—'}
                </td>
                <td className="px-3 py-2 text-xs">
                  {p.cveCount > 0 ? (
                    <span className="flex flex-wrap items-center gap-1">
                      <Badge tone={p.worstCvss && p.worstCvss >= 9 ? 'red' : p.worstCvss && p.worstCvss >= 7 ? 'amber' : 'zinc'}>
                        {p.cveCount} CVE{p.cveCount > 1 ? 's' : ''}
                      </Badge>
                      {p.kev && <Badge tone="red">KEV</Badge>}
                    </span>
                  ) : (
                    <span className="text-zinc-600">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
            className={`flex items-center gap-3 px-3 py-2 text-sm ${i > 0 ? 'border-t border-hair/60' : ''}`}
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
