import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { api, type AdviceAction, type AttackPath, type Finding, type IntelAdvice } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Card, Empty, PageHeader, ScoreBadge } from '../components/ui'
import { riskFromScore, summarizeFinding, timeAgo, type RiskLevel } from '../lib/format'
import { AttackGraph } from '../components/AttackGraph'

// Rules-based triage ("big filter"): pulls every finding, ranks by the scorer,
// and surfaces what to look at first. No AI — pure heuristics for now.
export function Intel() {
  const { domains, selected } = useApp()
  const [findings, setFindings] = useState<Finding[]>([])
  const [paths, setPaths] = useState<AttackPath[]>([])
  const [pathView, setPathView] = useState<'graph' | 'table'>('graph')
  const [llmOn, setLlmOn] = useState(false)
  const [advice, setAdvice] = useState<{ data: IntelAdvice | null; note: string } | null>(null)
  const [adviceBusy, setAdviceBusy] = useState(false)

  useEffect(() => {
    api.meta().then((m) => setLlmOn(Boolean(m.llm?.enabled))).catch(() => {})
  }, [])

  // Clear a stale analysis when the operator switches targets.
  useEffect(() => {
    setAdvice(null)
  }, [selected])

  async function analyze() {
    if (!selected || adviceBusy) return
    setAdviceBusy(true)
    try {
      const r = await api.adviseIntel(selected.id)
      setAdvice({ data: r.advice, note: r.note })
    } catch (e) {
      setAdvice({ data: null, note: e instanceof Error ? e.message : 'failed to analyze' })
    } finally {
      setAdviceBusy(false)
    }
  }

  // Scoped to the selected domain (matches the header target). No selection =
  // triage across all domains.
  const load = useCallback(() => {
    api.findings({ domainId: selected?.id, limit: 500 }).then((r) => setFindings(r.findings)).catch(() => {})
  }, [selected])
  usePoll(load, 8000, true)

  // Attack-path correlation is per-domain (needs a selected target). Runs on
  // every findings poll so it stays fresh, but we only push a new array when
  // the content actually changed — otherwise the graph would reheat its layout
  // every 8s and never settle.
  const pathSigRef = useRef('')
  useEffect(() => {
    if (!selected) {
      setPaths([])
      pathSigRef.current = ''
      return
    }
    api
      .correlate(selected.id)
      .then((r) => {
        const sig = JSON.stringify(r.paths)
        if (sig !== pathSigRef.current) {
          pathSigRef.current = sig
          setPaths(r.paths)
        }
      })
      .catch(() => setPaths([]))
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
      <div className="flex items-start justify-between gap-3">
        <PageHeader
          title="Intel"
          subtitle={`Rules-based triage — ${selected ? selected.host : 'all domains'}`}
        />
        {llmOn && selected && (
          <button
            onClick={analyze}
            disabled={adviceBusy}
            className="mt-1 shrink-0 rounded-lg border border-accent-500/40 px-3 py-1.5 text-xs text-accent-fg transition hover:bg-accent-500/10 disabled:opacity-50"
            title="Have the AI read all gathered recon for this target and suggest a prioritized testing plan (sends target + finding summaries)"
          >
            {adviceBusy ? 'Analyzing…' : '🧠 Analyze with AI'}
          </button>
        )}
      </div>

      {advice && selected && (
        <AdvicePanel result={advice} domainId={selected.id} onDismiss={() => setAdvice(null)} />
      )}

      {/* Headline signal tiles */}
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <SignalTile label="Priority items" value={buckets.high.length + buckets.medium.length} tone="amber" />
        <SignalTile label="Critical-ish" value={signals.critical} tone="red" />
        <SignalTile label="CVEs seen" value={signals.cves} tone="red" />
        <SignalTile label="Admin/interesting" value={signals.adminish} tone="blue" />
      </div>

      {selected && paths.length > 0 && (
        <AttackPathsSection paths={paths} host={selected.host} view={pathView} onViewChange={setPathView} />
      )}

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

// Map an advisor action to the real (gated) scan/tool endpoint. confirm:true is
// only sent AFTER the operator clicks Confirm in RunButton — the server still
// enforces mode/scope/window/cooldown and audits the enqueue.
async function runAdviceAction(domainId: number, a: AdviceAction): Promise<number> {
  const target = a.target
  switch (a.kind) {
    case 'nmap':
      return (await api.nmap(domainId, { target, confirm: true })).jobId
    case 'nuclei':
      return (await api.nuclei(domainId, { target, confirm: true })).jobId
    case 'ffuf':
      return (await api.ffuf(domainId, { target, confirm: true })).jobId
    case 'naabu':
    case 'dalfox':
    case 'sslscan':
    case 'katana':
      return (await api.runTool(domainId, { tool: a.kind, target, confirm: true })).jobId
    case 'owasp':
      return (await api.runOwasp(domainId, undefined, undefined, true)).jobId
  }
}

// One-click run with a mandatory confirm step (active scans on passive_only
// targets require confirm; we make the operator opt in every time).
function RunButton({ domainId, action }: { domainId: number; action: AdviceAction }) {
  const [state, setState] = useState<'idle' | 'confirm' | 'running' | 'done' | 'error'>('idle')
  const [msg, setMsg] = useState('')

  async function go() {
    setState('running')
    try {
      const jobId = await runAdviceAction(domainId, action)
      setMsg(`queued job #${jobId}`)
      setState('done')
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'failed to enqueue')
      setState('error')
    }
  }

  if (state === 'done') {
    return <span className="text-[11px] text-emerald-400">✓ {action.kind} {msg}</span>
  }
  if (state === 'running') {
    return <span className="text-[11px] text-zinc-400">running {action.kind}…</span>
  }
  if (state === 'confirm') {
    return (
      <span className="inline-flex flex-wrap items-center gap-1.5 text-[11px]">
        <span className="text-amber-400">Run active {action.kind} on {action.target}?</span>
        <button onClick={go} className="rounded bg-emerald-600/80 px-1.5 py-0.5 text-white transition hover:bg-emerald-600">
          Confirm
        </button>
        <button onClick={() => setState('idle')} className="rounded bg-ink-800 px-1.5 py-0.5 text-zinc-300 transition hover:bg-ink-700">
          Cancel
        </button>
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-2">
      <button
        onClick={() => setState('confirm')}
        className="rounded border border-emerald-600/40 px-2 py-0.5 text-[11px] text-emerald-300 transition hover:bg-emerald-600/10"
        title={`Enqueue ${action.kind} against ${action.target} — active scan, you will confirm first`}
      >
        ▶ Run {action.kind}
      </button>
      {state === 'error' && <span className="text-[11px] text-red-400">{msg}</span>}
    </span>
  )
}

// AI advisor output: prioritized, structured testing plan rendered as cards.
function AdvicePanel({
  result,
  domainId,
  onDismiss,
}: {
  result: { data: IntelAdvice | null; note: string }
  domainId: number
  onDismiss: () => void
}) {
  const a = result.data
  return (
    <div className="mb-5 rounded-xl border border-accent-500/30 bg-ink-900/60 p-4">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wide text-accent-fg">🧠 AI analysis</span>
        <button onClick={onDismiss} className="text-xs text-zinc-500 hover:text-zinc-300">
          dismiss
        </button>
      </div>

      {!a ? (
        <p className="text-sm text-red-400">{result.note}</p>
      ) : (
        <div className="space-y-4">
          {a.summary && <p className="text-sm leading-relaxed text-zinc-200">{a.summary}</p>}

          {a.priorities.length > 0 && (
            <AdviceSection title="🎯 Priority targets">
              <div className="space-y-2">
                {a.priorities.map((p, i) => (
                  <div key={i} className="rounded-lg border border-hair/60 bg-ink-950/40 p-2.5">
                    <div className="flex items-center gap-2">
                      <Badge tone={p.risk === 'high' ? 'red' : p.risk === 'medium' ? 'amber' : 'zinc'}>
                        {p.risk}
                      </Badge>
                      <span className="font-mono text-xs text-zinc-100">{p.target}</span>
                    </div>
                    {p.why && <p className="mt-1 text-xs text-zinc-400">{p.why}</p>}
                    {p.tests.length > 0 && (
                      <ul className="mt-1.5 flex flex-wrap gap-1.5">
                        {p.tests.map((t, j) => (
                          <li key={j} className="rounded bg-ink-800/70 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300">
                            {t}
                          </li>
                        ))}
                      </ul>
                    )}
                    {p.action && (
                      <div className="mt-2">
                        <RunButton domainId={domainId} action={p.action} />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </AdviceSection>
          )}

          {a.injection.length > 0 && (
            <AdviceSection title="💉 Injection / XSS candidates">
              <div className="space-y-1.5">
                {a.injection.map((c, i) => (
                  <div key={i} className="rounded-lg border border-hair/60 bg-ink-950/40 p-2.5 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="amber">{c.type}</Badge>
                      <span className="break-all font-mono text-zinc-100">{c.target}</span>
                      {c.param && <span className="font-mono text-[11px] text-accent-fg">param: {c.param}</span>}
                    </div>
                    {c.why && <p className="mt-1 text-zinc-400">{c.why}</p>}
                    {c.action && (
                      <div className="mt-2">
                        <RunButton domainId={domainId} action={c.action} />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </AdviceSection>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            {a.quickWins.length > 0 && (
              <AdviceSection title="⚡ Quick wins">
                <ItemList items={a.quickWins} />
              </AdviceSection>
            )}
            {a.deeperDigs.length > 0 && (
              <AdviceSection title="🔬 Deeper digs">
                <ItemList items={a.deeperDigs} />
              </AdviceSection>
            )}
          </div>

          <p className="text-[11px] text-amber-400/80">⚠ {result.note}</p>
        </div>
      )}
    </div>
  )
}

function AdviceSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="mb-1.5 text-xs font-semibold text-zinc-300">{title}</h3>
      {children}
    </div>
  )
}

function ItemList({ items }: { items: { item: string; why: string }[] }) {
  return (
    <ul className="space-y-1.5">
      {items.map((it, i) => (
        <li key={i} className="rounded-lg border border-hair/60 bg-ink-950/40 p-2 text-xs">
          <span className="text-zinc-200">{it.item}</span>
          {it.why && <span className="text-zinc-500"> — {it.why}</span>}
        </li>
      ))}
    </ul>
  )
}

// IP-centric join: host(s) -> IP (ASN) -> ports -> CVEs, worst first. Graph
// view is the default (spatial relationships read faster); table stays for
// scanning/exporting exact values.
function AttackPathsSection({
  paths,
  host,
  view,
  onViewChange,
}: {
  paths: AttackPath[]
  host: string
  view: 'graph' | 'table'
  onViewChange: (v: 'graph' | 'table') => void
}) {
  return (
    <div className="mb-6">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-zinc-200">
          🧭 Attack paths <span className="text-zinc-500">— {host} ({paths.length} asset{paths.length > 1 ? 's' : ''})</span>
        </h2>
        <div className="flex gap-1 rounded-lg border border-hair bg-ink-900/60 p-0.5 text-xs">
          {(['graph', 'table'] as const).map((v) => (
            <button
              key={v}
              onClick={() => onViewChange(v)}
              className={`rounded px-2 py-1 capitalize transition ${
                view === v ? 'bg-accent-600/80 text-white' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>
      {view === 'graph' ? <AttackGraph paths={paths} host={host} /> : <AttackPathsTable paths={paths} />}
    </div>
  )
}

function AttackPathsTable({ paths }: { paths: AttackPath[] }) {
  return (
    <div>
      <div className="overflow-x-auto rounded-xl border border-hair">
        <table className="w-full min-w-[680px] text-sm">
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
