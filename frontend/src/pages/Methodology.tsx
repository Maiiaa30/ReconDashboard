import { useCallback, useState } from 'react'
import { CheckCircle2, Circle, Loader, Search } from 'lucide-react'
import { api, type Methodology as MethodologyData, type MethodologySkill, type StepStatus } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Card, Empty, PageHeader } from '../components/ui'

const STATUS: Record<StepStatus, { label: string; cls: string; icon: typeof Circle }> = {
  found: { label: 'found', cls: 'text-green-400', icon: CheckCircle2 },
  done: { label: 'ran', cls: 'text-blue-400', icon: CheckCircle2 },
  running: { label: 'running', cls: 'text-amber-400', icon: Loader },
  todo: { label: 'to do', cls: 'text-zinc-600', icon: Circle },
}

function CoverageBar({ pct }: { pct: number }) {
  const tone = pct >= 80 ? 'bg-green-500' : pct >= 40 ? 'bg-amber-500' : 'bg-zinc-600'
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-ink-800">
      <div className={`h-full rounded-full ${tone} transition-all`} style={{ width: `${pct}%` }} />
    </div>
  )
}

function SkillCard({ skill }: { skill: MethodologySkill }) {
  return (
    <Card>
      <div className="mb-1 flex items-center gap-2">
        <h2 className="text-sm font-semibold text-zinc-100">{skill.name}</h2>
        <Badge tone={skill.coverage >= 80 ? 'green' : skill.coverage >= 40 ? 'amber' : 'zinc'}>{skill.coverage}%</Badge>
        <span className="ml-auto text-[11px] text-zinc-500">{skill.reason}</span>
      </div>
      <p className="mb-2 text-xs text-zinc-500">{skill.description}</p>
      <CoverageBar pct={skill.coverage} />
      <div className="mt-3 space-y-1">
        {skill.steps.map((st) => {
          const s = STATUS[st.status]
          const Icon = s.icon
          return (
            <div key={st.key} className="flex items-start gap-2.5 rounded-lg px-2 py-1.5 hover:bg-ink-900/50">
              <Icon size={15} className={`mt-0.5 shrink-0 ${s.cls} ${st.status === 'running' ? 'animate-spin' : ''}`} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`text-sm ${st.status === 'todo' ? 'text-zinc-300' : 'text-zinc-100'}`}>{st.label}</span>
                  <span className={`text-[11px] ${s.cls}`}>{s.label}</span>
                </div>
                <div className="text-xs text-zinc-500">
                  {st.why} <span className="text-zinc-600">· {st.run}</span>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

// Recon methodology / coverage: which packaged "skills" apply to the target and
// how far through each you are — a checklist derived from what's already run.
export function Methodology() {
  const { selected } = useApp()
  const [data, setData] = useState<MethodologyData | null>(null)

  const load = useCallback(() => {
    if (!selected) return
    api.methodology(selected.id).then(setData).catch(() => {})
  }, [selected])
  usePoll(load, 8000, !!selected)

  if (!selected) return <Empty>Select a domain to see its methodology coverage.</Empty>

  const applicable = data?.skills.filter((s) => s.applicable) ?? []
  const other = data?.skills.filter((s) => !s.applicable) ?? []
  const overall = applicable.length
    ? Math.round(applicable.reduce((a, s) => a + s.coverage, 0) / applicable.length)
    : 0

  return (
    <div>
      <PageHeader
        title="Methodology"
        subtitle={`${selected.host} — coverage across the recon skills that apply`}
        actions={<Badge tone={overall >= 80 ? 'green' : overall >= 40 ? 'amber' : 'zinc'}>{overall}% overall</Badge>}
      />

      {/* Detected signals that drive which skills apply */}
      {data && (data.tech.length > 0 || data.ports.length > 0) && (
        <Card className="mb-4">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="flex items-center gap-1.5 text-zinc-400"><Search size={13} /> Detected:</span>
            {data.tech.map((t) => (
              <Badge key={t} tone="indigo">{t}</Badge>
            ))}
            {data.ports.slice(0, 14).map((p) => (
              <span key={p} className="rounded bg-ink-800/70 px-1.5 py-0.5 font-mono text-[11px] text-zinc-400">
                :{p}
              </span>
            ))}
            {data.tech.length === 0 && data.ports.length === 0 && (
              <span className="text-zinc-600">nothing fingerprinted yet — run recon first</span>
            )}
          </div>
        </Card>
      )}

      {!data ? (
        <Empty>Loading methodology…</Empty>
      ) : (
        <div className="space-y-4">
          {applicable.map((s) => (
            <SkillCard key={s.id} skill={s} />
          ))}

          {other.length > 0 && (
            <div>
              <h2 className="mb-2 mt-6 text-xs font-semibold uppercase tracking-wide text-zinc-500">
                Not matched yet ({other.length})
              </h2>
              <div className="flex flex-wrap gap-2">
                {other.map((s) => (
                  <span key={s.id} className="rounded-lg border border-hair bg-ink-900/40 px-2.5 py-1 text-xs text-zinc-500">
                    {s.name} <span className="text-zinc-600">— needs {s.reason === 'not matched' ? 'a matching signal' : s.reason}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
