import { useCallback, useState } from 'react'
import { CheckCircle2, Circle, Loader, MinusCircle, Search } from 'lucide-react'
import {
  api,
  ApiError,
  type Methodology as MethodologyData,
  type MethodologySkill,
  type MethodologyStep,
  type StepAction,
  type StepStatus,
} from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Card, Empty, PageHeader } from '../components/ui'

const STATUS: Record<StepStatus, { label: string; cls: string; icon: typeof Circle; spin?: boolean }> = {
  found: { label: 'found', cls: 'text-green-400', icon: CheckCircle2 },
  done: { label: 'done', cls: 'text-blue-400', icon: CheckCircle2 },
  running: { label: 'running', cls: 'text-amber-400', icon: Loader, spin: true },
  todo: { label: 'to do', cls: 'text-zinc-600', icon: Circle },
  skipped: { label: 'skipped', cls: 'text-zinc-600', icon: MinusCircle },
}

const ACTIVE_KINDS = new Set<StepAction['kind']>(['tool', 'nmap', 'nuclei', 'ffuf', 'owasp'])

// Map a step's action to the existing (gated) endpoint. Passive kinds ignore
// confirm; active kinds send confirm=true when the domain is passive_only.
async function runStepAction(domainId: number, a: StepAction, host: string, confirm: boolean): Promise<number> {
  switch (a.kind) {
    case 'discover':
      return (await api.discover(domainId)).jobId
    case 'exposure':
      return (await api.exposure(domainId)).jobId
    case 'osint':
      return (await api.osint(domainId)).jobId
    case 'screenshots':
      return (await api.captureScreenshots(domainId)).jobId
    case 'origin':
      return (await api.findOrigin(domainId)).jobId
    case 'owasp':
      return (await api.runOwasp(domainId, undefined, undefined, confirm)).jobId
    case 'nmap':
      return (await api.nmap(domainId, { target: host, confirm })).jobId
    case 'nuclei':
      return (await api.nuclei(domainId, { target: host, tags: a.tags, confirm })).jobId
    case 'ffuf':
      return (await api.ffuf(domainId, { target: host, confirm })).jobId
    case 'tool':
      return (await api.runTool(domainId, { tool: a.tool!, target: host, confirm })).jobId
  }
}

function RunButton({ domainId, host, active, action }: { domainId: number; host: string; active: boolean; action: StepAction }) {
  const [state, setState] = useState<'idle' | 'running' | 'done' | 'error'>('idle')
  const [msg, setMsg] = useState('')
  const label = action.tool ?? action.kind

  async function go() {
    if (!active && ACTIVE_KINDS.has(action.kind)) {
      const ok = window.confirm(
        `⚠ "${label}" is a LOUD, active step and ${host} is passive_only.\n\nOnly run it if you are authorized to actively test ${host}.\n\nRun anyway?`,
      )
      if (!ok) return
    }
    setState('running')
    try {
      const jobId = await runStepAction(domainId, action, host, !active)
      setMsg(`queued #${jobId}`)
      setState('done')
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : 'failed')
      setState('error')
    }
  }

  if (state === 'done') return <span className="text-[11px] text-emerald-400">✓ {msg}</span>
  if (state === 'running') return <span className="text-[11px] text-zinc-400">queuing…</span>
  return (
    <span className="inline-flex items-center gap-1.5">
      <button
        onClick={go}
        className="rounded border border-accent-500/40 px-2 py-0.5 text-[11px] text-accent-fg transition hover:bg-accent-500/10"
      >
        ▶ Run {label}
      </button>
      {state === 'error' && <span className="text-[11px] text-red-400">{msg}</span>}
    </span>
  )
}

function OverrideControls({
  domainId,
  skillId,
  step,
  onUpdate,
}: {
  domainId: number
  skillId: string
  step: MethodologyStep
  onUpdate: (m: MethodologyData) => void
}) {
  const set = (s: 'done' | 'skipped' | 'clear') =>
    api.setMethodologyStep(domainId, skillId, step.key, s).then(onUpdate).catch(() => {})
  if (step.manual) {
    return (
      <button onClick={() => set('clear')} className="text-[11px] text-zinc-500 transition hover:text-zinc-300">
        clear
      </button>
    )
  }
  return (
    <span className="inline-flex gap-2 text-[11px] text-zinc-600">
      <button onClick={() => set('done')} className="transition hover:text-emerald-400">
        done
      </button>
      <button onClick={() => set('skipped')} className="transition hover:text-zinc-300">
        skip
      </button>
    </span>
  )
}

function CoverageBar({ pct }: { pct: number }) {
  const tone = pct >= 80 ? 'bg-green-500' : pct >= 40 ? 'bg-amber-500' : 'bg-zinc-600'
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-ink-800">
      <div className={`h-full rounded-full ${tone} transition-all`} style={{ width: `${pct}%` }} />
    </div>
  )
}

function SkillCard({
  skill,
  domainId,
  host,
  active,
  onUpdate,
}: {
  skill: MethodologySkill
  domainId: number
  host: string
  active: boolean
  onUpdate: (m: MethodologyData) => void
}) {
  return (
    <Card>
      <div className="mb-1 flex items-center gap-2">
        <h2 className="text-sm font-semibold text-zinc-100">{skill.name}</h2>
        <Badge tone={skill.coverage >= 80 ? 'green' : skill.coverage >= 40 ? 'amber' : 'zinc'}>{skill.coverage}%</Badge>
        <span className="ml-auto text-[11px] text-zinc-500">{skill.reason}</span>
      </div>
      <p className="mb-2 text-xs text-zinc-500">{skill.description}</p>
      <CoverageBar pct={skill.coverage} />
      <div className="mt-3 space-y-0.5">
        {skill.steps.map((st) => {
          const s = STATUS[st.status]
          const Icon = s.icon
          const runnable = st.status === 'todo' || st.status === 'running'
          return (
            <div key={st.key} className="flex items-start gap-2.5 rounded-lg px-2 py-1.5 hover:bg-ink-900/50">
              <Icon size={15} className={`mt-0.5 shrink-0 ${s.cls} ${s.spin ? 'animate-spin' : ''}`} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`text-sm ${st.status === 'skipped' ? 'text-zinc-500 line-through' : st.status === 'todo' ? 'text-zinc-300' : 'text-zinc-100'}`}>
                    {st.label}
                  </span>
                  <span className={`text-[11px] ${s.cls}`}>{s.label}{st.manual ? ' (manual)' : ''}</span>
                </div>
                <div className="text-xs text-zinc-500">{st.why}</div>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                {runnable && <RunButton domainId={domainId} host={host} active={active} action={st.action} />}
                {st.status !== 'found' && (
                  <OverrideControls domainId={domainId} skillId={skill.id} step={st} onUpdate={onUpdate} />
                )}
              </div>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

// Recon methodology / coverage: which packaged "skills" apply to the target, how
// far through each you are, one-click run per step, and manual done/skip.
export function Methodology() {
  const { selected } = useApp()
  const [data, setData] = useState<MethodologyData | null>(null)

  const load = useCallback(() => {
    if (!selected) return
    api.methodology(selected.id).then(setData).catch(() => {})
  }, [selected])
  usePoll(load, 8000, !!selected)

  if (!selected) return <Empty>Select a domain to see its methodology coverage.</Empty>

  const active = selected.mode === 'active_authorized'
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

      {data && (
        <Card className="mb-4">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="flex items-center gap-1.5 text-zinc-400">
              <Search size={13} /> Detected:
            </span>
            {data.tech.map((t) => (
              <Badge key={t} tone="indigo">{t}</Badge>
            ))}
            {data.ports.slice(0, 14).map((p) => (
              <span key={p} className="rounded bg-ink-800/70 px-1.5 py-0.5 font-mono text-[11px] text-zinc-400">:{p}</span>
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
            <SkillCard key={s.id} skill={s} domainId={selected.id} host={selected.host} active={active} onUpdate={setData} />
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
