import { useCallback, useMemo, useState } from 'react'
import { ArrowRight, Check, CheckCircle2, CircleDot, ListChecks, RotateCcw, ShieldAlert, Sparkles, Target, X } from 'lucide-react'
import { api, type NextAction, type NextActionStatus } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, SkeletonList } from '../components/ui'
import { useToast } from '../components/Toast'
import { setPendingFindingFilter, setPendingOwasp, setPendingScan } from '../lib/navigationHandoff'

type View = 'active' | 'completed' | 'dismissed'
type Mode = 'all' | NextAction['mode']

const riskTone: Record<NextAction['risk'], 'red' | 'amber' | 'blue' | 'zinc'> = { critical: 'red', high: 'red', medium: 'amber', low: 'zinc' }
const sourceLabel: Record<NextAction['source'], string> = { assessment: 'assessment', finding: 'finding', attack_chain: 'attack chain', methodology: 'methodology' }

export function NextActions({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const toast = useToast()
  const [actions, setActions] = useState<NextAction[]>([])
  const [loaded, setLoaded] = useState(false)
  const [view, setView] = useState<View>('active')
  const [mode, setMode] = useState<Mode>('all')
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(() => {
    if (!selected) return
    api.nextActions(selected.id).then((result) => setActions(result.actions)).catch(() => {}).finally(() => setLoaded(true))
  }, [selected])
  usePoll(load, 6000, !!selected, selected?.id)

  const counts = useMemo(() => ({
    active: actions.filter((action) => action.status === 'open' || action.status === 'attempted').length,
    critical: actions.filter((action) => (action.status === 'open' || action.status === 'attempted') && action.risk === 'critical').length,
    attempted: actions.filter((action) => action.status === 'attempted').length,
    completed: actions.filter((action) => action.status === 'completed').length,
  }), [actions])

  const visible = useMemo(() => actions.filter((action) => {
    const statusMatch = view === 'active' ? action.status === 'open' || action.status === 'attempted' : action.status === view
    return statusMatch && (mode === 'all' || action.mode === mode)
  }), [actions, view, mode])

  async function update(action: NextAction, state: NextActionStatus) {
    if (!selected) return
    setBusy(action.key)
    try {
      const result = await api.updateNextAction(selected.id, action.key, state)
      setActions(result.actions)
      toast.success(state === 'open' ? 'Action reopened.' : `Action marked ${state}.`)
    } catch (error) { toast.error(error instanceof Error ? error.message : 'Failed to update action.') }
    finally { setBusy(null) }
  }

  async function open(action: NextAction) {
    if (!selected) return
    if (action.status === 'open') {
      try { setActions((await api.updateNextAction(selected.id, action.key, 'attempted')).actions) } catch { /* navigation is still useful */ }
    }
    if (action.page === 'findings') setPendingFindingFilter({ domainId: selected.id, asset: action.target })
    if (action.page === 'scans') setPendingScan({ target: action.target })
    if (action.page === 'owasp') setPendingOwasp({ target: action.target })
    navigate(action.page, selected.id)
  }

  if (!selected) return <Empty>Select an engagement to view its next actions.</Empty>

  return <div>
    <PageHeader title="Next actions" subtitle={`${selected.host} - the complete operational queue`} actions={<Button variant="ghost" onClick={() => navigate('methodology', selected.id)}><ListChecks size={14} /> Coverage reference</Button>} />
    {!loaded ? <SkeletonList rows={7} /> : <>
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Active" value={counts.active} tone="text-accent-400" />
        <Metric label="Critical" value={counts.critical} tone="text-red-400" />
        <Metric label="In progress" value={counts.attempted} tone="text-amber-400" />
        <Metric label="Completed" value={counts.completed} tone="text-emerald-400" />
      </div>

      <Card className="mb-5 border-accent-500/20 bg-accent-500/5">
        <div className="flex items-start gap-3"><Sparkles size={18} className="mt-0.5 shrink-0 text-accent-400" /><div><h2 className="text-sm font-semibold text-zinc-100">Priority is deterministic and evidence-backed</h2><p className="mt-1 text-sm text-zinc-400">Assessment gaps and grounded attack chains rank first, followed by material findings and uncovered methodology. Opening an action marks it attempted; completion and dismissal remain stored across restarts.</p></div></div>
      </Card>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {(['active', 'completed', 'dismissed'] as View[]).map((item) => <button key={item} onClick={() => setView(item)} className={`rounded-lg px-3 py-1.5 text-sm ${view === item ? 'bg-accent-500/15 text-accent-fg' : 'text-zinc-500 hover:bg-ink-850 hover:text-zinc-300'}`}>{item}</button>)}
        <span className="mx-1 h-5 w-px bg-hair" />
        {(['all', 'passive', 'loud', 'manual'] as Mode[]).map((item) => <button key={item} onClick={() => setMode(item)} className={`rounded-full border px-2.5 py-1 text-xs ${mode === item ? 'border-hair-strong bg-ink-800 text-zinc-200' : 'border-hair text-zinc-600 hover:text-zinc-400'}`}>{item}</button>)}
      </div>

      {visible.length === 0 ? <Empty>No {view} actions match this filter.</Empty> : <div className="space-y-3">{visible.map((action, index) => <Card key={action.key} className={action.risk === 'critical' && view === 'active' ? 'border-red-900/60 bg-red-950/10' : ''}>
        <div className="flex flex-wrap items-start gap-3">
          <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl font-semibold ${action.priority >= 90 ? 'bg-red-500/15 text-red-300' : action.priority >= 70 ? 'bg-amber-500/15 text-amber-300' : 'bg-ink-700 text-zinc-300'}`}>{index + 1}</span>
          <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h2 className="font-medium text-zinc-100">{action.title}</h2><Badge tone={riskTone[action.risk]}>{action.risk}</Badge>{action.status === 'attempted' && <Badge tone="amber">attempted</Badge>}</div><p className="mt-1 text-sm leading-relaxed text-zinc-400">{action.why}</p><div className="mt-2 flex flex-wrap items-center gap-2 text-xs"><span className="flex items-center gap-1 font-mono text-zinc-500"><Target size={12} /> {action.target}</span><Badge>{sourceLabel[action.source]}</Badge><Badge tone={action.mode === 'loud' ? 'red' : action.mode === 'passive' ? 'green' : 'zinc'}>{action.mode}</Badge><Badge tone="indigo">{action.automation}</Badge><span className="text-zinc-600">priority {action.priority}</span></div></div>
          <div className="flex flex-wrap items-center gap-2">{view === 'active' ? <><Button variant="primary" disabled={busy === action.key} onClick={() => open(action)}>Open {action.moduleLabel} <ArrowRight size={14} /></Button><Button variant="ghost" disabled={busy === action.key} onClick={() => update(action, 'completed')}><Check size={14} /> Complete</Button><button disabled={busy === action.key} onClick={() => update(action, 'dismissed')} className="rounded-lg p-2 text-zinc-600 hover:bg-ink-800 hover:text-zinc-300" title="Dismiss"><X size={15} /></button></> : <Button variant="ghost" disabled={busy === action.key} onClick={() => update(action, 'open')}><RotateCcw size={14} /> Reopen</Button>}</div>
        </div>
      </Card>)}</div>}
    </>}
  </div>
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  const Icon = label === 'Critical' ? ShieldAlert : label === 'Completed' ? CheckCircle2 : CircleDot
  return <div className="rounded-xl border border-hair bg-ink-850 p-3"><div className="flex items-center justify-between"><span className="text-xs text-zinc-500">{label}</span><Icon size={15} className={tone} /></div><div className="mt-1 text-2xl font-semibold text-zinc-100">{value}</div></div>
}
