import { useEffect, useMemo, useState } from 'react'
import { Activity, AlertTriangle, Check, CheckCircle2, ChevronDown, Clock3, Loader, Radar, RotateCcw, Save, ShieldCheck, Sparkles, Square, Zap, type LucideIcon } from 'lucide-react'
import { api, type AssessmentAction, type AssessmentRun } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { useConfirm } from '../components/Confirm'
import { useToast } from '../components/Toast'

type StepKey = 'discover' | 'exposure' | 'osint' | 'screenshots' | 'api' | 'nmap' | 'nuclei' | 'ffuf' | 'owasp' | 'params'
type Profile = { id: string; name: string; description: string; active: boolean; steps: StepKey[]; icon: LucideIcon; tone: string }

const STEPS: Record<StepKey, { label: string; active: boolean }> = {
  discover: { label: 'Subdomain discovery', active: false },
  exposure: { label: 'Exposure intelligence', active: false },
  osint: { label: 'OSINT collection', active: false },
  screenshots: { label: 'Screenshots', active: false },
  api: { label: 'API surface discovery', active: false },
  nmap: { label: 'Nmap surface sweep', active: true },
  nuclei: { label: 'Nuclei checks', active: true },
  ffuf: { label: 'Content discovery', active: true },
  owasp: { label: 'OWASP web checks', active: true },
  params: { label: 'Parameter discovery', active: true },
}

const BUILT_INS: Profile[] = [
  { id: 'passive', name: 'Passive foundation', description: 'Build the asset map without loud testing. Best first run for every engagement.', active: false, steps: ['discover', 'exposure', 'osint', 'screenshots', 'api'], icon: Sparkles, tone: 'border-blue-900/50 bg-blue-950/10' },
  { id: 'monitor', name: 'Continuous surface refresh', description: 'Validate DNS, enrich live web assets, check takeover signals and detect response changes.', active: false, steps: ['discover', 'exposure', 'screenshots', 'osint', 'api'], icon: Clock3, tone: 'border-emerald-900/50 bg-emerald-950/10' },
  { id: 'web', name: 'Web assessment', description: 'Map the web surface, parameters and common application weaknesses.', active: true, steps: ['screenshots', 'api', 'params', 'ffuf', 'owasp'], icon: ShieldCheck, tone: 'border-amber-900/50 bg-amber-950/10' },
  { id: 'full', name: 'Full authorized assessment', description: 'Run broad discovery plus active network and web coverage.', active: true, steps: ['discover', 'exposure', 'osint', 'screenshots', 'api', 'nmap', 'nuclei', 'ffuf', 'owasp', 'params'], icon: Zap, tone: 'border-red-900/50 bg-red-950/10' },
]

const CUSTOM_STORAGE = 'assessmentCustomProfile'

export function ScanProfiles({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const ask = useConfirm()
  const toast = useToast()
  const [running, setRunning] = useState<string | null>(null)
  const [results, setResults] = useState<Record<string, string>>({})
  const [customName, setCustomName] = useState('My assessment profile')
  const [customSteps, setCustomSteps] = useState<StepKey[]>(['discover', 'exposure', 'osint'])
  const [builderOpen, setBuilderOpen] = useState(false)
  const [latestRun, setLatestRun] = useState<AssessmentRun | null>(null)

  usePoll(() => {
    if (!selected) return
    api.assessmentRuns(selected.id).then((result) => setLatestRun(result.runs[0] ?? null)).catch(() => {})
  }, 2500, !!selected, selected?.id)

  useEffect(() => {
    try {
      const stored = JSON.parse(localStorage.getItem(CUSTOM_STORAGE) ?? 'null') as { name?: string; steps?: StepKey[] } | null
      if (stored?.name) setCustomName(stored.name)
      if (stored?.steps?.length) setCustomSteps(stored.steps.filter((step) => step in STEPS))
    } catch { /* ignore malformed local preference */ }
  }, [])

  const customProfile = useMemo<Profile>(() => ({ id: 'custom', name: customName.trim() || 'Custom profile', description: 'Your reusable selection, stored in this browser.', active: customSteps.some((step) => STEPS[step].active), steps: customSteps, icon: Save, tone: 'border-violet-900/50 bg-violet-950/10' }), [customName, customSteps])

  if (!selected) return <Empty>Select an engagement before running an assessment profile.</Empty>

  async function runProfile(profile: Profile) {
    if (!selected || running) return
    if (latestRun?.status === 'queued' || latestRun?.status === 'running') return toast.error(`Assessment run #${latestRun.id} is already active.`)
    if (profile.steps.length === 0) return toast.error('Select at least one step for the custom profile.')
    const requiresOverride = profile.active && selected.mode !== 'active_authorized'
    if (profile.active) {
      const ok = await ask({
        title: `Run ${profile.name}?`,
        message: `${profile.name} includes loud, active testing against ${selected.host}. Only continue if this target is in scope and you are authorized to run every selected step.`,
        confirmLabel: 'Run profile',
        tone: 'danger',
      })
      if (!ok) return
    }
    setRunning(profile.id)
    setResults((current) => ({ ...current, [profile.id]: '' }))
    try {
      const { run } = await api.createAssessmentRun(selected.id, {
        profile: profile.id as 'passive' | 'monitor' | 'web' | 'full' | 'custom',
        name: profile.name,
        ...(profile.id === 'custom' ? { steps: profile.steps as AssessmentAction[] } : {}),
        confirm: requiresOverride,
      })
      setLatestRun(run)
      const message = `Assessment run #${run.id} started in ordered phases`
      setResults((current) => ({ ...current, [profile.id]: message }))
      toast.success(message)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to start assessment run.')
    } finally {
      setRunning(null)
    }
  }

  function saveCustom() {
    localStorage.setItem(CUSTOM_STORAGE, JSON.stringify({ name: customName.trim() || 'Custom profile', steps: customSteps }))
    toast.success('Custom profile saved in this browser.')
    setBuilderOpen(false)
  }

  function toggleStep(step: StepKey) {
    setCustomSteps((current) => current.includes(step) ? current.filter((value) => value !== step) : [...current, step])
  }

  return (
    <div>
      <PageHeader title="Assessment profiles" subtitle={`${selected.host} — reusable workflows instead of starting every tool manually`} actions={<Button variant="ghost" onClick={() => navigate('jobs', selected.id)}><Activity size={15} /> View activity</Button>} />

      <Card className="mb-5 border-accent-500/20 bg-accent-500/5">
        <div className="flex items-start gap-3"><Radar size={20} className="mt-0.5 shrink-0 text-accent-400" /><div><h2 className="text-sm font-semibold text-zinc-100">Choose the smallest profile that answers the assessment question</h2><p className="mt-1 text-sm text-zinc-400">Passive profiles gather context. Active profiles still pass through scope, authorization-window, duplicate-job and cooldown controls.</p></div></div>
      </Card>

      {latestRun && <RunProgress run={latestRun} onChange={setLatestRun} navigate={navigate} />}

      <div className="grid gap-4 lg:grid-cols-2">
        {[...BUILT_INS, customProfile].map((profile) => <ProfileCard key={profile.id} profile={profile} running={running === profile.id} disabled={latestRun?.status === 'queued' || latestRun?.status === 'running'} result={results[profile.id]} onRun={() => runProfile(profile)} onEdit={profile.id === 'custom' ? () => setBuilderOpen((value) => !value) : undefined} />)}
      </div>

      {builderOpen && (
        <Card className="mt-5 border-violet-900/50">
          <div className="mb-3 flex items-center justify-between"><div><h2 className="text-sm font-semibold">Custom profile builder</h2><p className="text-xs text-zinc-500">Saved locally and reusable for every engagement.</p></div><Button variant="primary" onClick={saveCustom}><Save size={14} /> Save profile</Button></div>
          <label className="mb-4 block text-xs text-zinc-400">Profile name<input value={customName} onChange={(event) => setCustomName(event.target.value)} className="mt-1 block w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent-500" /></label>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{(Object.keys(STEPS) as StepKey[]).map((step) => {
            const checked = customSteps.includes(step)
            return <button key={step} onClick={() => toggleStep(step)} className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm transition ${checked ? 'border-violet-700/60 bg-violet-950/30 text-zinc-100' : 'border-hair text-zinc-500 hover:border-hair-strong'}`}><span className={`flex h-4 w-4 items-center justify-center rounded border ${checked ? 'border-violet-500 bg-violet-500 text-white' : 'border-zinc-700'}`}>{checked && <Check size={11} />}</span><span className="min-w-0 flex-1 truncate">{STEPS[step].label}</span>{STEPS[step].active && <Badge tone="amber">active</Badge>}</button>
          })}</div>
        </Card>
      )}
    </div>
  )
}

function RunProgress({ run, onChange, navigate }: { run: AssessmentRun; onChange: (run: AssessmentRun) => void; navigate: (page: string, domainId?: number) => void }) {
  const toast = useToast()
  const active = run.status === 'queued' || run.status === 'running'
  const problem = run.status === 'partial' || run.steps.some((step) => ['degraded', 'unavailable', 'failed', 'skipped'].includes(step.status))
  async function retry() {
    try { onChange((await api.retryAssessmentRun(run.id)).run); toast.success('Failed steps queued for retry.') }
    catch (error) { toast.error(error instanceof Error ? error.message : 'Retry failed.') }
  }
  async function cancel() {
    try { onChange((await api.cancelAssessmentRun(run.id)).run); toast.success('Assessment run cancelled.') }
    catch (error) { toast.error(error instanceof Error ? error.message : 'Cancel failed.') }
  }
  return <Card className="mb-5 border-accent-500/30">
    <div className="mb-3 flex flex-wrap items-start gap-3">
      <div className="min-w-0 flex-1"><div className="flex items-center gap-2"><h2 className="font-medium text-zinc-100">{run.name}</h2><Badge tone={run.status === 'completed' ? 'green' : problem ? 'amber' : 'indigo'}>{run.status}</Badge></div><p className="mt-1 text-xs text-zinc-500">Run #{run.id} · phase {Math.min(run.currentPhase + 1, run.totalPhases)}/{run.totalPhases} · {run.completedSteps}/{run.totalSteps} steps · {run.completedTargetJobs}/{run.totalTargetJobs} concrete target jobs complete</p></div>
      <div className="flex gap-2">{problem && !active && <Button variant="ghost" onClick={retry}><RotateCcw size={14} /> Retry problems</Button>}{active && <Button variant="ghost" onClick={cancel}><Square size={13} /> Cancel run</Button>}<Button variant="ghost" onClick={() => navigate('command', run.domainId)}>Command center</Button></div>
    </div>
    <div className="mb-4 h-2 overflow-hidden rounded-full bg-ink-950"><div className="h-full bg-accent-500 transition-all" style={{ width: `${run.coverage}%` }} /></div>
    <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">{run.steps.map((step) => {
      const hasProblem = ['degraded', 'unavailable', 'failed', 'skipped'].includes(step.status)
      const Icon = step.status === 'done' ? CheckCircle2 : step.status === 'running' ? Loader : hasProblem ? AlertTriangle : Clock3
      const tone = step.status === 'done' ? 'text-emerald-400' : step.status === 'running' ? 'text-amber-400' : step.status === 'degraded' ? 'text-amber-400' : hasProblem ? 'text-red-400' : 'text-zinc-600'
      const evidence = step.evidence
      return <div key={step.id} className="rounded-lg border border-hair/70 bg-ink-950/30 px-3 py-2"><div className="flex items-center gap-2"><Icon size={14} className={`${tone} ${step.status === 'running' ? 'animate-spin' : ''}`} /><span className="min-w-0 flex-1 truncate text-sm text-zinc-200">{step.label}</span><span className={`text-[10px] ${tone}`}>{step.status}</span></div><p className="mt-1 truncate text-[11px] text-zinc-500">{evidence.targets ? `${evidence.completed}/${evidence.targets} executed · ${evidence.findingsProduced} finding${evidence.findingsProduced === 1 ? '' : 's'}${evidence.highFindings ? ` · ${evidence.highFindings} high-risk` : ''}` : step.error ?? `phase ${step.phase + 1}`}</p>{(evidence.degraded > 0 || evidence.unavailable > 0 || evidence.failed > 0) && <p className="mt-1 text-[11px] text-amber-400/90">{evidence.degraded ? `${evidence.degraded} degraded · ` : ''}{evidence.unavailable ? `${evidence.unavailable} unavailable · ` : ''}{evidence.failed ? `${evidence.failed} failed` : ''}</p>}{step.error && <p className="mt-1 line-clamp-2 text-[11px] text-red-400/80" title={step.error}>{step.error}</p>}{step.jobs.some((job) => job.summary.length) && <p className="mt-1 truncate text-[10px] text-zinc-600" title={step.jobs.flatMap((job) => job.summary).join(' · ')}>{step.jobs.flatMap((job) => job.summary).slice(0, 4).join(' · ')}</p>}</div>
    })}</div>
  </Card>
}

function ProfileCard({ profile, running, disabled, result, onRun, onEdit }: { profile: Profile; running: boolean; disabled?: boolean; result?: string; onRun: () => void; onEdit?: () => void }) {
  const Icon = profile.icon
  return <Card className={profile.tone}><div className="flex items-start gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-ink-950/60"><Icon size={19} className="text-zinc-300" /></span><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h2 className="font-medium text-zinc-100">{profile.name}</h2><Badge tone={profile.active ? 'amber' : 'green'}>{profile.active ? 'active' : 'passive'}</Badge></div><p className="mt-1 text-sm text-zinc-400">{profile.description}</p></div></div><div className="mt-4 flex flex-wrap gap-1.5">{profile.steps.map((step) => <Badge key={step}>{STEPS[step].label}</Badge>)}</div><div className="mt-4 flex items-center gap-2"><Button variant={profile.active ? 'loud' : 'primary'} onClick={onRun} disabled={running || disabled}>{running ? 'Queuing…' : disabled ? 'Run in progress' : 'Run profile'}</Button>{onEdit && <Button variant="ghost" onClick={onEdit}>Customize <ChevronDown size={13} /></Button>}{result && <span className="ml-auto text-xs text-emerald-400">{result}</span>}</div></Card>
}
