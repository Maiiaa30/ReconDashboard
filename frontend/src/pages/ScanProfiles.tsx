import { useEffect, useMemo, useState } from 'react'
import { Activity, Check, ChevronDown, Clock3, Radar, Save, ShieldCheck, Sparkles, Zap, type LucideIcon } from 'lucide-react'
import { api } from '../api'
import { useApp } from '../state'
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

  useEffect(() => {
    try {
      const stored = JSON.parse(localStorage.getItem(CUSTOM_STORAGE) ?? 'null') as { name?: string; steps?: StepKey[] } | null
      if (stored?.name) setCustomName(stored.name)
      if (stored?.steps?.length) setCustomSteps(stored.steps.filter((step) => step in STEPS))
    } catch { /* ignore malformed local preference */ }
  }, [])

  const customProfile = useMemo<Profile>(() => ({ id: 'custom', name: customName.trim() || 'Custom profile', description: 'Your reusable selection, stored in this browser.', active: customSteps.some((step) => STEPS[step].active), steps: customSteps, icon: Save, tone: 'border-violet-900/50 bg-violet-950/10' }), [customName, customSteps])

  if (!selected) return <Empty>Select an engagement before running an assessment profile.</Empty>

  async function runStep(step: StepKey, confirm: boolean): Promise<number[]> {
    if (!selected) return []
    switch (step) {
      case 'discover': return [(await api.discover(selected.id)).jobId]
      case 'exposure': return [(await api.exposure(selected.id)).jobId]
      case 'osint': return [(await api.osint(selected.id)).jobId]
      case 'screenshots': return [(await api.captureScreenshots(selected.id)).jobId]
      case 'api': return [(await api.apiDiscovery(selected.id)).jobId]
      case 'nmap': return (await api.nmapSweep(selected.id, { confirm })).jobs.map((job) => job.jobId)
      case 'nuclei': return [(await api.nuclei(selected.id, { target: selected.host, confirm })).jobId]
      case 'ffuf': return [(await api.ffuf(selected.id, { target: selected.host, confirm })).jobId]
      case 'owasp': return [(await api.runOwasp(selected.id, undefined, undefined, confirm, selected.host)).jobId]
      case 'params': return [(await api.paramDiscovery(selected.id, { target: selected.host, confirm })).jobId]
    }
  }

  async function runProfile(profile: Profile) {
    if (!selected || running) return
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
    const queued: number[] = []
    const failed: string[] = []
    for (const step of profile.steps) {
      try {
        queued.push(...await runStep(step, requiresOverride))
      } catch (error) {
        failed.push(`${STEPS[step].label}: ${error instanceof Error ? error.message : 'failed'}`)
      }
    }
    const message = `${queued.length} job${queued.length === 1 ? '' : 's'} queued${failed.length ? ` · ${failed.length} step${failed.length === 1 ? '' : 's'} skipped` : ''}`
    setResults((current) => ({ ...current, [profile.id]: message }))
    if (queued.length) toast.success(message)
    if (failed.length) toast.error(failed.join(' · '))
    setRunning(null)
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

      <div className="grid gap-4 lg:grid-cols-2">
        {[...BUILT_INS, customProfile].map((profile) => <ProfileCard key={profile.id} profile={profile} running={running === profile.id} result={results[profile.id]} onRun={() => runProfile(profile)} onEdit={profile.id === 'custom' ? () => setBuilderOpen((value) => !value) : undefined} />)}
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

function ProfileCard({ profile, running, result, onRun, onEdit }: { profile: Profile; running: boolean; result?: string; onRun: () => void; onEdit?: () => void }) {
  const Icon = profile.icon
  return <Card className={profile.tone}><div className="flex items-start gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-ink-950/60"><Icon size={19} className="text-zinc-300" /></span><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h2 className="font-medium text-zinc-100">{profile.name}</h2><Badge tone={profile.active ? 'amber' : 'green'}>{profile.active ? 'active' : 'passive'}</Badge></div><p className="mt-1 text-sm text-zinc-400">{profile.description}</p></div></div><div className="mt-4 flex flex-wrap gap-1.5">{profile.steps.map((step) => <Badge key={step}>{STEPS[step].label}</Badge>)}</div><div className="mt-4 flex items-center gap-2"><Button variant={profile.active ? 'loud' : 'primary'} onClick={onRun} disabled={running}>{running ? 'Queuing…' : 'Run profile'}</Button>{onEdit && <Button variant="ghost" onClick={onEdit}>Customize <ChevronDown size={13} /></Button>}{result && <span className="ml-auto text-xs text-emerald-400">{result}</span>}</div></Card>
}
