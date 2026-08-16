import { useCallback, useMemo, useState } from 'react'
import { Activity, AlertTriangle, ArrowRight, CheckCircle2, Circle, Clock, FileCheck2, Flag, ListChecks, Loader, Radar, RotateCcw, ShieldCheck, Sparkles, Square, type LucideIcon } from 'lucide-react'
import { api, type AssessmentRun, type Asset, type Finding, type Job, type Methodology, type ReportSnapshot } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, ScoreBadge, SkeletonList } from '../components/ui'
import { summarizeFinding, timeAgo } from '../lib/format'
import { useToast } from '../components/Toast'

export function CommandCenter({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const [loaded, setLoaded] = useState(false)
  const [findings, setFindings] = useState<Finding[]>([])
  const [assets, setAssets] = useState<Asset[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [methodology, setMethodology] = useState<Methodology | null>(null)
  const [snapshots, setSnapshots] = useState<ReportSnapshot[]>([])
  const [run, setRun] = useState<AssessmentRun | null>(null)
  const toast = useToast()

  const load = useCallback(() => {
    if (!selected) return
    Promise.all([
      api.findings({ domainId: selected.id, limit: 500 }),
      api.assets(selected.id),
      api.jobs(),
      api.methodology(selected.id),
      api.snapshots(selected.id),
      api.assessmentRuns(selected.id),
    ]).then(([findingResult, assetResult, jobResult, methodologyResult, snapshotResult, runResult]) => {
      setFindings(findingResult.findings)
      setAssets(assetResult.assets)
      setJobs(jobResult.jobs.filter((job) => job.domainId === selected.id))
      setMethodology(methodologyResult)
      setSnapshots(snapshotResult.snapshots)
      setRun(runResult.runs[0] ?? null)
    }).catch(() => {}).finally(() => setLoaded(true))
  }, [selected])
  usePoll(load, 6000, !!selected, selected?.id)

  const data = useMemo(() => {
    const active = findings.filter((finding) => !['false_positive', 'resolved', 'retest_passed', 'ignored'].includes(finding.status))
    const confirmed = findings.filter((finding) => finding.status === 'confirmed')
    const high = active.filter((finding) => (finding.score ?? 0) >= 70)
    const running = jobs.filter((job) => job.status === 'queued' || job.status === 'running')
    const changes = findings.filter((finding) => ['asset_change', 'cve_new', 'new_subdomain'].includes(finding.type)).slice(0, 8)
    const applicable = methodology?.skills.filter((skill) => skill.applicable) ?? []
    const methodologyCoverage = applicable.length ? Math.round(applicable.reduce((sum, skill) => sum + skill.coverage, 0) / applicable.length) : 0
    const coverage = run?.coverage ?? methodologyCoverage
    const nextSteps = applicable.flatMap((skill) => skill.steps.filter((step) => step.status === 'todo').map((step) => ({ ...step, skill: skill.name }))).slice(0, 6)
    return { active, confirmed, high, running, changes, coverage, methodologyCoverage, nextSteps }
  }, [assets, findings, jobs, methodology, run])

  if (!selected) return <Empty>Select an engagement to open its command center.</Empty>
  if (!loaded) return <><PageHeader title="Command center" subtitle={selected.host} /><SkeletonList rows={7} /></>

  const stages = [
    { label: 'Scope', done: true, page: 'domains' },
    { label: 'Discover', done: assets.some((asset) => asset.kind === 'host'), page: 'profiles' },
    { label: 'Map', done: assets.length > 0, page: 'assets' },
    { label: 'Test', done: run?.status === 'completed' || data.methodologyCoverage > 20, page: run ? 'profiles' : 'methodology' },
    { label: 'Triage', done: data.confirmed.length > 0 || findings.some((finding) => finding.status !== 'open'), page: 'findings' },
    { label: 'Report', done: snapshots.length > 0, page: 'reports' },
  ]

  return (
    <div>
      <PageHeader
        title="Command center"
        subtitle={`${selected.label ? `${selected.label} · ` : ''}${selected.host} — assessment progress and next actions`}
        actions={<><Badge tone={selected.mode === 'active_authorized' ? 'amber' : 'green'}>{selected.mode === 'active_authorized' ? 'active authorized' : 'passive only'}</Badge><Button variant="primary" onClick={() => navigate('profiles', selected.id)}><Radar size={15} /> Run profile</Button></>}
      />

      <Card className="mb-5 !p-4">
        <div className="mb-3 flex items-center justify-between"><h2 className="text-sm font-semibold text-zinc-200">Assessment lifecycle</h2><span className="text-xs text-zinc-500">{stages.filter((stage) => stage.done).length}/{stages.length} stages started</span></div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {stages.map((stage, index) => (
            <button key={stage.label} onClick={() => navigate(stage.page, selected.id)} className={`relative rounded-lg border px-3 py-3 text-left transition ${stage.done ? 'border-emerald-900/50 bg-emerald-950/15' : 'border-hair bg-ink-950/40 hover:border-hair-strong'}`}>
              <div className="flex items-center gap-2">{stage.done ? <CheckCircle2 size={15} className="text-emerald-400" /> : <Circle size={15} className="text-zinc-600" />}<span className={stage.done ? 'text-sm text-zinc-200' : 'text-sm text-zinc-500'}>{stage.label}</span></div>
              <span className="mt-1 block text-[10px] text-zinc-600">Step {index + 1}</span>
            </button>
          ))}
        </div>
      </Card>

      {run && <Card className={`mb-5 ${run.status === 'partial' ? 'border-amber-800/60' : 'border-accent-500/25'}`}>
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-0 flex-1"><div className="flex items-center gap-2">{run.status === 'running' ? <Loader size={16} className="animate-spin text-amber-400" /> : run.status === 'completed' ? <CheckCircle2 size={16} className="text-emerald-400" /> : <AlertTriangle size={16} className="text-amber-400" />}<h2 className="text-sm font-semibold">Current assessment · {run.name}</h2><Badge tone={run.status === 'completed' ? 'green' : run.status === 'partial' ? 'amber' : 'indigo'}>{run.status}</Badge></div><p className="mt-1 text-xs text-zinc-500">Run #{run.id} · phase {Math.min(run.currentPhase + 1, run.totalPhases)}/{run.totalPhases} · {run.completedSteps}/{run.totalSteps} steps · {run.completedTargetJobs}/{run.totalTargetJobs} target jobs complete</p></div>
          <div className="flex gap-2">{run.status === 'partial' && <Button variant="ghost" onClick={async () => { try { setRun((await api.retryAssessmentRun(run.id)).run); toast.success('Failed steps queued for retry.') } catch (error) { toast.error(error instanceof Error ? error.message : 'Retry failed.') } }}><RotateCcw size={14} /> Retry</Button>}{(run.status === 'queued' || run.status === 'running') && <Button variant="ghost" onClick={async () => { try { setRun((await api.cancelAssessmentRun(run.id)).run); toast.success('Assessment cancelled.') } catch (error) { toast.error(error instanceof Error ? error.message : 'Cancel failed.') } }}><Square size={13} /> Cancel</Button>}<Button variant="ghost" onClick={() => navigate('profiles', selected.id)}>View run</Button></div>
        </div>
        <div className="mt-3 h-2 overflow-hidden rounded-full bg-ink-950"><div className="h-full bg-accent-500 transition-all" style={{ width: `${run.coverage}%` }} /></div>
        <div className="mt-3 flex flex-wrap gap-1.5">{run.steps.map((step) => <Badge key={step.id} tone={step.status === 'done' ? 'green' : ['unavailable', 'failed', 'skipped'].includes(step.status) ? 'red' : ['running', 'degraded'].includes(step.status) ? 'amber' : 'zinc'}>{step.label}: {step.status}{step.evidence.targets ? ` · ${step.evidence.completed}/${step.evidence.targets} executed · ${step.evidence.findingsProduced} findings` : ''}</Badge>)}</div>
        {run.steps.some((step) => step.error) && <div className="mt-3 space-y-1 border-t border-hair/60 pt-3">{run.steps.filter((step) => step.error).map((step) => <p key={step.id} className="text-xs text-amber-300"><span className="font-medium">{step.label}:</span> {step.error}</p>)}</div>}
      </Card>}

      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Metric label="Assets" value={assets.length} icon={Sparkles} tone="text-blue-400" onClick={() => navigate('assets', selected.id)} />
        <Metric label="Active findings" value={data.active.length} icon={Flag} tone="text-amber-400" onClick={() => navigate('findings', selected.id)} />
        <Metric label="High risk" value={data.high.length} icon={ShieldCheck} tone="text-red-400" onClick={() => navigate('findings', selected.id)} />
        <Metric label="Coverage" value={`${data.coverage}%`} icon={ListChecks} tone="text-violet-400" onClick={() => navigate('methodology', selected.id)} />
        <Metric label="Running" value={data.running.length} icon={Activity} tone="text-emerald-400" onClick={() => navigate('jobs', selected.id)} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.15fr_.85fr]">
        <div className="space-y-5">
          <Card>
            <div className="mb-3 flex items-center gap-2"><Flag size={15} className="text-amber-400" /><h2 className="text-sm font-semibold">Priority queue</h2><button className="ml-auto text-xs text-zinc-500 hover:text-zinc-300" onClick={() => navigate('findings', selected.id)}>All findings →</button></div>
            {data.active.length === 0 ? <p className="text-sm text-zinc-500">No active findings. Start a discovery profile or review informational results.</p> : (
              <div className="space-y-1.5">{data.active.slice().sort((a, b) => (b.score ?? 0) - (a.score ?? 0)).slice(0, 8).map((finding) => (
                <button key={finding.id} onClick={() => navigate('findings', selected.id)} className="flex w-full items-center gap-3 rounded-lg border border-hair/70 bg-ink-950/35 px-3 py-2 text-left hover:border-hair-strong">
                  <ScoreBadge score={finding.score} /><span className="min-w-0 flex-1 truncate text-sm text-zinc-200">{summarizeFinding(finding.type, finding.data)}</span><Badge>{finding.status === 'open' ? 'draft' : finding.status.replace('_', ' ')}</Badge>
                </button>
              ))}</div>
            )}
          </Card>

          <Card>
            <div className="mb-3 flex items-center gap-2"><Sparkles size={15} className="text-blue-400" /><h2 className="text-sm font-semibold">Recent changes</h2></div>
            {data.changes.length === 0 ? <p className="text-sm text-zinc-500">No material asset changes recorded yet.</p> : <div className="space-y-2">{data.changes.map((finding) => <button key={finding.id} onClick={() => navigate('findings', selected.id)} className="flex w-full items-start gap-3 rounded-lg border border-hair/60 px-3 py-2 text-left hover:bg-ink-850"><Clock size={14} className="mt-0.5 shrink-0 text-zinc-500" /><span className="min-w-0 flex-1"><span className="block truncate text-sm text-zinc-200">{summarizeFinding(finding.type, finding.data)}</span><span className="text-xs text-zinc-600">{timeAgo(new Date(finding.createdAt).getTime())}</span></span></button>)}</div>}
          </Card>
        </div>

        <div className="space-y-5">
          <Card>
            <div className="mb-3 flex items-center gap-2"><ListChecks size={15} className="text-violet-400" /><h2 className="text-sm font-semibold">Recommended next actions</h2><Badge tone="indigo">{data.coverage}% covered</Badge></div>
            {data.nextSteps.length === 0 ? <p className="text-sm text-zinc-500">No outstanding methodology steps.</p> : <div className="space-y-2">{data.nextSteps.map((step) => <button key={`${step.skill}:${step.key}`} onClick={() => navigate('methodology', selected.id)} className="group flex w-full items-center gap-3 rounded-lg border border-hair/60 px-3 py-2 text-left hover:border-accent-500/40"><Circle size={13} className="shrink-0 text-zinc-600" /><span className="min-w-0 flex-1"><span className="block truncate text-sm text-zinc-200">{step.label}</span><span className="block truncate text-xs text-zinc-600">{step.skill}</span></span><span className="text-[11px] text-accent-fg">Review & run</span><ArrowRight size={13} className="text-zinc-600 group-hover:text-accent-fg" /></button>)}</div>}
          </Card>

          <Card>
            <div className="mb-3 flex items-center gap-2"><Activity size={15} className="text-emerald-400" /><h2 className="text-sm font-semibold">Current activity</h2></div>
            {data.running.length === 0 ? <p className="text-sm text-zinc-500">No queued or running jobs.</p> : <div className="space-y-2">{data.running.slice(0, 6).map((job) => <button key={job.id} onClick={() => navigate('jobs', selected.id)} className="w-full rounded-lg border border-hair/60 px-3 py-2 text-left"><div className="flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${job.status === 'running' ? 'animate-pulse bg-amber-400' : 'bg-zinc-500'}`} /><span className="text-sm text-zinc-200">{job.type.replaceAll('_', ' ')}</span><span className="ml-auto text-xs text-zinc-600">#{job.id}</span></div>{job.progress && <p className="mt-1 truncate text-xs text-zinc-500">{job.progress}</p>}</button>)}</div>}
          </Card>

          <Card>
            <div className="flex items-center gap-3"><FileCheck2 size={18} className="text-blue-400" /><div className="min-w-0 flex-1"><h2 className="text-sm font-semibold">Deliverables</h2><p className="text-xs text-zinc-500">{snapshots.length} frozen report snapshot{snapshots.length === 1 ? '' : 's'}</p></div><Button variant="ghost" onClick={() => navigate('reports', selected.id)}>Open reports</Button></div>
          </Card>
        </div>
      </div>
    </div>
  )
}

function Metric({ label, value, icon: Icon, tone, onClick }: { label: string; value: number | string; icon: LucideIcon; tone: string; onClick: () => void }) {
  return <button onClick={onClick} className="rounded-xl border border-hair bg-ink-850 p-3 text-left shadow-card transition hover:border-hair-strong"><div className="flex items-center justify-between"><span className="text-[10px] font-medium uppercase tracking-wide text-zinc-500">{label}</span><Icon size={15} className={tone} /></div><div className="mt-1 text-2xl font-semibold text-zinc-100">{value}</div></button>
}
