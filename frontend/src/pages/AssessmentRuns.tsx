import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, Download, FileCheck2, History, Loader, RotateCcw, Square, Target } from 'lucide-react'
import { api, type AssessmentComparison, type AssessmentFindingSnapshot, type AssessmentRun, type AssessmentStepJob } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, ScoreBadge, SkeletonList } from '../components/ui'
import { useToast } from '../components/Toast'

const ACTIVE = new Set(['queued', 'running'])
const RETRYABLE = new Set(['degraded', 'unavailable', 'failed', 'cancelled', 'missing'])

function statusTone(status: string): 'green' | 'amber' | 'red' | 'indigo' | 'zinc' {
  if (status === 'completed' || status === 'done') return 'green'
  if (status === 'running' || status === 'queued') return 'indigo'
  if (status === 'partial' || status === 'degraded' || status === 'unavailable') return 'amber'
  if (status === 'failed' || status === 'cancelled' || status === 'missing') return 'red'
  return 'zinc'
}

export function AssessmentRuns({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const toast = useToast()
  const [runs, setRuns] = useState<AssessmentRun[]>([])
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null)
  const [run, setRun] = useState<AssessmentRun | null>(null)
  const [comparison, setComparison] = useState<AssessmentComparison | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [loadError, setLoadError] = useState(false)

  useEffect(() => { setRuns([]); setSelectedRunId(null); setRun(null); setComparison(null); setLoaded(false); setLoadError(false) }, [selected?.id])

  const load = useCallback((signal?: AbortSignal) => {
    if (!selected) return
    return api.assessmentRuns(selected.id).then(async ({ runs: next }) => {
      if (signal?.aborted) return
      setRuns(next)
      setLoadError(false)
      const id = selectedRunId && next.some((item) => item.id === selectedRunId) ? selectedRunId : next[0]?.id ?? null
      if (id !== selectedRunId) setSelectedRunId(id)
      if (!id) { setRun(null); setComparison(null); return }
      const [{ run: detail }, { comparison: diff }] = await Promise.all([api.assessmentRun(id), api.assessmentComparison(id)])
      if (signal?.aborted) return
      setRun(detail)
      setComparison(diff)
    }).catch(() => {
      if (!signal?.aborted) setLoadError(true)
    }).finally(() => {
      if (!signal?.aborted) setLoaded(true)
    })
  }, [selected, selectedRunId])
  usePoll(load, 3500, !!selected, `${selected?.id ?? ''}:${selectedRunId ?? ''}`)

  async function action(key: string, work: () => Promise<{ run: AssessmentRun }>, message: string) {
    setBusy(key)
    try { const result = await work(); setRun(result.run); toast.success(message); load() }
    catch (error) { toast.error(error instanceof Error ? error.message : 'Assessment action failed.') }
    finally { setBusy(null) }
  }

  async function createReport() {
    if (!run) return
    setBusy('report')
    try { await api.createAssessmentReport(run.id); toast.success(`Report snapshot linked to run #${run.id}.`); load() }
    catch (error) { toast.error(error instanceof Error ? error.message : 'Failed to create report.') }
    finally { setBusy(null) }
  }

  if (!selected) return <Empty>Select an engagement to inspect its assessment history.</Empty>

  return <div>
    <PageHeader title="Assessment runs" subtitle={`${selected.host} — durable target evidence, retries and run-to-run change tracking`} actions={<Button variant="primary" onClick={() => navigate('profiles', selected.id)}>Start a profile</Button>} />
    {!loaded ? <SkeletonList rows={7} /> : loadError ? <Empty>Unable to load assessment runs. The dashboard will retry automatically.</Empty> : runs.length === 0 ? <Empty>No assessment runs yet. Start a scan profile to create the first evidence trail.</Empty> : (
      <div className="grid gap-5 xl:grid-cols-[280px_minmax(0,1fr)]">
        <div className="space-y-2">{runs.map((item) => <button key={item.id} onClick={() => setSelectedRunId(item.id)} className={`w-full rounded-xl border p-3 text-left transition ${item.id === run?.id ? 'border-accent-500/50 bg-accent-500/10' : 'border-hair bg-ink-850 hover:border-hair-strong'}`}>
          <div className="flex items-center gap-2"><span className="min-w-0 flex-1 truncate text-sm font-medium text-zinc-100">{item.name}</span><Badge tone={statusTone(item.status)}>{item.status}</Badge></div>
          <p className="mt-1 text-xs text-zinc-500">Run #{item.id} · {item.profile} · {new Date(item.createdAt).toLocaleString()}</p>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink-950"><div className="h-full bg-accent-500" style={{ width: `${item.targetCoverage}%` }} /></div>
          <p className="mt-1 text-[11px] text-zinc-600">{item.completedTargetJobs}/{item.totalTargetJobs} targets executed</p>
        </button>)}</div>
        {run && <div className="min-w-0 space-y-5">
          <Card className="border-accent-500/25">
            <div className="flex flex-wrap items-start gap-3"><div className="min-w-0 flex-1"><div className="flex items-center gap-2">{ACTIVE.has(run.status) ? <Loader size={17} className="animate-spin text-amber-400" /> : run.status === 'completed' ? <CheckCircle2 size={17} className="text-emerald-400" /> : <AlertTriangle size={17} className="text-amber-400" />}<h2 className="font-semibold text-zinc-100">{run.name}</h2><Badge tone={statusTone(run.status)}>{run.status}</Badge></div><p className="mt-1 text-xs text-zinc-500">Run #{run.id} · {run.completedSteps}/{run.totalSteps} steps · {run.completedTargetJobs}/{run.totalTargetJobs} current attempts completed · {run.targetCoverage}% target coverage</p></div>
              <div className="flex flex-wrap gap-2">{ACTIVE.has(run.status) && <Button variant="danger" disabled={!!busy} onClick={() => action('cancel-run', () => api.cancelAssessmentRun(run.id), 'Assessment run cancelled.')}><Square size={13} /> Cancel run</Button>}{run.status === 'partial' && <Button variant="ghost" disabled={!!busy} onClick={() => action('retry-run', () => api.retryAssessmentRun(run.id), 'Problem steps queued for retry.')}><RotateCcw size={14} /> Retry problems</Button>}{['completed', 'partial'].includes(run.status) && <Button variant="primary" disabled={!!busy} onClick={createReport}><FileCheck2 size={14} /> {run.reportSnapshot ? 'Use run report' : 'Create run report'}</Button>}{run.reportSnapshot && <a href={api.reportPdfUrl(run.reportSnapshot.id)} className="inline-flex items-center gap-1.5 rounded-lg border border-hair px-3 py-1.5 text-sm text-zinc-300 hover:bg-ink-800"><Download size={14} /> PDF</a>}</div>
            </div>
          </Card>

          <Comparison comparison={comparison} />

          <div className="space-y-3">{run.steps.map((step) => <Card key={step.id} className="!p-0 overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-hair px-4 py-3"><span className="flex h-7 w-7 items-center justify-center rounded-lg bg-ink-950 text-zinc-400">{step.status === 'running' ? <Loader size={14} className="animate-spin" /> : <Target size={14} />}</span><div className="min-w-0 flex-1"><h3 className="text-sm font-medium text-zinc-100">Phase {step.phase + 1} · {step.label}</h3><p className="text-[11px] text-zinc-500">{step.evidence.completed}/{step.evidence.targets} current targets completed · {step.evidence.findingsProduced} findings · {step.evidence.highFindings} high-risk</p></div><Badge tone={statusTone(step.status)}>{step.status}</Badge></div>
            {step.error && <p className="border-b border-hair bg-amber-950/10 px-4 py-2 text-xs text-amber-300">{step.error}</p>}
            {step.jobs.length === 0 ? <p className="px-4 py-3 text-sm text-zinc-500">No concrete target attempts.</p> : <div className="divide-y divide-hair/60">{step.jobs.map((job) => <TargetAttempt key={job.id} job={job} busy={busy} onRetry={() => action(`retry-${job.id}`, () => api.retryAssessmentTarget(run.id, step.id, job.id), `Target ${job.target ?? selected.host} queued for retry.`)} onCancel={() => action(`cancel-${job.id}`, () => api.cancelAssessmentTarget(run.id, step.id, job.id), `Target ${job.target ?? selected.host} cancelled.`)} />)}</div>}
          </Card>)}</div>
        </div>}
      </div>
    )}
  </div>
}

function TargetAttempt({ job, busy, onRetry, onCancel }: { job: AssessmentStepJob; busy: string | null; onRetry: () => void; onCancel: () => void }) {
  return <div className={`flex flex-wrap items-center gap-3 px-4 py-3 ${job.current ? '' : 'opacity-55'}`}>
    <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="truncate font-mono text-xs text-zinc-200">{job.target ?? 'engagement-wide'}</span><Badge tone={statusTone(job.outcome)}>{job.outcome}</Badge><span className="text-[10px] text-zinc-600">attempt {job.attempt}{job.current ? ' · current' : ' · superseded'}</span></div><p className="mt-1 text-[11px] text-zinc-500">{job.reason ?? job.progress ?? (job.summary.join(' · ') || 'No execution warning')} · {job.findingsProduced} findings{job.highFindings ? ` · ${job.highFindings} high-risk` : ''}</p></div>
    {job.current && <div className="flex gap-2">{ACTIVE.has(job.outcome) && <Button variant="danger" disabled={!!busy} onClick={onCancel}><Square size={12} /> Cancel</Button>}{RETRYABLE.has(job.outcome) && <Button variant="ghost" disabled={!!busy} onClick={onRetry}><RotateCcw size={13} /> Retry target</Button>}</div>}
  </div>
}

function Comparison({ comparison }: { comparison: AssessmentComparison | null }) {
  if (!comparison) return null
  const sections: { key: keyof Pick<AssessmentComparison, 'new' | 'unchanged' | 'resolved' | 'regressed'>; label: string; tone: 'blue' | 'zinc' | 'green' | 'red' }[] = [
    { key: 'new', label: 'New', tone: 'blue' }, { key: 'unchanged', label: 'Unchanged', tone: 'zinc' }, { key: 'resolved', label: 'Resolved', tone: 'green' }, { key: 'regressed', label: 'Regressed', tone: 'red' },
  ]
  return <Card><div className="mb-3 flex items-center gap-2"><History size={15} className="text-violet-400" /><h2 className="text-sm font-semibold">Run comparison</h2><span className="text-xs text-zinc-500">{comparison.previousRunId ? `against run #${comparison.previousRunId}` : 'first run for this profile'}</span></div><div className="grid grid-cols-2 gap-2 sm:grid-cols-4">{sections.map((section) => <div key={section.key} className="rounded-lg border border-hair bg-ink-950/35 p-3"><div className="flex items-center justify-between"><span className="text-xs text-zinc-400">{section.label}</span><Badge tone={section.tone}>{comparison.counts[section.key]}</Badge></div><div className="mt-2 space-y-1">{comparison[section.key].slice(0, 3).map((item) => <FindingLine key={item.findingKey} item={item} />)}{comparison[section.key].length > 3 && <p className="text-[10px] text-zinc-600">+{comparison[section.key].length - 3} more</p>}</div></div>)}</div></Card>
}

function FindingLine({ item }: { item: AssessmentFindingSnapshot }) {
  return <div className="flex items-center gap-1.5"><ScoreBadge score={item.score} /><span className="min-w-0 flex-1 truncate text-[11px] text-zinc-400" title={`${item.title}${item.target ? ` · ${item.target}` : ''}`}>{item.title}</span></div>
}
