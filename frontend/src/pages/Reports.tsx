import { useCallback, useEffect, useMemo, useState } from 'react'
import { Camera, Download, FileCheck2, FileText, Flag, ListChecks, Trash2, type LucideIcon } from 'lucide-react'
import { api, type Finding, type Methodology, type ReportSnapshot } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, ExportLinks, PageHeader, SkeletonList } from '../components/ui'
import { useToast } from '../components/Toast'

export function Reports({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const toast = useToast()
  const [snapshots, setSnapshots] = useState<ReportSnapshot[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [methodology, setMethodology] = useState<Methodology | null>(null)
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [loadError, setLoadError] = useState(false)

  useEffect(() => {
    setSnapshots([])
    setFindings([])
    setMethodology(null)
    setLoaded(false)
    setLoadError(false)
  }, [selected?.id])

  const load = useCallback((signal?: AbortSignal) => {
    if (!selected) return
    return Promise.all([api.snapshots(selected.id), api.findings({ domainId: selected.id, limit: 500 }), api.methodology(selected.id)])
      .then(([snapshotResult, findingResult, methodologyResult]) => {
        if (signal?.aborted) return
        setSnapshots(snapshotResult.snapshots)
        setFindings(findingResult.findings)
        setMethodology(methodologyResult)
        setLoadError(false)
      }).catch(() => {
        if (!signal?.aborted) setLoadError(true)
      }).finally(() => {
        if (!signal?.aborted) setLoaded(true)
      })
  }, [selected])
  usePoll(load, 10000, !!selected, selected?.id)

  const readiness = useMemo(() => {
    const reportable = findings.filter((finding) => !['false_positive', 'ignored'].includes(finding.status))
    const confirmed = reportable.filter((finding) => finding.status === 'confirmed')
    const draft = reportable.filter((finding) => finding.status === 'open')
    const withEvidence = confirmed.filter((finding) => Array.isArray(finding.data?.evidence) ? finding.data.evidence.length > 0 : Boolean(finding.data?.evidence))
    const skills = methodology?.skills.filter((skill) => skill.applicable) ?? []
    const coverage = skills.length ? Math.round(skills.reduce((sum, skill) => sum + skill.coverage, 0) / skills.length) : 0
    return { reportable, confirmed, draft, withEvidence, coverage }
  }, [findings, methodology])

  if (!selected) return <Empty>Select an engagement to manage its reports.</Empty>

  async function freeze() {
    if (!selected) return
    setBusy(true)
    try {
      await api.createSnapshot(selected.id, label.trim() || undefined)
      setLabel('')
      toast.success('Report snapshot frozen.')
      load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to create report snapshot.')
    } finally { setBusy(false) }
  }

  async function remove(id: number) {
    setBusy(true)
    try { await api.deleteSnapshot(id); toast.success('Snapshot deleted.'); load() }
    catch { toast.error('Failed to delete snapshot.') }
    finally { setBusy(false) }
  }

  return (
    <div>
      <PageHeader title="Reports" subtitle={`${selected.host} — live exports and immutable assessment deliverables`} actions={<ExportLinks path={`/domains/${selected.id}/report`} formats={['md', 'html']} />} />
      {!loaded ? <SkeletonList rows={6} /> : loadError ? <Empty>Unable to load report readiness. The dashboard will retry automatically.</Empty> : <>
        <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Readiness label="Reportable findings" value={readiness.reportable.length} detail={`${readiness.draft.length} draft`} icon={Flag} tone="text-amber-400" onClick={() => navigate('findings', selected.id)} />
          <Readiness label="Confirmed" value={readiness.confirmed.length} detail={`${readiness.withEvidence.length} with evidence`} icon={FileCheck2} tone="text-red-400" onClick={() => navigate('findings', selected.id)} />
          <Readiness label="Coverage" value={`${readiness.coverage}%`} detail="methodology" icon={ListChecks} tone="text-violet-400" onClick={() => navigate('methodology', selected.id)} />
          <Readiness label="Frozen versions" value={snapshots.length} detail="immutable" icon={Camera} tone="text-blue-400" onClick={() => {}} />
        </div>

        <Card className="mb-5 border-accent-500/20 bg-accent-500/5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="min-w-0 flex-1"><h2 className="text-sm font-semibold text-zinc-100">Freeze a deliverable</h2><p className="mt-1 text-sm text-zinc-400">A snapshot preserves the exact findings, evidence and methodology state at this moment.</p><input value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Optional label, e.g. Initial assessment or Retest 1" className="mt-3 block w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent-500" /></div>
            <Button variant="primary" onClick={freeze} disabled={busy}><Camera size={15} /> {busy ? 'Freezing…' : 'Create snapshot'}</Button>
          </div>
        </Card>

        <div className="mb-3 flex items-center gap-2"><FileText size={16} className="text-zinc-400" /><h2 className="text-sm font-semibold">Deliverable history</h2></div>
        {snapshots.length === 0 ? <Empty>No frozen report versions yet. Triage findings, attach evidence, then create the first snapshot.</Empty> : <div className="space-y-3">{snapshots.map((snapshot, index) => (
          <Card key={snapshot.id} className="!p-4">
            <div className="flex flex-wrap items-center gap-3"><span className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-950/40 text-blue-400"><FileCheck2 size={17} /></span><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="font-medium text-zinc-100">{snapshot.label || `Report snapshot ${snapshots.length - index}`}</span>{index === 0 && <Badge tone="green">latest</Badge>}{snapshot.assessmentRunId && <Badge tone="indigo">run #{snapshot.assessmentRunId}</Badge>}</div><p className="text-xs text-zinc-500">{new Date(snapshot.createdAt).toLocaleString()}{snapshot.meta ? ` · ${snapshot.meta.findings} findings · ${snapshot.meta.high} high · ${snapshot.meta.cves} CVEs` : ''}</p></div><div className="flex items-center gap-1.5">{snapshot.assessmentRunId && <button onClick={() => navigate('runs', selected.id)} className="rounded-lg border border-hair px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-ink-800">Run</button>}<a href={api.reportPdfUrl(snapshot.id)} className="inline-flex items-center gap-1.5 rounded-lg border border-accent-500/40 bg-accent-500/10 px-2.5 py-1.5 text-xs text-accent-fg hover:bg-accent-500/20"><Download size={13} /> PDF</a><a href={api.snapshotUrl(snapshot.id, 'html')} className="rounded-lg border border-hair px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-ink-800">HTML</a><a href={api.snapshotUrl(snapshot.id, 'md')} className="rounded-lg border border-hair px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-ink-800">MD</a><button onClick={() => remove(snapshot.id)} disabled={busy} className="rounded-lg border border-hair p-1.5 text-zinc-600 hover:border-red-900 hover:text-red-400" title="Delete snapshot"><Trash2 size={14} /></button></div></div>
          </Card>
        ))}</div>}
      </>}
    </div>
  )
}

function Readiness({ label, value, detail, icon: Icon, tone, onClick }: { label: string; value: number | string; detail: string; icon: LucideIcon; tone: string; onClick: () => void }) {
  return <button onClick={onClick} className="rounded-xl border border-hair bg-ink-850 p-3 text-left transition hover:border-hair-strong"><div className="flex items-center justify-between"><span className="text-xs text-zinc-500">{label}</span><Icon size={15} className={tone} /></div><div className="mt-1 text-2xl font-semibold text-zinc-100">{value}</div><div className="text-[11px] text-zinc-600">{detail}</div></button>
}
