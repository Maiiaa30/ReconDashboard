import { Fragment, useCallback, useState, type MouseEvent, type ReactNode } from 'react'
import {
  Network, Radar, Eye, ScanSearch, ShieldCheck, ShieldAlert, Crosshair, Camera, Wrench,
  Activity, ListChecks, Loader, CheckCircle2, XCircle, Clock, Webhook, type LucideIcon,
} from 'lucide-react'
import { api, type Job } from '../api'
import { useApp, usePoll } from '../state'
import { useAppEvent } from '../lib/events'
import { Button, Empty, JobStatusBadge, PageHeader } from '../components/ui'
import { summarizeJob, timeAgo } from '../lib/format'

const STATUSES = ['all', 'queued', 'running', 'done', 'error', 'dead', 'cancelled'] as const
type StatusFilter = (typeof STATUSES)[number]

// Friendly label + icon per job type.
const JOB_META: Record<string, { label: string; icon: LucideIcon }> = {
  subdomain_discovery: { label: 'Discovery', icon: Network },
  exposure_scan: { label: 'Exposure', icon: Radar },
  osint_gather: { label: 'OSINT', icon: Eye },
  nmap_scan: { label: 'nmap', icon: ScanSearch },
  nuclei_scan: { label: 'nuclei', icon: ShieldCheck },
  ffuf_scan: { label: 'ffuf', icon: Crosshair },
  screenshot: { label: 'Screenshots', icon: Camera },
  origin_scan: { label: 'WAF / Origin', icon: ShieldAlert },
  owasp_active: { label: 'OWASP checks', icon: ShieldCheck },
  tool_scan: { label: 'Tool', icon: Wrench },
  api_discovery: { label: 'API discovery', icon: Webhook },
  code_leak: { label: 'Code leaks', icon: Eye },
}
const jobMeta = (type: string) => JOB_META[type] ?? { label: type, icon: Activity }

// Row label for a job. Tool scans append which tool ran (e.g. "Tool | sqlmap")
// so the log isn't a wall of identical "Tool" rows.
function jobLabel(j: Job): string {
  const base = jobMeta(j.type).label
  if (j.type === 'tool_scan') {
    const p = (j.params ?? {}) as Record<string, unknown>
    if (typeof p.tool === 'string' && p.tool) return `${base} | ${p.tool}`
  }
  return base
}

function duration(job: Job): string {
  if (!job.startedAt) return '—'
  const end = job.finishedAt ? new Date(job.finishedAt).getTime() : Date.now()
  const ms = end - new Date(job.startedAt).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
}

// Absolute + relative timestamp for the detail panel ("14:32:09 · 3m ago").
function fmtTime(iso: string | null): string {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  if (!Number.isFinite(t)) return '—'
  return `${new Date(t).toLocaleString()} · ${timeAgo(t)}`
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 text-zinc-500">{label}</span>
      <span className="min-w-0 flex-1 break-all text-zinc-300">{children}</span>
    </div>
  )
}

function Block({ label, body, tone = 'zinc' }: { label: string; body: string; tone?: 'zinc' | 'red' }) {
  return (
    <div>
      <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">{label}</div>
      <pre
        className={`max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-hair bg-ink-950/70 p-2.5 text-xs ${
          tone === 'red' ? 'text-red-300' : 'text-zinc-400'
        }`}
      >
        {body}
      </pre>
    </div>
  )
}

// Expanded per-job detail: timing, target + effective invocation, params, and
// the result or error payload. Everything the operator needs to understand what
// a scan actually did without leaving the log.
function JobDetail({
  job, target, host, queueLabel,
}: { job: Job; target: string; host: string | null; queueLabel: string | null }) {
  const asText = (v: unknown): string =>
    v == null ? '(none)' : typeof v === 'string' ? v : JSON.stringify(v, null, 2)
  const outcome = job.status === 'done' ? summarizeJob(job.type, job.result) : null
  return (
    <div className="grid gap-4 text-xs md:grid-cols-2">
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <DetailRow label="Job">{jobLabel(job)} <span className="text-zinc-600">· {job.type}</span></DetailRow>
          <DetailRow label="Target">{target}</DetailRow>
          {host && <DetailRow label="Domain">{host}</DetailRow>}
          <DetailRow label="Status">{job.status}{queueLabel ? ` · ${queueLabel}` : ''}</DetailRow>
          {outcome && <DetailRow label="Outcome">{outcome}</DetailRow>}
        </div>
        <div className="flex flex-col gap-1">
          <DetailRow label="Created">{fmtTime(job.createdAt)}</DetailRow>
          <DetailRow label="Started">{fmtTime(job.startedAt)}</DetailRow>
          <DetailRow label="Finished">{fmtTime(job.finishedAt)}</DetailRow>
          <DetailRow label="Duration">{duration(job)}</DetailRow>
          {job.progress && <DetailRow label="Progress">{job.progress}</DetailRow>}
        </div>
        <Block label="Parameters / command" body={asText(job.params)} />
      </div>
      <div className="flex flex-col gap-3">
        {job.error && <Block label="Error" body={job.error} tone="red" />}
        {job.result != null && <Block label="Result" body={asText(job.result)} />}
        {!job.error && job.result == null && (
          <div className="text-zinc-600">No result payload{job.status === 'running' ? ' yet — job is running.' : '.'}</div>
        )}
      </div>
    </div>
  )
}

function Kpi({ icon: Icon, tone, label, value }: { icon: LucideIcon; tone: string; label: string; value: number }) {
  const chip: Record<string, string> = {
    zinc: 'bg-ink-700 text-zinc-300',
    amber: 'bg-amber-500/15 text-amber-400',
    blue: 'bg-blue-500/15 text-blue-400',
    green: 'bg-green-500/15 text-green-400',
    red: 'bg-red-500/15 text-red-400',
  }
  return (
    <div className="rounded-xl border border-hair bg-ink-850 p-3 shadow-card">
      <div className="mb-2 flex items-center gap-2">
        <span className={`flex h-6 w-6 items-center justify-center rounded-md ${chip[tone]}`}>
          <Icon size={14} />
        </span>
        <span className="text-xs text-zinc-400">{label}</span>
      </div>
      <div className="text-2xl font-semibold leading-none text-zinc-50">{value}</div>
    </div>
  )
}

export function Jobs() {
  const { domains } = useApp()
  const [jobs, setJobs] = useState<Job[]>([])
  const [loadError, setLoadError] = useState(false)
  const [filter, setFilter] = useState<StatusFilter>('all')
  const [typeFilter, setTypeFilter] = useState('')
  const [domainFilter, setDomainFilter] = useState<number | 'all'>('all')
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [cancelling, setCancelling] = useState<number | null>(null)

  const load = useCallback(() => {
    api.jobs().then((r) => { setJobs(r.jobs); setLoadError(false) }).catch(() => setLoadError(true))
  }, [])
  usePoll(load, 2500)
  // Live refresh on any job change (queue/status/progress); poll is the fallback.
  useAppEvent('jobs', load)

  async function cancel(id: number, e: MouseEvent) {
    e.stopPropagation()
    setCancelling(id)
    try {
      await api.cancelJob(id)
    } catch {
      /* worker may have claimed it; reload reflects reality */
    } finally {
      setCancelling(null)
      load()
    }
  }

  function toggle(id: number) {
    setExpanded((cur) => {
      const next = new Set(cur)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function jobTarget(j: Job): string {
    const p = (j.params ?? {}) as Record<string, unknown>
    if (typeof p.target === 'string' && p.target) return p.target
    const tool = typeof p.tool === 'string' ? p.tool : ''
    if (typeof p.domainId === 'number') {
      const host = domains.find((d) => d.id === p.domainId)?.host ?? `#${p.domainId}`
      return tool ? `${host} · ${tool}` : host
    }
    return tool || '—'
  }

  const counts = {
    total: jobs.length,
    queued: jobs.filter((j) => j.status === 'queued').length,
    running: jobs.filter((j) => j.status === 'running').length,
    done: jobs.filter((j) => j.status === 'done').length,
    error: jobs.filter((j) => j.status === 'error').length,
  }
  const jobDomainId = (j: Job): number | null => {
    const p = (j.params ?? {}) as Record<string, unknown>
    return typeof p.domainId === 'number' ? p.domainId : null
  }
  const types = [...new Set(jobs.map((j) => j.type))].sort()
  const shown = jobs.filter(
    (j) =>
      (filter === 'all' || j.status === filter) &&
      (!typeFilter || j.type === typeFilter) &&
      (domainFilter === 'all' || jobDomainId(j) === domainFilter),
  )

  // Queue position: the worker claims queued jobs oldest-id first.
  const queuePos = new Map<number, number>()
  jobs
    .filter((j) => j.status === 'queued')
    .sort((a, b) => a.id - b.id)
    .forEach((j, i) => queuePos.set(j.id, i + 1))
  // A deep nmap scan sweeps all 65k ports and emits no progress heartbeat while
  // it runs, so it legitimately sits idle for many minutes — never flag it.
  const isDeepNmap = (j: Job) =>
    j.type === 'nmap_scan' && !!j.params && typeof j.params === 'object' && (j.params as { deep?: unknown }).deep === true
  // A running job whose updatedAt hasn't moved in a while may be wedged.
  const isStale = (j: Job) =>
    !isDeepNmap(j) && j.status === 'running' && !!j.updatedAt && Date.now() - new Date(j.updatedAt).getTime() > 180_000

  return (
    <div>
      <PageHeader
        title="Activity log"
        subtitle="Every background job — discovery, scans, tools, OSINT — newest first"
        actions={
          <span className="flex items-center gap-1.5 text-xs text-zinc-500">
            <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-green-500" />
            live
          </span>
        }
      />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Kpi icon={ListChecks} tone="zinc" label="Total" value={counts.total} />
        <Kpi icon={Loader} tone="amber" label="Running" value={counts.running} />
        <Kpi icon={Clock} tone="blue" label="Queued" value={counts.queued} />
        <Kpi icon={CheckCircle2} tone="green" label="Done" value={counts.done} />
        <Kpi icon={XCircle} tone="red" label="Error" value={counts.error} />
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        {STATUSES.map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`rounded-lg px-2.5 py-1 text-xs capitalize transition ${
              filter === s ? 'bg-accent-500/20 text-accent-fg ring-1 ring-accent-500/30' : 'border border-hair text-zinc-400 hover:bg-ink-800'
            }`}
          >
            {s}
          </button>
        ))}
        <select
          aria-label="Filter by domain"
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value === 'all' ? 'all' : Number(e.target.value))}
          className="ml-auto rounded-lg border border-hair bg-ink-950 px-2.5 py-1 text-xs text-zinc-300 outline-none focus:border-accent-500"
        >
          <option value="all">All domains</option>
          {domains.map((d) => (
            <option key={d.id} value={d.id}>
              {d.host}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by job type"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded-lg border border-hair bg-ink-950 px-2.5 py-1 text-xs text-zinc-300 outline-none focus:border-accent-500"
        >
          <option value="">All types</option>
          {types.map((t) => (
            <option key={t} value={t}>
              {jobMeta(t).label}
            </option>
          ))}
        </select>
      </div>

      {loadError && jobs.length === 0 ? (
        <Empty>Couldn’t load the activity log — will retry.</Empty>
      ) : shown.length === 0 ? (
        <Empty>No jobs{filter !== 'all' || typeFilter || domainFilter !== 'all' ? ' match these filters' : ' yet'}.</Empty>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-hair">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="bg-ink-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
              <tr>
                <th scope="col" className="px-3 py-2 w-12">#</th>
                <th scope="col" className="px-3 py-2">Job</th>
                <th scope="col" className="px-3 py-2">Target</th>
                <th scope="col" className="px-3 py-2 w-24">Status</th>
                <th scope="col" className="px-3 py-2">Result</th>
                <th scope="col" className="px-3 py-2 w-20">Age</th>
                <th scope="col" className="px-3 py-2 w-24">Duration</th>
                <th scope="col" className="px-3 py-2 w-20"></th>
              </tr>
            </thead>
            <tbody>
              {shown.map((j) => {
                const open = expanded.has(j.id)
                const meta = jobMeta(j.type)
                const Icon = meta.icon
                const running = j.status === 'running'
                return (
                  <Fragment key={j.id}>
                    <tr
                      onClick={() => toggle(j.id)}
                      className={`cursor-pointer border-t border-hair/60 hover:bg-ink-850/60 ${running ? 'bg-amber-500/5' : ''}`}
                    >
                      <td className="px-3 py-2 font-mono text-zinc-500">{j.id}</td>
                      <td className="px-3 py-2">
                        <span className="flex items-center gap-2 text-zinc-200">
                          <Icon size={15} className={running ? 'animate-pulse text-amber-400' : 'text-zinc-500'} />
                          {jobLabel(j)}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-zinc-400 break-all">{jobTarget(j)}</td>
                      <td className="px-3 py-2"><JobStatusBadge status={j.status} /></td>
                      <td className="px-3 py-2 text-zinc-400">
                        {j.status === 'error' ? (
                          <span className="text-red-400">{j.error?.slice(0, 80)}</span>
                        ) : j.status === 'running' ? (
                          <span className="flex items-center gap-2">
                            <span className="text-amber-300">{j.progress || 'running…'}</span>
                            {isStale(j) && <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] text-red-300">possibly stuck</span>}
                          </span>
                        ) : j.status === 'queued' ? (
                          <span className="text-blue-300">#{queuePos.get(j.id) ?? '?'} in queue</span>
                        ) : (
                          summarizeJob(j.type, j.result)
                        )}
                      </td>
                      <td className="px-3 py-2 text-zinc-500">{timeAgo(new Date(j.createdAt).getTime())}</td>
                      <td className="px-3 py-2 text-zinc-500">{duration(j)}</td>
                      <td className="px-3 py-2">
                        {(j.status === 'queued' || j.status === 'running') && (
                          <Button
                            variant="danger"
                            className="px-2 py-1 text-xs"
                            disabled={cancelling === j.id}
                            onClick={(e) => cancel(j.id, e)}
                          >
                            {cancelling === j.id ? '…' : 'Cancel'}
                          </Button>
                        )}
                      </td>
                    </tr>
                    {open && (
                      <tr className="border-t border-hair/60 bg-ink-950/60">
                        <td colSpan={8} className="px-3 py-3">
                          <JobDetail
                            job={j}
                            target={jobTarget(j)}
                            host={jobDomainId(j) != null ? domains.find((d) => d.id === jobDomainId(j))?.host ?? null : null}
                            queueLabel={j.status === 'queued' ? `#${queuePos.get(j.id) ?? '?'} in queue` : null}
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
