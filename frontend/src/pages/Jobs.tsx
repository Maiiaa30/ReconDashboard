import { Fragment, useCallback, useState, type MouseEvent } from 'react'
import {
  Network, Radar, Eye, ScanSearch, ShieldCheck, ShieldAlert, Crosshair, Camera, Wrench,
  Activity, ListChecks, Loader, CheckCircle2, XCircle, Clock, type LucideIcon,
} from 'lucide-react'
import { api, type Job } from '../api'
import { useApp, usePoll } from '../state'
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
}
const jobMeta = (type: string) => JOB_META[type] ?? { label: type, icon: Activity }

function duration(job: Job): string {
  if (!job.startedAt) return '—'
  const end = job.finishedAt ? new Date(job.finishedAt).getTime() : Date.now()
  const ms = end - new Date(job.startedAt).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
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
  const [filter, setFilter] = useState<StatusFilter>('all')
  const [typeFilter, setTypeFilter] = useState('')
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [cancelling, setCancelling] = useState<number | null>(null)

  const load = useCallback(() => {
    api.jobs().then((r) => setJobs(r.jobs)).catch(() => {})
  }, [])
  usePoll(load, 2500)

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
      next.has(id) ? next.delete(id) : next.add(id)
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
  const types = [...new Set(jobs.map((j) => j.type))].sort()
  const shown = jobs.filter(
    (j) => (filter === 'all' || j.status === filter) && (!typeFilter || j.type === typeFilter),
  )

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
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="ml-auto rounded-lg border border-hair bg-ink-950 px-2.5 py-1 text-xs text-zinc-300 outline-none focus:border-accent-500"
        >
          <option value="">All types</option>
          {types.map((t) => (
            <option key={t} value={t}>
              {jobMeta(t).label}
            </option>
          ))}
        </select>
      </div>

      {shown.length === 0 ? (
        <Empty>No jobs{filter !== 'all' || typeFilter ? ' match these filters' : ' yet'}.</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border border-hair">
          <table className="w-full text-sm">
            <thead className="bg-ink-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
              <tr>
                <th className="px-3 py-2 w-12">#</th>
                <th className="px-3 py-2">Job</th>
                <th className="px-3 py-2">Target</th>
                <th className="px-3 py-2 w-24">Status</th>
                <th className="px-3 py-2">Result</th>
                <th className="px-3 py-2 w-20">Age</th>
                <th className="px-3 py-2 w-24">Duration</th>
                <th className="px-3 py-2 w-20"></th>
              </tr>
            </thead>
            <tbody>
              {shown.map((j) => {
                const open = expanded.has(j.id)
                const detailObj = j.status === 'error' ? j.error : j.result
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
                          {meta.label}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-zinc-400 break-all">{jobTarget(j)}</td>
                      <td className="px-3 py-2"><JobStatusBadge status={j.status} /></td>
                      <td className="px-3 py-2 text-zinc-400">
                        {j.status === 'error' ? (
                          <span className="text-red-400">{j.error?.slice(0, 80)}</span>
                        ) : (
                          summarizeJob(j.type, j.result)
                        )}
                      </td>
                      <td className="px-3 py-2 text-zinc-500">{timeAgo(new Date(j.createdAt).getTime())}</td>
                      <td className="px-3 py-2 text-zinc-500">{duration(j)}</td>
                      <td className="px-3 py-2">
                        {j.status === 'queued' && (
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
                          <pre
                            className={`max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs ${
                              j.error ? 'text-red-300' : 'text-zinc-400'
                            }`}
                          >
                            {detailObj ? (typeof detailObj === 'string' ? detailObj : JSON.stringify(detailObj, null, 2)) : '(no detail)'}
                          </pre>
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
