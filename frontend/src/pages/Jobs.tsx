import { Fragment, useCallback, useState, type MouseEvent } from 'react'
import { api, type Job } from '../api'
import { usePoll } from '../state'
import { Badge, Button, Empty, JobStatusBadge, PageHeader } from '../components/ui'
import { summarizeJob, timeAgo } from '../lib/format'

const STATUSES = ['all', 'queued', 'running', 'done', 'error', 'cancelled'] as const
type StatusFilter = (typeof STATUSES)[number]

function duration(job: Job): string {
  if (!job.startedAt) return '—'
  const end = job.finishedAt ? new Date(job.finishedAt).getTime() : Date.now()
  const ms = end - new Date(job.startedAt).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
}

export function Jobs() {
  const [jobs, setJobs] = useState<Job[]>([])
  const [filter, setFilter] = useState<StatusFilter>('all')
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [cancelling, setCancelling] = useState<number | null>(null)

  const load = useCallback(() => {
    api.jobs().then((r) => setJobs(r.jobs)).catch(() => {})
  }, [])
  usePoll(load, 2500)

  async function cancel(id: number, e: MouseEvent) {
    e.stopPropagation() // don't toggle the row's detail panel
    setCancelling(id)
    try {
      await api.cancelJob(id)
    } catch {
      // The worker may have just claimed it; the reload reflects the real state.
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

  const counts = {
    queued: jobs.filter((j) => j.status === 'queued').length,
    running: jobs.filter((j) => j.status === 'running').length,
    done: jobs.filter((j) => j.status === 'done').length,
    error: jobs.filter((j) => j.status === 'error').length,
  }
  const shown = filter === 'all' ? jobs : jobs.filter((j) => j.status === filter)

  return (
    <div>
      <PageHeader
        title="Activity log"
        subtitle="Every background job — discovery, scans, OSINT — newest first"
        actions={
          <div className="flex flex-wrap items-center gap-1.5">
            {counts.running > 0 && <Badge tone="amber">{counts.running} running</Badge>}
            {counts.queued > 0 && <Badge>{counts.queued} queued</Badge>}
            <Badge tone="green">{counts.done} done</Badge>
            {counts.error > 0 && <Badge tone="red">{counts.error} error</Badge>}
          </div>
        }
      />

      <div className="mb-3 flex flex-wrap gap-1.5">
        {STATUSES.map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`rounded-lg px-2.5 py-1 text-xs capitalize ${
              filter === s ? 'bg-zinc-200 text-zinc-900' : 'border border-hair text-zinc-400 hover:bg-ink-800'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {shown.length === 0 ? (
        <Empty>No jobs{filter !== 'all' ? ` with status “${filter}”` : ' yet'}.</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border border-hair">
          <table className="w-full text-sm">
            <thead className="bg-ink-900/60 text-left text-xs text-zinc-500">
              <tr>
                <th className="px-3 py-2 w-12">#</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Result</th>
                <th className="px-3 py-2">When</th>
                <th className="px-3 py-2 w-24">Duration</th>
                <th className="px-3 py-2 w-20"></th>
              </tr>
            </thead>
            <tbody>
              {shown.map((j) => {
                const open = expanded.has(j.id)
                const detailObj = j.status === 'error' ? j.error : j.result
                return (
                  <Fragment key={j.id}>
                    <tr
                      onClick={() => toggle(j.id)}
                      className="cursor-pointer border-t border-hair/60 hover:bg-ink-850/60"
                    >
                      <td className="px-3 py-2 font-mono text-zinc-500">{j.id}</td>
                      <td className="px-3 py-2 font-mono text-xs text-zinc-300">{j.type}</td>
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
                        <td colSpan={7} className="px-3 py-3">
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
