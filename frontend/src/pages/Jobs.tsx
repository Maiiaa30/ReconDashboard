import { Fragment, useCallback, useState } from 'react'
import { api, type Job } from '../api'
import { usePoll } from '../state'
import { Empty, JobStatusBadge, PageHeader } from '../components/ui'

function duration(job: Job): string {
  if (!job.startedAt || !job.finishedAt) return '—'
  const ms = new Date(job.finishedAt).getTime() - new Date(job.startedAt).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  return `${(ms / 1000).toFixed(1)}s`
}

function detail(job: Job): string {
  if (job.error) return job.error
  return JSON.stringify(job.result ?? null, null, 2)
}

export function Jobs() {
  const [jobs, setJobs] = useState<Job[]>([])
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  const load = useCallback(() => {
    api
      .jobs()
      .then((r) => setJobs(r.jobs))
      .catch(() => {})
  }, [])

  usePoll(load, 2500)

  function toggle(id: number) {
    setExpanded((cur) => {
      const next = new Set(cur)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div>
      <PageHeader title="Jobs" />

      {jobs.length === 0 ? (
        <Empty>No jobs yet. Enqueue a scan from the Scans, Subdomains or Exposure tabs.</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border border-zinc-800">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900/60 text-left text-xs text-zinc-500">
              <tr>
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2">Duration</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => {
                const open = expanded.has(j.id)
                return (
                  <Fragment key={j.id}>
                    <tr
                      onClick={() => toggle(j.id)}
                      className="cursor-pointer border-t border-zinc-800/60 hover:bg-zinc-900/40"
                    >
                      <td className="px-3 py-2 font-mono text-zinc-400">#{j.id}</td>
                      <td className="px-3 py-2 font-mono text-zinc-200">{j.type}</td>
                      <td className="px-3 py-2">
                        <JobStatusBadge status={j.status} />
                      </td>
                      <td className="px-3 py-2 text-zinc-500">
                        {new Date(j.createdAt).toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-zinc-500">{duration(j)}</td>
                    </tr>
                    {open && (
                      <tr className="border-t border-zinc-800/60 bg-zinc-950/40">
                        <td colSpan={5} className="px-3 py-2">
                          <pre
                            className={`whitespace-pre-wrap break-all max-h-96 overflow-auto text-xs ${
                              j.error ? 'text-red-300' : 'text-zinc-400'
                            }`}
                          >
                            {detail(j)}
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
