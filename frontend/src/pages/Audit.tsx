import { useEffect, useState } from 'react'
import { api, type AuditEntry } from '../api'
import { useApp } from '../state'
import { Badge, Empty, PageHeader } from '../components/ui'
import { timeAgo } from '../lib/format'

// Read-only view of the append-only audit ledger: every active action against a
// target, plus job start/finish, newest first. The record is legal cover for an
// authorized engagement ("who ran what, against whom, when, under which mode").
export function Audit() {
  const { domains } = useApp()
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [scope, setScope] = useState<'all' | number>('all')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api
      .audit({ domainId: scope === 'all' ? undefined : scope, limit: 500 })
      .then((r) => setEntries(r.entries))
      .finally(() => setLoading(false))
  }, [scope])

  const hostOf = (id: number | null) => domains.find((d) => d.id === id)?.host ?? (id == null ? '—' : `#${id}`)

  function actionTone(action: string): 'blue' | 'green' | 'red' | 'amber' | 'zinc' {
    if (action.startsWith('enqueue')) return 'blue'
    if (action === 'job:done') return 'green'
    if (action === 'job:error') return 'red'
    if (action === 'job:start') return 'amber'
    return 'zinc'
  }

  return (
    <div>
      <PageHeader
        title="Audit ledger"
        subtitle="Append-only record of active actions and job execution — legal cover for authorized testing"
        actions={
          <select
            value={String(scope)}
            onChange={(e) => setScope(e.target.value === 'all' ? 'all' : Number(e.target.value))}
            className="rounded-lg border border-hair bg-ink-850 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
          >
            <option value="all">All targets</option>
            {domains.map((d) => (
              <option key={d.id} value={d.id}>
                {d.host}
              </option>
            ))}
          </select>
        }
      />

      {loading ? (
        <Empty>Loading…</Empty>
      ) : entries.length === 0 ? (
        <Empty>No audit entries yet. Active scans and their execution will be recorded here.</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border border-hair">
          <table className="w-full text-sm">
            <thead className="bg-ink-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
              <tr>
                <th className="px-3 py-2 w-40">When</th>
                <th className="px-3 py-2 w-28">Actor</th>
                <th className="px-3 py-2 w-40">Action</th>
                <th className="px-3 py-2">Target</th>
                <th className="px-3 py-2 w-20">Mode</th>
                <th className="px-3 py-2 w-16">Job</th>
                <th className="px-3 py-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-t border-hair/60 align-top">
                  <td className="px-3 py-2 text-zinc-400" title={new Date(e.ts).toLocaleString()}>
                    {timeAgo(new Date(e.ts).getTime())}
                  </td>
                  <td className="px-3 py-2 text-zinc-300">{e.actor}</td>
                  <td className="px-3 py-2">
                    <Badge tone={actionTone(e.action)}>{e.action}</Badge>
                  </td>
                  <td className="px-3 py-2 text-zinc-300">
                    {e.target ?? <span className="text-zinc-600">—</span>}
                    {e.domainId != null && (
                      <span className="ml-1 text-xs text-zinc-600">({hostOf(e.domainId)})</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs text-zinc-500">{e.mode ?? '—'}</td>
                  <td className="px-3 py-2 text-xs text-zinc-500">{e.jobId ?? '—'}</td>
                  <td className="px-3 py-2 font-mono text-xs text-zinc-500 break-all">{e.detail ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
