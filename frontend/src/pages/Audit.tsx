import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, type AuditEntry, type AuditSummary } from '../api'
import { useApp } from '../state'
import { Badge, Empty, PageHeader } from '../components/ui'
import { timeAgo } from '../lib/format'

// Server-side page size for keyset pagination; "Load more" fetches the next page.
const PAGE_SIZE = 100

// Read-only view of the append-only audit ledger: every active action against a
// target, plus job start/finish, newest first. The record is legal cover for an
// authorized engagement ("who ran what, against whom, when, under which mode").
// Filtering and paging are done server-side (keyset cursor over the primary key)
// so a long-running engagement's ledger never truncates in the browser.
export function Audit() {
  const { domains } = useApp()
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [scope, setScope] = useState<'all' | number>('all')
  const [action, setAction] = useState('')
  const [target, setTarget] = useState('')
  const [summary, setSummary] = useState<AuditSummary | null>(null)
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const cursorRef = useRef<string | null>(null)
  cursorRef.current = nextCursor

  const query = useMemo(
    () => ({
      domainId: scope === 'all' ? undefined : scope,
      action: action || undefined,
      target: target.trim() || undefined,
    }),
    [scope, action, target],
  )

  // Reload the first page for the current filter set.
  const load = useCallback(() => {
    setLoading(true)
    api
      .audit({ ...query, limit: PAGE_SIZE })
      .then((r) => {
        setEntries(r.entries)
        setNextCursor(r.nextCursor)
      })
      .finally(() => setLoading(false))
  }, [query])

  // Append the next page using the cursor from the last response.
  const loadMore = useCallback(() => {
    const cursor = cursorRef.current
    if (!cursor || loadingMore) return
    setLoadingMore(true)
    api
      .audit({ ...query, limit: PAGE_SIZE, cursor })
      .then((r) => {
        setEntries((prev) => [...prev, ...r.entries])
        setNextCursor(r.nextCursor)
      })
      .finally(() => setLoadingMore(false))
  }, [query, loadingMore])

  // Per-action counts + total, independent of the action filter so the dropdown
  // shows how many entries sit behind each action.
  const loadSummary = useCallback(() => {
    api
      .auditSummary({ domainId: query.domainId, target: query.target })
      .then(setSummary)
      .catch(() => setSummary(null))
  }, [query.domainId, query.target])

  // Debounced so typing in the target box doesn't fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => load(), 200)
    return () => clearTimeout(t)
  }, [load])

  useEffect(() => {
    const t = setTimeout(() => loadSummary(), 200)
    return () => clearTimeout(t)
  }, [loadSummary])

  const hostOf = (id: number | null) => domains.find((d) => d.id === id)?.host ?? (id == null ? '—' : `#${id}`)

  function actionTone(a: string): 'blue' | 'green' | 'red' | 'amber' | 'zinc' {
    if (a.startsWith('enqueue')) return 'blue'
    if (a === 'job:done') return 'green'
    if (a === 'job:error') return 'red'
    if (a === 'job:start') return 'amber'
    return 'zinc'
  }

  // Actions to offer in the filter, sorted by frequency (most-used first) so the
  // common ones are easiest to reach.
  const actionOptions = useMemo(
    () => (summary ? Object.entries(summary.byAction).sort((a, b) => b[1] - a[1]) : []),
    [summary],
  )

  const inputCls =
    'rounded-lg border border-hair bg-ink-850 px-3 py-1.5 text-sm outline-none focus:border-accent-500'

  return (
    <div>
      <PageHeader
        title="Audit ledger"
        subtitle="Append-only record of active actions and job execution — legal cover for authorized testing"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={String(scope)}
              onChange={(e) => setScope(e.target.value === 'all' ? 'all' : Number(e.target.value))}
              className={inputCls}
            >
              <option value="all">All targets</option>
              {domains.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.host}
                </option>
              ))}
            </select>
            <select value={action} onChange={(e) => setAction(e.target.value)} className={inputCls}>
              <option value="">All actions{summary ? ` (${summary.total})` : ''}</option>
              {actionOptions.map(([a, n]) => (
                <option key={a} value={a}>
                  {a} ({n})
                </option>
              ))}
            </select>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Filter target…"
              className={`${inputCls} w-44`}
            />
          </div>
        }
      />

      {loading ? (
        <Empty>Loading…</Empty>
      ) : entries.length === 0 ? (
        <Empty>
          {action || target ? 'No audit entries match this filter.' : 'No audit entries yet. Active scans and their execution will be recorded here.'}
        </Empty>
      ) : (
        <>
          <div className="mb-2 text-xs text-zinc-500">
            {entries.length}
            {summary && summary.total > entries.length ? ` of ${summary.total}` : ''} shown
          </div>
          <div className="overflow-x-auto rounded-xl border border-hair">
            <table className="w-full min-w-[720px] text-sm">
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
          {nextCursor && (
            <div className="mt-3 flex justify-center">
              <button
                onClick={loadMore}
                disabled={loadingMore}
                className="rounded-lg border border-hair px-4 py-1.5 text-sm text-zinc-300 transition hover:border-hair-strong hover:bg-ink-800 disabled:opacity-50"
              >
                {loadingMore ? 'Loading…' : `Load more${summary ? ` (${summary.total - entries.length} more)` : ''}`}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
