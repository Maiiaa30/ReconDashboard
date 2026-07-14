import { useCallback, useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronUp, ChevronsUpDown } from 'lucide-react'
import { api, ApiError, type Finding, type MetaStatus } from '../api'
import { useApp, useHosts, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { useConfirm } from '../components/Confirm'
import { timeAgo } from '../lib/format'
import { safeHttpUrl } from '../lib/url'

function statusTone(status: number): 'green' | 'amber' | 'red' | 'blue' | 'zinc' {
  if (status >= 200 && status < 300) return 'green'
  if (status >= 300 && status < 400) return 'blue'
  if (status === 401 || status === 403) return 'amber'
  if (status >= 500) return 'red'
  return 'zinc'
}

type SortKey = 'status' | 'url' | 'length' | 'words' | 'found'

// Numeric columns default to descending (biggest first); URL defaults ascending.
function defaultDir(k: SortKey): 'asc' | 'desc' {
  return k === 'url' ? 'asc' : 'desc'
}

function sortValue(h: Finding, k: SortKey): number | string {
  switch (k) {
    case 'status':
      return Number(h.data?.status)
    case 'length':
      return Number(h.data?.length)
    case 'words':
      return Number(h.data?.words)
    case 'found':
      return new Date(h.createdAt).getTime()
    case 'url':
      return String(h.data?.url ?? '')
  }
}

function SortTh({
  label,
  k,
  sortKey,
  sortDir,
  onSort,
  className = '',
}: {
  label: string
  k: SortKey
  sortKey: SortKey
  sortDir: 'asc' | 'desc'
  onSort: (k: SortKey) => void
  className?: string
}) {
  const activeCol = sortKey === k
  const Icon = !activeCol ? ChevronsUpDown : sortDir === 'asc' ? ChevronUp : ChevronDown
  return (
    <th className={`px-3 py-2 ${className}`}>
      <button
        type="button"
        onClick={() => onSort(k)}
        className={`inline-flex items-center gap-1 font-medium uppercase tracking-wide transition hover:text-zinc-300 ${
          activeCol ? 'text-accent-fg' : 'text-zinc-500'
        }`}
      >
        {label}
        <Icon size={13} className={activeCol ? 'text-accent-400' : 'text-zinc-600'} />
      </button>
    </th>
  )
}

export function Fuzzing() {
  const { selected } = useApp()
  const ask = useConfirm()
  const hosts = useHosts(selected)
  const [hits, setHits] = useState<Finding[]>([])
  const [meta, setMeta] = useState<MetaStatus | null>(null)
  const [target, setTarget] = useState('')
  const [path, setPath] = useState('FUZZ')
  const [scheme, setScheme] = useState<'https' | 'http'>('https')
  const [wordlist, setWordlist] = useState('')
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [running, setRunning] = useState(false)
  const [sortKey, setSortKey] = useState<SortKey>('found')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  useEffect(() => {
    api.meta().then(setMeta).catch(() => setMeta(null))
  }, [])

  // Default the target to the apex when the domain changes.
  useEffect(() => {
    setTarget(selected?.host ?? '')
  }, [selected])

  const load = useCallback(() => {
    if (!selected) return
    api
      .findings({ domainId: selected.id, type: 'ffuf', limit: 1000 })
      .then((r) => setHits(r.findings))
      .catch(() => {})
  }, [selected])
  usePoll(load, 4000, !!selected)

  function toggleSort(k: SortKey) {
    if (k === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortKey(k)
      setSortDir(defaultDir(k))
    }
  }

  const sortedHits = useMemo(() => {
    const arr = [...hits]
    arr.sort((a, b) => {
      const va = sortValue(a, sortKey)
      const vb = sortValue(b, sortKey)
      let cmp: number
      if (typeof va === 'string' || typeof vb === 'string') {
        cmp = String(va).localeCompare(String(vb))
      } else {
        // Missing/NaN numbers sink to the bottom regardless of direction.
        const na = Number.isFinite(va) ? va : -Infinity
        const nb = Number.isFinite(vb) ? vb : -Infinity
        cmp = na - nb
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
    return arr
  }, [hits, sortKey, sortDir])

  if (!selected) return <Empty>Select a domain to view fuzzing results.</Empty>

  const active = selected.mode === 'active_authorized'
  const toolMissing = meta ? !meta.tools.ffuf : false
  const pathValid = path.includes('FUZZ')

  async function run() {
    if (!selected) return
    // Passive domain: warn, then run with explicit confirmation.
    if (!active) {
      const ok = await ask({
        title: 'Run a loud scan?',
        message: `${selected.host} is passive_only.\n\nffuf is a LOUD, active scan. Only run it against ${target} if you are authorized to actively test this target.`,
        confirmLabel: 'Run anyway',
        tone: 'danger',
      })
      if (!ok) return
    }
    setMsg(null)
    setRunning(true)
    try {
      const { jobId } = await api.ffuf(selected.id, {
        target,
        path: path || 'FUZZ',
        wordlist: wordlist || undefined,
        scheme,
        confirm: !active,
      })
      setMsg({ ok: true, text: `Queued ffuf job #${jobId} on ${target} — results appear below as they complete.` })
    } catch (err) {
      setMsg({ ok: false, text: err instanceof ApiError ? err.message : 'failed to start ffuf' })
    } finally {
      setRunning(false)
    }
  }

  // Send a 401/403 hit to the 403-bypass tool, targeting its exact path.
  async function sendToBypass(h: Finding) {
    if (!selected) return
    let host = selected.host
    let hitPath = '/'
    let sch: 'https' | 'http' = scheme
    try {
      const u = new URL(String(h.data?.url ?? ''))
      host = u.hostname
      hitPath = u.pathname + u.search
      sch = u.protocol === 'http:' ? 'http' : 'https'
    } catch {
      /* keep defaults */
    }
    if (!active) {
      const ok = await ask({
        title: 'Run a loud tool?',
        message: `${selected.host} is passive_only.\n\nThe 403 bypass is a LOUD, active tool. Only run it against ${host}${hitPath} if you are authorized to actively test this target.`,
        confirmLabel: 'Run anyway',
        tone: 'danger',
      })
      if (!ok) return
    }
    try {
      const { jobId } = await api.runTool(selected.id, { tool: 'bypass403', target: host, path: hitPath, scheme: sch, confirm: !active })
      setMsg({ ok: true, text: `Queued 403 bypass job #${jobId} on ${hitPath} — results appear on the Tools/Findings page.` })
    } catch (err) {
      setMsg({ ok: false, text: err instanceof ApiError ? err.message : 'failed to start 403 bypass' })
    }
  }

  return (
    <div>
      <PageHeader
        title="Fuzzing"
        subtitle={`${selected.host} — content discovery (ffuf)`}
        actions={<Badge tone="amber">LOUD / ACTIVE</Badge>}
      />

      {!active && (
        <Card className="mb-4 border-amber-900/50">
          <div className="flex items-center gap-2">
            <Badge tone="amber">passive_only</Badge>
            <span className="text-sm font-medium text-amber-200">This domain is passive — ffuf is loud/active</span>
          </div>
          <p className="mt-2 text-sm text-zinc-400">
            You can still run it after a confirmation, but only do so for a target you are authorized to actively
            test. (Set the domain to <span className="font-mono">active_authorized</span> in Domains to skip the prompt.)
          </p>
        </Card>
      )}

      <Card className="mb-5">
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="text-zinc-400">Target host</span>
            <select
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="mt-1 block w-64 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-accent-500"
            >
              {hosts.length === 0 && <option value={selected.host}>{selected.host}</option>}
              {hosts.map((h) => (
                <option key={h.host} value={h.host}>
                  {h.host}
                  {h.live ? ' • live' : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="text-zinc-400">Scheme</span>
            <select
              value={scheme}
              onChange={(e) => setScheme(e.target.value as 'https' | 'http')}
              className="mt-1 block rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm"
            >
              <option value="https">https</option>
              <option value="http">http</option>
            </select>
          </label>
          <label className="text-sm">
            <span className="text-zinc-400">Path (must contain FUZZ)</span>
            <input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="FUZZ"
              className={`mt-1 block w-40 rounded-lg border bg-ink-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-accent-500 ${pathValid ? 'border-hair' : 'border-red-800'}`}
            />
          </label>
          <label className="text-sm">
            <span className="text-zinc-400">Wordlist</span>
            <select
              value={wordlist}
              onChange={(e) => setWordlist(e.target.value)}
              className="mt-1 block w-64 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
            >
              <option value="">default (common.txt)</option>
              {(meta?.wordlists ?? []).map((w) => (
                <option key={w.path} value={w.path}>
                  {w.name} ({w.sizeKb > 1024 ? `${(w.sizeKb / 1024).toFixed(1)}MB` : `${w.sizeKb}KB`})
                </option>
              ))}
            </select>
          </label>
          <Button
            variant="loud"
            onClick={run}
            disabled={running || toolMissing || !pathValid || !target}
          >
            {running ? 'Starting…' : active ? 'Run ffuf' : 'Run ffuf (confirm)'}
          </Button>
        </div>
        {!pathValid && <p className="mt-2 text-xs text-red-400">Path must contain FUZZ.</p>}
        {toolMissing && <p className="mt-2 text-xs text-zinc-500">ffuf is not installed in this image.</p>}
        {msg && <p className={`mt-2 text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>{msg.text}</p>}
      </Card>

      {hits.length === 0 ? (
        <Empty>No fuzzing hits yet for {selected.host}.</Empty>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-hair">
          <table className="w-full min-w-[680px] text-sm">
            <thead className="bg-ink-900/60 text-left text-xs">
              <tr>
                <SortTh label="Status" k="status" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} className="w-20" />
                <SortTh label="URL" k="url" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                <SortTh label="Length" k="length" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} className="w-24" />
                <SortTh label="Words" k="words" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} className="w-24" />
                <SortTh label="Found" k="found" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} className="w-28" />
                <th className="w-24 px-3 py-2 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Action</th>
              </tr>
            </thead>
            <tbody>
              {sortedHits.map((h) => (
                <tr key={h.id} className="border-t border-hair/60">
                  <td className="px-3 py-2">
                    <Badge tone={statusTone(Number(h.data?.status))}>{h.data?.status ?? '?'}</Badge>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-zinc-200 break-all">
                    {h.data?.url ? (
                      <a href={safeHttpUrl(h.data.url)} target="_blank" rel="noreferrer" className="hover:underline">
                        {h.data.url}
                      </a>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="px-3 py-2 text-zinc-400">{h.data?.length ?? '—'}</td>
                  <td className="px-3 py-2 text-zinc-400">{h.data?.words ?? '—'}</td>
                  <td className="px-3 py-2 text-zinc-500">{timeAgo(new Date(h.createdAt).getTime())}</td>
                  <td className="px-3 py-2">
                    {(Number(h.data?.status) === 403 || Number(h.data?.status) === 401) && (
                      <button
                        type="button"
                        onClick={() => sendToBypass(h)}
                        title="Send this forbidden path to the 403/401 bypass tool"
                        className="rounded border border-amber-600/40 px-2 py-0.5 text-[11px] text-amber-300 transition hover:bg-amber-600/10"
                      >
                        Bypass 403 →
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
