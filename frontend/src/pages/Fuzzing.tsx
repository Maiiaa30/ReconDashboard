import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type Finding, type MetaStatus } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { timeAgo } from '../lib/format'

function statusTone(status: number): 'green' | 'amber' | 'red' | 'blue' | 'zinc' {
  if (status >= 200 && status < 300) return 'green'
  if (status >= 300 && status < 400) return 'blue'
  if (status === 401 || status === 403) return 'amber'
  if (status >= 500) return 'red'
  return 'zinc'
}

export function Fuzzing() {
  const { selected } = useApp()
  const [hits, setHits] = useState<Finding[]>([])
  const [meta, setMeta] = useState<MetaStatus | null>(null)
  const [path, setPath] = useState('FUZZ')
  const [scheme, setScheme] = useState<'https' | 'http'>('https')
  const [wordlist, setWordlist] = useState('')
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [running, setRunning] = useState(false)

  useEffect(() => {
    api.meta().then(setMeta).catch(() => setMeta(null))
  }, [])

  const load = useCallback(() => {
    if (!selected) return
    api
      .findings({ domainId: selected.id, type: 'ffuf', limit: 1000 })
      .then((r) => setHits(r.findings))
      .catch(() => {})
  }, [selected])
  usePoll(load, 4000, !!selected)

  if (!selected) return <Empty>Select a domain to view fuzzing results.</Empty>

  const active = selected.mode === 'active_authorized'
  const toolMissing = meta ? !meta.tools.ffuf : false

  async function run() {
    if (!selected) return
    setMsg(null)
    setRunning(true)
    try {
      const { jobId } = await api.ffuf(selected.id, path || 'FUZZ', wordlist || undefined, scheme)
      setMsg({ ok: true, text: `Queued ffuf job #${jobId} — results appear below as they complete.` })
    } catch (err) {
      setMsg({ ok: false, text: err instanceof ApiError ? err.message : 'failed to start ffuf' })
    } finally {
      setRunning(false)
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
            <Badge tone="amber">disabled</Badge>
            <span className="text-sm font-medium text-amber-200">ffuf is disabled for passive_only domains</span>
          </div>
          <p className="mt-2 text-sm text-zinc-400">
            Content fuzzing is loud/active. Mark <span className="font-mono">{selected.host}</span> as
            <span className="font-mono"> active_authorized</span> in the Domains tab — only for a target you are
            authorized to actively test — to enable it.
          </p>
        </Card>
      )}

      <Card className="mb-5">
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="text-zinc-400">Scheme</span>
            <select
              value={scheme}
              onChange={(e) => setScheme(e.target.value as 'https' | 'http')}
              className="mt-1 block rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm"
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
              className="mt-1 block w-40 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-zinc-500"
            />
          </label>
          <label className="text-sm">
            <span className="text-zinc-400">Wordlist</span>
            <select
              value={wordlist}
              onChange={(e) => setWordlist(e.target.value)}
              className="mt-1 block w-64 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
            >
              <option value="">default (common.txt)</option>
              {(meta?.wordlists ?? []).map((w) => (
                <option key={w.path} value={w.path}>
                  {w.name} ({w.sizeKb > 1024 ? `${(w.sizeKb / 1024).toFixed(1)}MB` : `${w.sizeKb}KB`})
                </option>
              ))}
            </select>
          </label>
          <Button variant="loud" onClick={run} disabled={!active || running || toolMissing}>
            {running ? 'Starting…' : 'Run ffuf'}
          </Button>
        </div>
        {toolMissing && <p className="mt-2 text-xs text-zinc-500">ffuf is not installed in this image.</p>}
        {msg && <p className={`mt-2 text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>{msg.text}</p>}
      </Card>

      {hits.length === 0 ? (
        <Empty>No fuzzing hits yet for {selected.host}.</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border border-zinc-800">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900/60 text-left text-xs text-zinc-500">
              <tr>
                <th className="px-3 py-2 w-20">Status</th>
                <th className="px-3 py-2">URL</th>
                <th className="px-3 py-2 w-24">Length</th>
                <th className="px-3 py-2 w-24">Words</th>
                <th className="px-3 py-2 w-28">Found</th>
              </tr>
            </thead>
            <tbody>
              {hits.map((h) => (
                <tr key={h.id} className="border-t border-zinc-800/60">
                  <td className="px-3 py-2">
                    <Badge tone={statusTone(Number(h.data?.status))}>{h.data?.status ?? '?'}</Badge>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-zinc-200 break-all">
                    {h.data?.url ? (
                      <a href={h.data.url} target="_blank" rel="noreferrer" className="hover:underline">
                        {h.data.url}
                      </a>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="px-3 py-2 text-zinc-400">{h.data?.length ?? '—'}</td>
                  <td className="px-3 py-2 text-zinc-400">{h.data?.words ?? '—'}</td>
                  <td className="px-3 py-2 text-zinc-500">{timeAgo(new Date(h.createdAt).getTime())}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
