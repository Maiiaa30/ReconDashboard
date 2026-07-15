import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { Copy, Check } from 'lucide-react'
import { api, type Subdomain } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Empty, ExportLinks, PageHeader } from '../components/ui'
import { useToast } from '../components/Toast'
import { copyText } from '../lib/clipboard'
import { safeHttpUrl } from '../lib/url'

type Tone = 'green' | 'blue' | 'amber' | 'red' | 'zinc'

type SortKey = 'status' | 'host' | 'ip' | 'lastSeen' | 'new'
const SORTS: { key: SortKey; label: string }[] = [
  { key: 'status', label: 'Status' },
  { key: 'host', label: 'Host' },
  { key: 'ip', label: 'IP' },
  { key: 'lastSeen', label: 'Last seen' },
  { key: 'new', label: 'New' },
]

function statusTone(status: number | null): Tone {
  if (status == null) return 'zinc'
  if (status >= 200 && status < 300) return 'green'
  if (status >= 300 && status < 400) return 'blue'
  if (status === 401 || status === 403) return 'amber'
  if (status >= 400) return 'red'
  return 'zinc'
}

function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs uppercase tracking-wide text-zinc-600">{label}</span>
      <span className={`text-zinc-300 ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}

// One-click copy of a subdomain link (stops the row toggle; brief ✓ feedback).
function CopyLink({ url }: { url: string }) {
  const toast = useToast()
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      title={`Copy ${url}`}
      aria-label="Copy link"
      onClick={async (e) => {
        e.stopPropagation()
        const ok = await copyText(url)
        if (ok) {
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        } else {
          toast.error('Copy failed')
        }
      }}
      className="rounded p-1 text-zinc-500 transition hover:bg-ink-700 hover:text-zinc-200"
    >
      {copied ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
    </button>
  )
}

export function Subdomains() {
  const { selected } = useApp()
  const [subs, setSubs] = useState<Subdomain[]>([])
  const [running, setRunning] = useState(false)
  const [lastJob, setLastJob] = useState<number | null>(null)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [sortKey, setSortKey] = useState<SortKey>('status')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  // Text-ish keys default to A→Z; numeric/recency keys default to biggest-first.
  function toggleSort(k: SortKey) {
    if (k === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortKey(k)
      setSortDir(k === 'host' || k === 'ip' ? 'asc' : 'desc')
    }
  }

  const sorted = useMemo(() => {
    const dir = sortDir === 'asc' ? 1 : -1
    return [...subs].sort((a, b) => {
      switch (sortKey) {
        case 'status':
          return ((a.httpStatus ?? -1) - (b.httpStatus ?? -1)) * dir
        case 'host':
          return a.host.localeCompare(b.host) * dir
        case 'ip':
          return (a.ipAddress ?? '').localeCompare(b.ipAddress ?? '', undefined, { numeric: true }) * dir
        case 'lastSeen':
          return (new Date(a.lastSeen).getTime() - new Date(b.lastSeen).getTime()) * dir
        case 'new':
          return ((a.isNew ? 1 : 0) - (b.isNew ? 1 : 0)) * dir
        default:
          return 0
      }
    })
  }, [subs, sortKey, sortDir])

  const load = useCallback(() => {
    if (!selected) return
    api.subdomains(selected.id).then((r) => setSubs(r.subdomains))
    if (lastJob != null) {
      api.job(lastJob).then((r) => {
        if (r.job.status === 'done' || r.job.status === 'error') {
          setRunning(false)
          setLastJob(null)
        }
      })
    }
  }, [selected, lastJob])

  usePoll(load, 3000, !!selected)

  async function runDiscovery() {
    if (!selected) return
    setRunning(true)
    try {
      const { jobId } = await api.discover(selected.id)
      setLastJob(jobId)
    } catch {
      setRunning(false) // don't leave the button stuck on failure
    }
  }

  async function runPermute() {
    if (!selected) return
    setRunning(true)
    try {
      const { jobId } = await api.dnsPermute(selected.id)
      setLastJob(jobId)
    } catch {
      setRunning(false)
    }
  }

  async function ack() {
    if (!selected) return
    try {
      await api.acknowledgeNew(selected.id)
      load()
    } catch {
      /* transient; next poll refreshes */
    }
  }

  if (!selected) return <Empty>Select a domain (Domains tab) to view subdomains.</Empty>

  const newCount = subs.filter((s) => s.isNew).length

  return (
    <div>
      <PageHeader
        title="Subdomains"
        subtitle={`${selected.host} — ${subs.length} known, ${newCount} new`}
        actions={
          <>
            {subs.length > 0 && (
              <ExportLinks path={`/domains/${selected.id}/subdomains/export`} formats={['csv', 'txt', 'json']} />
            )}
            {newCount > 0 && (
              <Button variant="ghost" onClick={ack}>
                Acknowledge {newCount} new
              </Button>
            )}
            <Button variant="ghost" onClick={runPermute} disabled={running} title="Permute names from the wordlist + inventory and brute-resolve (wildcard-guarded)">
              Permute DNS
            </Button>
            <Button onClick={runDiscovery} disabled={running}>
              {running ? 'Discovering…' : 'Run discovery now'}
            </Button>
          </>
        }
      />

      {subs.length === 0 ? (
        <Empty>No subdomains discovered yet. Click “Run discovery now” (passive: crt.sh + subfinder).</Empty>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-zinc-500">Sort by</span>
            {SORTS.map((s) => {
              const active = sortKey === s.key
              return (
                <button
                  key={s.key}
                  onClick={() => toggleSort(s.key)}
                  className={`rounded-lg border px-2 py-1 transition ${
                    active
                      ? 'border-accent-500 bg-accent-500/15 text-accent-fg'
                      : 'border-hair text-zinc-400 hover:border-hair-strong hover:text-zinc-200'
                  }`}
                >
                  {s.label}
                  {active && <span className="ml-1">{sortDir === 'asc' ? '▲' : '▼'}</span>}
                </button>
              )
            })}
          </div>
          <div className="divide-y divide-zinc-800/60 overflow-hidden rounded-xl border border-hair bg-ink-850/60">
            {sorted.map((s) => {
              const expanded = expandedId === s.id
              return (
                <div key={s.id}>
                  <button
                    type="button"
                    onClick={() => setExpandedId(expanded ? null : s.id)}
                    className="flex w-full cursor-pointer items-center gap-3 px-3 py-2 text-left text-sm hover:bg-ink-800/40"
                  >
                    <Badge tone={statusTone(s.httpStatus)}>{s.httpStatus ?? '—'}</Badge>
                    <span className="font-mono text-zinc-200">{s.host}</span>
                    {s.title && (
                      <span className="min-w-0 flex-1 truncate text-zinc-500" title={s.title}>
                        {s.title}
                      </span>
                    )}
                    {!s.title && <span className="flex-1" />}
                    {s.isNew && <Badge tone="blue">new</Badge>}
                    <CopyLink url={`${s.scheme ?? 'https'}://${s.host}`} />
                    <span className="text-xs text-zinc-600">{expanded ? '▾' : '▸'}</span>
                  </button>

                  {expanded && (
                    <div className="grid grid-cols-2 gap-x-6 gap-y-3 border-t border-hair/60 bg-ink-900/50 px-3 py-3 sm:grid-cols-3">
                      <Field label="IP address" value={s.ipAddress ?? '—'} mono />
                      <Field label="Server" value={s.server ?? '—'} mono />
                      <Field label="Scheme" value={s.scheme ?? '—'} mono />
                      <Field label="Source" value={s.source ?? '—'} />
                      <Field label="First seen" value={new Date(s.firstSeen).toLocaleString()} />
                      <Field label="Last seen" value={new Date(s.lastSeen).toLocaleString()} />
                      {s.scheme && (
                        <div className="col-span-2 flex flex-col gap-0.5 sm:col-span-3">
                          <span className="text-xs uppercase tracking-wide text-zinc-600">Open</span>
                          <a
                            href={safeHttpUrl(`${s.scheme}://${s.host}`)}
                            target="_blank"
                            rel="noreferrer"
                            className="font-mono text-sky-400 hover:text-sky-300 hover:underline"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {`${s.scheme}://${s.host}`}
                          </a>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
          <p className="mt-2 text-xs text-zinc-600">
            Status, title, IP and server come from a lightweight HTTP/HTTPS probe run during discovery. Click a row to expand.
          </p>
        </>
      )}
    </div>
  )
}
