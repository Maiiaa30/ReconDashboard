import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Copy, Check } from 'lucide-react'
import { api, type Subdomain, type SubdomainSort } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Empty, ExportLinks, PageHeader } from '../components/ui'
import { useToast } from '../components/Toast'
import { copyText } from '../lib/clipboard'
import { safeHttpUrl } from '../lib/url'

type Tone = 'green' | 'blue' | 'amber' | 'red' | 'zinc'

// Server-side page size for keyset pagination; "Load more" fetches the next page.
const PAGE_SIZE = 100

const SORTS: { key: SubdomainSort; label: string }[] = [
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
  const toast = useToast()
  const [subs, setSubs] = useState<Subdomain[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const [summary, setSummary] = useState<{ total: number; newCount: number } | null>(null)
  const [running, setRunning] = useState(false)
  const [lastJob, setLastJob] = useState<number | null>(null)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [sortKey, setSortKey] = useState<SubdomainSort>('status')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [q, setQ] = useState('')
  const [newOnly, setNewOnly] = useState(false)
  const cursorRef = useRef<string | null>(null)
  cursorRef.current = nextCursor

  // Text-ish keys default to A→Z; numeric/recency keys default to biggest-first.
  function toggleSort(k: SubdomainSort) {
    if (k === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortKey(k)
      setSortDir(k === 'host' || k === 'ip' ? 'asc' : 'desc')
    }
  }

  const query = useMemo(
    () => ({ q: q.trim() || undefined, newOnly: newOnly || undefined, sort: sortKey, dir: sortDir }),
    [q, newOnly, sortKey, sortDir],
  )

  // Load the first page for the current filter/sort.
  const load = useCallback(() => {
    if (!selected) return
    api
      .subdomainsPage(selected.id, { ...query, limit: PAGE_SIZE })
      .then((r) => {
        setSubs(r.subdomains)
        setNextCursor(r.nextCursor)
      })
      .catch(() => toast.error('Failed to load subdomains.'))
  }, [selected, query, toast])

  const loadMore = useCallback(() => {
    const cursor = cursorRef.current
    if (!selected || !cursor || loadingMore) return
    setLoadingMore(true)
    api
      .subdomainsPage(selected.id, { ...query, limit: PAGE_SIZE, cursor })
      .then((r) => {
        setSubs((prev) => [...prev, ...r.subdomains])
        setNextCursor(r.nextCursor)
      })
      .catch(() => toast.error('Failed to load more subdomains.'))
      .finally(() => setLoadingMore(false))
  }, [selected, query, loadingMore, toast])

  const loadSummary = useCallback(() => {
    if (!selected) return
    api
      .subdomainsSummary(selected.id, { q: query.q })
      .then(setSummary)
      .catch(() => setSummary(null))
  }, [selected, query.q])

  // Debounced so typing in the host search doesn't fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => load(), 200)
    return () => clearTimeout(t)
  }, [load])

  useEffect(() => {
    const t = setTimeout(() => loadSummary(), 200)
    return () => clearTimeout(t)
  }, [loadSummary])

  // While a discovery/permute job runs, poll to surface fresh results and detect
  // completion. Polling is OFF when idle so loaded pages aren't clobbered.
  const pollRunning = useCallback(() => {
    if (!selected) return
    load()
    loadSummary()
    if (lastJob != null) {
      api.job(lastJob).then((r) => {
        if (r.job.status === 'done' || r.job.status === 'error') {
          setRunning(false)
          setLastJob(null)
        }
      })
    }
  }, [selected, lastJob, load, loadSummary])

  usePoll(pollRunning, 3000, !!selected && running)

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
      loadSummary()
    } catch {
      /* transient; next poll refreshes */
    }
  }

  if (!selected) return <Empty>Select a domain (Domains tab) to view subdomains.</Empty>

  const newCount = summary?.newCount ?? 0
  const total = summary?.total ?? subs.length
  const inputCls =
    'rounded-lg border border-hair bg-ink-850 px-3 py-1.5 text-sm outline-none focus:border-accent-500'

  return (
    <div>
      <PageHeader
        title="Subdomains"
        subtitle={`${selected.host} — ${total} known, ${newCount} new`}
        actions={
          <>
            {total > 0 && (
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

      <div className="mb-3 flex flex-wrap items-center gap-1.5 text-xs">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter host…"
          className={`${inputCls} w-44`}
        />
        <button
          onClick={() => setNewOnly((v) => !v)}
          className={`rounded-lg border px-2 py-1 transition ${
            newOnly
              ? 'border-accent-500 bg-accent-500/15 text-accent-fg'
              : 'border-hair text-zinc-400 hover:border-hair-strong hover:text-zinc-200'
          }`}
        >
          New only
        </button>
        <span className="ml-2 text-zinc-500">Sort by</span>
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

      {subs.length === 0 ? (
        <Empty>
          {q || newOnly
            ? 'No subdomains match this filter.'
            : 'No subdomains discovered yet. Click “Run discovery now” (passive: crt.sh + subfinder).'}
        </Empty>
      ) : (
        <>
          <div className="mb-2 text-xs text-zinc-500">
            {subs.length}
            {total > subs.length ? ` of ${total}` : ''} shown
          </div>
          <div className="divide-y divide-zinc-800/60 overflow-hidden rounded-xl border border-hair bg-ink-850/60">
            {subs.map((s) => {
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
                    {s.waf && (
                      <Badge tone="amber">
                        {(s.httpStatus === 403 || s.httpStatus === 503 || s.httpStatus === 429) ? `${s.waf} · protected` : s.waf}
                      </Badge>
                    )}
                    {s.isNew && <Badge tone="blue">new</Badge>}
                    <CopyLink url={`${s.scheme ?? 'https'}://${s.host}`} />
                    <span className="text-xs text-zinc-600">{expanded ? '▾' : '▸'}</span>
                  </button>

                  {expanded && (
                    <div className="grid grid-cols-2 gap-x-6 gap-y-3 border-t border-hair/60 bg-ink-900/50 px-3 py-3 sm:grid-cols-3">
                      <Field label="IP address" value={s.ipAddress ?? '—'} mono />
                      <Field label="Server" value={s.server ?? '—'} mono />
                      <Field label="WAF / CDN" value={s.waf ?? '—'} />
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
          {nextCursor && (
            <div className="mt-3 flex justify-center">
              <button
                onClick={loadMore}
                disabled={loadingMore}
                className="rounded-lg border border-hair px-4 py-1.5 text-sm text-zinc-300 transition hover:border-hair-strong hover:bg-ink-800 disabled:opacity-50"
              >
                {loadingMore ? 'Loading…' : `Load more${total > subs.length ? ` (${total - subs.length} more)` : ''}`}
              </button>
            </div>
          )}
          <p className="mt-2 text-xs text-zinc-600">
            Status, title, IP and server come from a lightweight HTTP/HTTPS probe run during discovery. Cloudflare-challenged hosts (403 · "Just a moment…") are re-checked through a headless browser that solves the JS challenge, so a protected host that loads in your browser shows as reachable here too. Click a row to expand.
          </p>
        </>
      )}
    </div>
  )
}
