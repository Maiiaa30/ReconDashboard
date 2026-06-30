import { useCallback, useState, type ReactNode } from 'react'
import { api, type Subdomain } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Empty, ExportLinks, PageHeader } from '../components/ui'

type Tone = 'green' | 'blue' | 'amber' | 'red' | 'zinc'

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

export function Subdomains() {
  const { selected } = useApp()
  const [subs, setSubs] = useState<Subdomain[]>([])
  const [running, setRunning] = useState(false)
  const [lastJob, setLastJob] = useState<number | null>(null)
  const [expandedId, setExpandedId] = useState<number | null>(null)

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
          <div className="divide-y divide-zinc-800/60 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/40">
            {subs.map((s) => {
              const expanded = expandedId === s.id
              return (
                <div key={s.id}>
                  <button
                    type="button"
                    onClick={() => setExpandedId(expanded ? null : s.id)}
                    className="flex w-full cursor-pointer items-center gap-3 px-3 py-2 text-left text-sm hover:bg-zinc-800/40"
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
                    <span className="text-xs text-zinc-600">{expanded ? '▾' : '▸'}</span>
                  </button>

                  {expanded && (
                    <div className="grid grid-cols-2 gap-x-6 gap-y-3 border-t border-zinc-800/60 bg-zinc-950/40 px-3 py-3 sm:grid-cols-3">
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
                            href={`${s.scheme}://${s.host}`}
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
