import { useCallback, useState } from 'react'
import { api, type Subdomain } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Empty, PageHeader } from '../components/ui'

export function Subdomains() {
  const { selected } = useApp()
  const [subs, setSubs] = useState<Subdomain[]>([])
  const [running, setRunning] = useState(false)
  const [lastJob, setLastJob] = useState<number | null>(null)

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
    await api.acknowledgeNew(selected.id)
    load()
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
        <div className="overflow-hidden rounded-xl border border-zinc-800">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900/60 text-left text-xs text-zinc-500">
              <tr>
                <th className="px-3 py-2">Host</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">First seen</th>
                <th className="px-3 py-2">Last seen</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {subs.map((s) => (
                <tr key={s.id} className="border-t border-zinc-800/60">
                  <td className="px-3 py-2 font-mono text-zinc-200">{s.host}</td>
                  <td className="px-3 py-2 text-zinc-400">{s.source ?? '—'}</td>
                  <td className="px-3 py-2 text-zinc-500">{new Date(s.firstSeen).toLocaleDateString()}</td>
                  <td className="px-3 py-2 text-zinc-500">{new Date(s.lastSeen).toLocaleDateString()}</td>
                  <td className="px-3 py-2">{s.isNew && <Badge tone="blue">new</Badge>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
