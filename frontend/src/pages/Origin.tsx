import { useCallback, useState } from 'react'
import { api, type Finding } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { timeAgo } from '../lib/format'

interface OriginData {
  domain: string
  behindCdn: boolean
  provider: string | null
  apexIp: string | null
  baseline: { status: number | null; title: string | null }
  candidatesChecked: number
  confirmedOrigins: { ip: string; status: number | null; title: string | null; server: string | null }[]
  allCandidates: { ip: string; reachable: boolean; status: number | null; title: string | null; server: string | null; confirmed: boolean }[]
}

export function Origin() {
  const { selected } = useApp()
  const [latest, setLatest] = useState<Finding | null>(null)
  const [running, setRunning] = useState(false)
  const [lastJob, setLastJob] = useState<number | null>(null)

  const load = useCallback(() => {
    if (!selected) return
    api.findings({ domainId: selected.id, type: 'origin', limit: 1 }).then((r) => setLatest(r.findings[0] ?? null)).catch(() => {})
    if (lastJob != null) {
      api.job(lastJob).then((r) => {
        if (r.job.status === 'done' || r.job.status === 'error') {
          setRunning(false)
          setLastJob(null)
        }
      }).catch(() => {})
    }
  }, [selected, lastJob])
  usePoll(load, 4000, !!selected)

  if (!selected) return <Empty>Select a domain to discover its origin server.</Empty>

  async function run() {
    if (!selected) return
    setRunning(true)
    try {
      const { jobId } = await api.findOrigin(selected.id)
      setLastJob(jobId)
    } catch {
      setRunning(false)
    }
  }

  const data = latest?.data as OriginData | undefined

  return (
    <div>
      <PageHeader
        title="WAF / Origin"
        subtitle={`${selected.host} — find the real server behind a CDN/WAF`}
        actions={
          <Button onClick={run} disabled={running}>
            {running ? 'Scanning…' : 'Find origin'}
          </Button>
        }
      />

      <p className="mb-4 text-xs text-zinc-500">
        Discovers the origin IP behind Cloudflare/WAF (via non-proxied subdomains, mail records, and
        direct Host-header probes) so authorized active scans reach the real server, not the edge.
        Use only on targets you’re authorized to test.
      </p>

      {!data ? (
        <Empty>No origin scan yet. Click “Find origin”. (Run discovery first for best results — it uses your subdomains’ IPs.)</Empty>
      ) : (
        <div className="space-y-4">
          <Card>
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-sm text-zinc-400">Edge protection:</span>
              {data.behindCdn ? (
                <Badge tone="amber">{data.provider ?? 'CDN/WAF detected'}</Badge>
              ) : (
                <Badge tone="zinc">none detected (direct)</Badge>
              )}
              {data.apexIp && <span className="font-mono text-xs text-zinc-500">apex → {data.apexIp}</span>}
              <span className="ml-auto text-[10px] text-zinc-600">
                {timeAgo(new Date(latest!.createdAt).getTime())} · {data.candidatesChecked} candidate(s) checked
              </span>
            </div>
          </Card>

          {data.confirmedOrigins.length > 0 ? (
            <Card className="border-red-900/50">
              <h2 className="text-sm font-semibold text-red-300">
                ✅ Origin server found ({data.confirmedOrigins.length})
              </h2>
              <p className="mt-1 text-xs text-zinc-400">
                These non-CDN IPs served the site directly (Host-header match) — likely the real origin
                behind {data.provider ?? 'the edge'}.
              </p>
              <div className="mt-3 space-y-2">
                {data.confirmedOrigins.map((o) => (
                  <div key={o.ip} className="flex items-center gap-3 rounded-lg border border-hair bg-ink-900/50 px-3 py-2 text-sm">
                    <Badge tone="red">origin</Badge>
                    <span className="font-mono text-zinc-100">{o.ip}</span>
                    {o.status != null && <span className="text-zinc-500">HTTP {o.status}</span>}
                    {o.server && <span className="text-zinc-500">{o.server}</span>}
                    {o.title && <span className="min-w-0 flex-1 truncate text-zinc-500">{o.title}</span>}
                  </div>
                ))}
              </div>
            </Card>
          ) : (
            <Card>
              <p className="text-sm text-zinc-400">
                No confirmed origin among the checked candidates. The origin may be well-isolated, or run
                discovery + exposure first to surface more candidate IPs.
              </p>
            </Card>
          )}

          {data.allCandidates.length > 0 && (
            <Card>
              <h2 className="mb-2 text-sm font-semibold">All candidate IPs</h2>
              <div className="overflow-x-auto rounded-lg border border-hair">
                <table className="w-full min-w-[560px] text-sm">
                  <thead className="bg-ink-900/60 text-left text-xs text-zinc-500">
                    <tr>
                      <th className="px-3 py-2">IP</th>
                      <th className="px-3 py-2">Reachable</th>
                      <th className="px-3 py-2">Status</th>
                      <th className="px-3 py-2">Server</th>
                      <th className="px-3 py-2">Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.allCandidates.map((c) => (
                      <tr key={c.ip} className="border-t border-hair/60">
                        <td className="px-3 py-2 font-mono text-zinc-200">{c.ip}</td>
                        <td className="px-3 py-2 text-zinc-400">{c.reachable ? 'yes' : 'no'}</td>
                        <td className="px-3 py-2 text-zinc-400">{c.status ?? '—'}</td>
                        <td className="px-3 py-2 text-zinc-500">{c.server ?? '—'}</td>
                        <td className="px-3 py-2">
                          {c.confirmed ? <Badge tone="red">origin</Badge> : <Badge tone="zinc">candidate</Badge>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
