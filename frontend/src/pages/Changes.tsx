import { useCallback, useMemo, useState } from 'react'
import { Bell, Clock, History, Network, ShieldAlert } from 'lucide-react'
import { api, type Finding, type Subdomain } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Card, Empty, PageHeader, ScoreBadge, SkeletonList } from '../components/ui'
import { summarizeFinding, timeAgo } from '../lib/format'

type ChangeItem = { id: string; at: number; kind: 'asset' | 'cve' | 'subdomain'; title: string; detail: string; finding?: Finding; subdomain?: Subdomain }

export function Changes({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const [findings, setFindings] = useState<Finding[]>([])
  const [subdomains, setSubdomains] = useState<Subdomain[]>([])
  const [loaded, setLoaded] = useState(false)

  const load = useCallback(() => {
    if (!selected) return
    Promise.all([api.findings({ domainId: selected.id, limit: 1000 }), api.subdomains(selected.id)])
      .then(([findingResult, subdomainResult]) => { setFindings(findingResult.findings); setSubdomains(subdomainResult.subdomains) })
      .catch(() => {}).finally(() => setLoaded(true))
  }, [selected])
  usePoll(load, 10000, !!selected, selected?.id)

  const timeline = useMemo<ChangeItem[]>(() => {
    const findingChanges = findings.filter((finding) => finding.type === 'asset_change' || finding.type === 'cve_new').map((finding) => ({
      id: `finding-${finding.id}`,
      at: new Date(finding.createdAt).getTime(),
      kind: finding.type === 'cve_new' ? 'cve' as const : 'asset' as const,
      title: summarizeFinding(finding.type, finding.data),
      detail: String(finding.data?.detail ?? finding.data?.host ?? finding.data?.ip ?? ''),
      finding,
    }))
    const newHosts = subdomains.filter((subdomain) => subdomain.isNew).map((subdomain) => ({
      id: `subdomain-${subdomain.id}`,
      at: new Date(subdomain.firstSeen).getTime(),
      kind: 'subdomain' as const,
      title: `New host ${subdomain.host}`,
      detail: [subdomain.httpStatus ? `HTTP ${subdomain.httpStatus}` : '', subdomain.title, subdomain.ipAddress].filter(Boolean).join(' · '),
      subdomain,
    }))
    return [...findingChanges, ...newHosts].sort((a, b) => b.at - a.at)
  }, [findings, subdomains])

  if (!selected) return <Empty>Select an engagement to view its change history.</Empty>
  return <div><PageHeader title="Change history" subtitle={`${selected.host} — new hosts, CVEs and material attack-surface changes`} />
    {!loaded ? <SkeletonList rows={7} /> : timeline.length === 0 ? <Empty>No material changes recorded yet. Enable monitoring or rerun a passive profile to establish and compare baselines.</Empty> : <div className="relative ml-3 border-l border-hair pl-6">{timeline.map((item) => {
      const Icon = item.kind === 'cve' ? ShieldAlert : item.kind === 'subdomain' ? Network : Bell
      const tone = item.kind === 'cve' ? 'text-red-400 border-red-900 bg-red-950' : item.kind === 'subdomain' ? 'text-blue-400 border-blue-900 bg-blue-950' : 'text-amber-400 border-amber-900 bg-amber-950'
      return <div key={item.id} className="relative mb-3"><span className={`absolute -left-[39px] top-4 flex h-7 w-7 items-center justify-center rounded-full border ${tone}`}><Icon size={13} /></span><button onClick={() => navigate(item.kind === 'subdomain' ? 'subdomains' : 'findings', selected.id)} className="w-full text-left"><Card className="!p-3 transition hover:border-hair-strong"><div className="flex items-start gap-3"><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><Badge tone={item.kind === 'cve' ? 'red' : item.kind === 'subdomain' ? 'blue' : 'amber'}>{item.kind}</Badge><span className="text-sm font-medium text-zinc-100">{item.title}</span></div>{item.detail && <p className="mt-1 text-xs text-zinc-500">{item.detail}</p>}</div>{item.finding && <ScoreBadge score={item.finding.score} />}<span className="flex shrink-0 items-center gap-1 text-xs text-zinc-600"><Clock size={12} /> {timeAgo(item.at)}</span></div></Card></button></div>
    })}</div>}
    {timeline.length > 0 && <div className="mt-4 flex items-center gap-2 text-xs text-zinc-600"><History size={13} /> Timeline reflects retained findings and unacknowledged discovered hosts.</div>}
  </div>
}
