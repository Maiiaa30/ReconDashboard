import { useCallback, useEffect, useMemo, useState } from 'react'
import { Boxes, ExternalLink, Filter, Flag, Network, Search, Server, ShieldAlert, Telescope, type LucideIcon } from 'lucide-react'
import { api, type Asset, type AssetDetail } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, ScoreBadge, SkeletonList } from '../components/ui'
import { summarizeFinding, timeAgo } from '../lib/format'
import { setPendingFindingFilter, setPendingScan } from '../lib/navigationHandoff'

type KindFilter = 'all' | Asset['kind']

export function Assets({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const [assets, setAssets] = useState<Asset[]>([])
  const [loaded, setLoaded] = useState(false)
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<KindFilter>('all')
  const [onlyRisk, setOnlyRisk] = useState(false)
  const [investigateId, setInvestigateId] = useState<number | null>(null)

  const load = useCallback(() => {
    if (!selected) return
    api.assets(selected.id).then((result) => setAssets(result.assets)).catch(() => setAssets([])).finally(() => setLoaded(true))
  }, [selected])
  usePoll(load, 8000, !!selected, selected?.id)

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return assets
      .filter((asset) => kind === 'all' || asset.kind === kind)
      .filter((asset) => !onlyRisk || asset.activeFindingCount > 0)
      .filter((asset) => !needle || [asset.value, asset.ip, asset.title, asset.server, asset.asn, asset.asnName, ...asset.technologies].some((value) => String(value ?? '').toLowerCase().includes(needle)))
      .sort((a, b) => (b.maxScore ?? 0) - (a.maxScore ?? 0) || b.activeFindingCount - a.activeFindingCount || a.value.localeCompare(b.value))
  }, [assets, kind, onlyRisk, query])

  if (!selected) return <Empty>Select an engagement to view its assets.</Empty>

  const totals = {
    hosts: assets.filter((asset) => asset.kind === 'host').length,
    ips: assets.filter((asset) => asset.kind === 'ip').length,
    services: assets.filter((asset) => asset.kind === 'service').length,
    atRisk: assets.filter((asset) => asset.activeFindingCount > 0).length,
  }

  function openFindings(asset: Asset) {
    setPendingFindingFilter({ domainId: selected!.id, asset: asset.kind === 'service' ? asset.ip ?? asset.value : asset.value })
    navigate('findings', selected!.id)
  }

  function scan(asset: Asset) {
    const target = asset.kind === 'host' ? asset.value : asset.ip ?? asset.value.split(':')[0]
    setPendingScan({ target, ...(asset.port ? { ports: String(asset.port) } : {}) })
    navigate('scans', selected!.id)
  }

  return (
    <div>
      <PageHeader title="Asset inventory" subtitle={`${selected.host} — continuously validated hosts, services, technology and response fingerprints`} />

      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric icon={Network} label="Hosts" value={totals.hosts} tone="text-blue-400" />
        <Metric icon={Server} label="IP addresses" value={totals.ips} tone="text-emerald-400" />
        <Metric icon={Boxes} label="Services" value={totals.services} tone="text-violet-400" />
        <Metric icon={ShieldAlert} label="With active findings" value={totals.atRisk} tone="text-amber-400" />
      </div>

      <Card className="mb-4 !p-3">
        <div className="flex flex-wrap items-center gap-2">
          <label className="relative min-w-[220px] flex-1">
            <Search size={15} className="pointer-events-none absolute left-3 top-2.5 text-zinc-500" />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search host, IP, service, ASN or technology…" className="w-full rounded-lg border border-hair bg-ink-950 py-2 pl-9 pr-3 text-sm outline-none focus:border-accent-500" />
          </label>
          <div className="flex items-center gap-1 rounded-lg border border-hair bg-ink-950 p-1">
            {(['all', 'host', 'ip', 'service'] as KindFilter[]).map((value) => (
              <button key={value} onClick={() => setKind(value)} className={`rounded-md px-2.5 py-1 text-xs capitalize transition ${kind === value ? 'bg-accent-500/20 text-accent-fg' : 'text-zinc-500 hover:text-zinc-300'}`}>{value}</button>
            ))}
          </div>
          <button onClick={() => setOnlyRisk((value) => !value)} className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs transition ${onlyRisk ? 'border-amber-700/60 bg-amber-950/30 text-amber-300' : 'border-hair text-zinc-400 hover:border-hair-strong'}`}>
            <Filter size={13} /> Active findings only
          </button>
        </div>
      </Card>

      {!loaded ? <SkeletonList rows={6} /> : filtered.length === 0 ? <Empty>No assets match the current filters. Run discovery and exposure collection to populate the inventory.</Empty> : (
        <div className="overflow-hidden rounded-xl border border-hair bg-ink-900/40">
          <div className="hidden grid-cols-[90px_minmax(180px,1.4fr)_minmax(150px,1fr)_minmax(130px,1fr)_100px_180px] gap-3 border-b border-hair bg-ink-850 px-4 py-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500 lg:grid">
            <span>Kind</span><span>Asset</span><span>Context</span><span>Technology</span><span>Risk</span><span className="text-right">Actions</span>
          </div>
          {filtered.map((asset) => (
            <div key={asset.id} className="border-b border-hair/60 last:border-b-0">
            <div className="grid gap-3 px-4 py-3 lg:grid-cols-[90px_minmax(180px,1.4fr)_minmax(150px,1fr)_minmax(130px,1fr)_100px_180px] lg:items-center">
              <div><Badge tone={asset.kind === 'host' ? 'blue' : asset.kind === 'ip' ? 'green' : 'purple'}>{asset.kind}</Badge></div>
              <div className="min-w-0">
                <div className="truncate font-mono text-sm text-zinc-100">{asset.value}</div>
                <div className="mt-0.5 truncate text-xs text-zinc-500">{asset.title ?? asset.ip ?? '—'} · seen {timeAgo(new Date(asset.lastSeen).getTime())}</div>
              </div>
              <div className="min-w-0 text-xs text-zinc-400">
                {asset.httpStatus != null && <span className="mr-2 text-emerald-400">HTTP {asset.httpStatus}</span>}
                {asset.redirect && <span className="mr-2 text-blue-400" title={asset.redirect}>redirect</span>}
                {asset.asn && <span>{asset.asn}{asset.asnName ? ` · ${asset.asnName}` : ''}</span>}
                {!asset.asn && asset.ports.length > 0 && <span>{asset.ports.slice(0, 8).join(', ')}{asset.ports.length > 8 ? '…' : ''}</span>}
                {!asset.asn && asset.ports.length === 0 && <span>{asset.server ?? '—'}</span>}
              </div>
              <div className="flex min-w-0 flex-wrap gap-1">
                {asset.cdn && <Badge tone="indigo">{asset.cdn}</Badge>}
                {asset.technologies.slice(0, 3).map((technology) => <Badge key={technology}>{technology}</Badge>)}
                {!asset.cdn && asset.technologies.length === 0 && <span className="text-xs text-zinc-600">—</span>}
              </div>
              <div className="flex items-center gap-2">
                <ScoreBadge score={asset.maxScore} />
                {asset.activeFindingCount > 0 && <span className="text-xs text-zinc-500">{asset.activeFindingCount}</span>}
              </div>
              <div className="flex justify-end gap-1.5">
                {asset.kind === 'host' && asset.scheme && <a href={`${asset.scheme}://${asset.value}`} target="_blank" rel="noreferrer" className="rounded-lg border border-hair p-1.5 text-zinc-500 hover:text-zinc-200" title="Open asset"><ExternalLink size={14} /></a>}
                <Button
                  variant="ghost"
                  className={`px-2 py-1 text-xs ${investigateId === asset.id ? 'text-accent-fg' : ''}`}
                  onClick={() => setInvestigateId((cur) => (cur === asset.id ? null : asset.id))}
                  title="Investigate this asset — findings, traffic, related hosts"
                >
                  <Telescope size={13} />
                </Button>
                <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => scan(asset)}>Scan</Button>
                <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => openFindings(asset)}><Flag size={13} /> {asset.findingCount}</Button>
              </div>
            </div>
            {investigateId === asset.id && (
              <AssetInvestigation domainId={selected.id} asset={asset} onOpenFindings={() => openFindings(asset)} onSearch={setQuery} />
            )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function RelatedHosts({ label, hosts, onSearch }: { label: string; hosts: string[]; onSearch: (q: string) => void }) {
  if (hosts.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</span>
      {hosts.slice(0, 12).map((h) => (
        <button key={h} onClick={() => onSearch(h)} className="rounded border border-hair bg-ink-900/60 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300 hover:border-accent-500/40 hover:text-accent-fg" title={`Filter the inventory to ${h}`}>
          {h}
        </button>
      ))}
      {hosts.length > 12 && <span className="text-[11px] text-zinc-600">+{hosts.length - 12}</span>}
    </div>
  )
}

function shortUrl(u: string): string {
  try {
    const x = new URL(u)
    return x.pathname + x.search
  } catch {
    return u
  }
}

// Expanded per-asset investigation: pulls the aggregate detail for one host/IP
// and shows its enrichment, the findings that mention it, recent captured
// traffic, and hosts it shares an IP / TLS cert / favicon with.
function AssetInvestigation({
  domainId,
  asset,
  onOpenFindings,
  onSearch,
}: {
  domainId: number
  asset: Asset
  onOpenFindings: () => void
  onSearch: (q: string) => void
}) {
  const [detail, setDetail] = useState<AssetDetail | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let live = true
    setDetail(null)
    setError(false)
    const controller = new AbortController()
    api
      .assetDetail(domainId, asset.id, { signal: controller.signal })
      .then((d) => live && setDetail(d))
      .catch(() => live && setError(true))
    return () => {
      live = false
      controller.abort()
    }
  }, [domainId, asset.id])

  return (
    <div className="border-t border-hair/60 bg-ink-950/40 px-4 py-3">
      {error ? (
        <p className="text-xs text-red-300">Couldn&apos;t load the investigation view. It will retry when you reopen it.</p>
      ) : !detail ? (
        <p className="text-xs text-zinc-500">Loading investigation…</p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Left: enrichment + related hosts */}
          <div className="space-y-2.5">
            {detail.subdomain && (
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-400">
                {detail.subdomain.httpStatus != null && <span className="text-emerald-400">HTTP {detail.subdomain.httpStatus}</span>}
                {detail.subdomain.title && <span className="text-zinc-300">{detail.subdomain.title}</span>}
                {detail.subdomain.server && <span>server: {detail.subdomain.server}</span>}
                {detail.subdomain.ipAddress && <span className="font-mono">{detail.subdomain.ipAddress}</span>}
                {detail.subdomain.certFp && <span title={detail.subdomain.certFp}>cert ✓</span>}
              </div>
            )}
            {detail.related.sameIp.length + detail.related.sameCert.length + detail.related.sameFavicon.length === 0 ? (
              <p className="text-xs text-zinc-600">No hosts share this asset&apos;s IP, TLS cert, or favicon.</p>
            ) : (
              <div className="space-y-1.5">
                <RelatedHosts label="Same IP" hosts={detail.related.sameIp} onSearch={onSearch} />
                <RelatedHosts label="Same cert" hosts={detail.related.sameCert} onSearch={onSearch} />
                <RelatedHosts label="Same favicon" hosts={detail.related.sameFavicon} onSearch={onSearch} />
              </div>
            )}
            {detail.captures.length > 0 && (
              <div>
                <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-500">Recent traffic ({detail.captures.length})</div>
                <div className="space-y-0.5">
                  {detail.captures.slice(0, 6).map((c) => (
                    <div key={c.id} className="flex items-center gap-2 font-mono text-[11px]">
                      <span className="w-11 shrink-0 text-zinc-400">{c.method}</span>
                      <span className="min-w-0 flex-1 truncate text-zinc-300" title={c.url}>{shortUrl(c.url)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Right: findings */}
          <div>
            <div className="mb-1 flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-wide text-zinc-500">Findings ({detail.findings.length})</span>
              {detail.findings.length > 0 && (
                <button onClick={onOpenFindings} className="text-[11px] text-accent-fg hover:underline">View all →</button>
              )}
            </div>
            {detail.findings.length === 0 ? (
              <p className="text-xs text-zinc-600">No findings reference this asset.</p>
            ) : (
              <div className="space-y-1">
                {detail.findings.slice(0, 8).map((f) => (
                  <button key={f.id} onClick={onOpenFindings} className="flex w-full items-center gap-2 rounded border border-hair/60 bg-ink-900/50 px-2 py-1 text-left hover:border-accent-500/40">
                    <ScoreBadge score={f.score} />
                    <span className="min-w-0 flex-1 truncate text-xs text-zinc-200" title={summarizeFinding(f.type, f.data)}>{summarizeFinding(f.type, f.data)}</span>
                    <span className="shrink-0 text-[10px] text-zinc-500">{f.status}</span>
                  </button>
                ))}
                {detail.findings.length > 8 && <p className="text-[11px] text-zinc-600">+{detail.findings.length - 8} more</p>}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function Metric({ icon: Icon, label, value, tone }: { icon: LucideIcon; label: string; value: number; tone: string }) {
  return <Card className="!p-3"><div className="flex items-center gap-2"><Icon size={15} className={tone} /><span className="text-xs text-zinc-500">{label}</span></div><div className="mt-1 text-2xl font-semibold text-zinc-100">{value}</div></Card>
}
