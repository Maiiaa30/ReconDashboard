import { useEffect, useMemo, useState } from 'react'
import { Network } from 'lucide-react'
import { api, type SitemapHost } from '../../api'
import { Card, Empty } from '../../components/ui'

const SITEMAP_METHOD_TONE: Record<string, string> = {
  GET: 'text-green-300 bg-green-500/10',
  POST: 'text-blue-300 bg-blue-500/10',
  PUT: 'text-amber-300 bg-amber-500/10',
  PATCH: 'text-amber-300 bg-amber-500/10',
  DELETE: 'text-red-300 bg-red-500/10',
}

// Endpoint tree assembled from captured traffic + fuzz hits + discovery. Clicking
// a row loads that method+URL into the Repeater.
export function SitemapPanel({ domainId, onOpen }: { domainId: number; onOpen: (method: string, url: string) => void }) {
  const [hosts, setHosts] = useState<SitemapHost[]>([])
  const [loaded, setLoaded] = useState(false)
  const [filter, setFilter] = useState('')
  useEffect(() => {
    setLoaded(false)
    api
      .sitemap(domainId)
      .then((r) => setHosts(r.hosts))
      .catch(() => setHosts([]))
      .finally(() => setLoaded(true))
  }, [domainId])

  const q = filter.trim().toLowerCase()
  const shown = useMemo(
    () =>
      hosts
        .map((h) => ({
          ...h,
          endpoints: q ? h.endpoints.filter((e) => e.path.toLowerCase().includes(q) || e.method.toLowerCase().includes(q)) : h.endpoints,
        }))
        .filter((h) => h.endpoints.length),
    [hosts, q],
  )
  const total = shown.reduce((n, h) => n + h.endpoints.length, 0)

  return (
    <Card className="flex min-h-0 flex-1 flex-col">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Network size={15} className="text-accent-fg" />
        <h2 className="text-sm font-semibold text-zinc-200">Sitemap</h2>
        <span className="text-xs text-zinc-500">{total} endpoint(s) — captured, fuzzed & discovered. Click one to load it.</span>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter path/method…"
          className="ml-auto w-56 rounded-lg border border-hair bg-ink-950 px-3 py-1 text-xs outline-none focus:border-accent-500"
        />
      </div>
      {!loaded ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : shown.length === 0 ? (
        <Empty>No endpoints yet. Capture traffic (extension), run API discovery, or fuzz to populate the sitemap.</Empty>
      ) : (
        <div className="min-h-0 flex-1 space-y-3 overflow-auto">
          {shown.map((h) => (
            <div key={h.host}>
              <div className="mb-1 flex items-center gap-2">
                <span className="font-mono text-sm text-zinc-200">{h.host}</span>
                <span className="text-xs text-zinc-500">{h.endpoints.length}</span>
              </div>
              <div className="space-y-0.5">
                {h.endpoints.map((e, i) => (
                  <button
                    key={i}
                    onClick={() => onOpen(e.method, e.url)}
                    title={`Load ${e.method} ${e.url} into the Repeater`}
                    className="flex w-full items-center gap-2 rounded border border-hair bg-ink-900/50 px-2 py-1 text-left transition hover:border-accent-500/40 hover:bg-ink-850"
                  >
                    <span className={`w-14 shrink-0 rounded px-1 text-center font-mono text-[10px] ${SITEMAP_METHOD_TONE[e.method] ?? 'text-zinc-300 bg-ink-800'}`}>
                      {e.method}
                    </span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-300">{e.path}</span>
                    {e.status != null && <span className="shrink-0 font-mono text-[10px] text-zinc-500">{e.status}</span>}
                    <span className="shrink-0 text-[10px] text-zinc-600">{e.source}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
