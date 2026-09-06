import { useState } from 'react'
import { Crosshair, ChevronRight } from 'lucide-react'
import { Badge, Card } from '../../components/ui'

const FFUF_STATUS_TONE = (s: number) =>
  s === 200 || s === 204
    ? 'text-green-300 bg-green-500/10'
    : s === 401 || s === 403
      ? 'text-amber-300 bg-amber-500/10'
      : s >= 300 && s < 400
        ? 'text-sky-300 bg-sky-500/10'
        : 'text-zinc-300 bg-ink-800'

export function FfufCard({ hits }: { hits: { url: string; status: number }[] }) {
  const [open, setOpen] = useState(false)
  const shown = open ? hits : hits.slice(0, 15)
  const fmt = (u: string) => {
    try {
      const x = new URL(u)
      return x.host + x.pathname + x.search
    } catch {
      return u
    }
  }
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <Crosshair size={16} className="text-orange-400" />
        <Badge tone="amber">ffuf fuzz</Badge>
        <span className="text-sm font-medium text-zinc-100">{hits.length} API path(s) that responded</span>
      </div>
      <div className="mt-1 text-xs text-zinc-500">
        Active brute-force of common API paths — each hit is a path that actually answered (200 = open, 401/403 = exists but
        protected), so it&apos;s a confirmed endpoint, not just a reference.
      </div>
      <div className="mt-2.5 space-y-0.5">
        {shown.map((h, i) => (
          <div key={i} className="flex items-center gap-2 font-mono text-[11px]">
            <span className={`rounded px-1 ${FFUF_STATUS_TONE(h.status)}`}>{h.status || '—'}</span>
            <span className="text-zinc-300 break-all">{fmt(h.url)}</span>
          </div>
        ))}
      </div>
      {hits.length > 15 && (
        <button
          onClick={() => setOpen((v) => !v)}
          className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
        >
          <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
          {open ? 'show fewer' : `show all ${hits.length}`}
        </button>
      )}
    </Card>
  )
}

