import { useState } from 'react'
import { Route, ChevronRight } from 'lucide-react'
import { Badge, Card } from '../../components/ui'

export function CrawlCard({ urls }: { urls: string[] }) {
  const [open, setOpen] = useState(false)
  const shown = open ? urls : urls.slice(0, 15)
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
        <Route size={16} className="text-blue-400" />
        <Badge tone="blue">katana crawl</Badge>
        <span className="text-sm font-medium text-zinc-100">{urls.length} API-looking URL(s) discovered</span>
      </div>
      <div className="mt-1 text-xs text-zinc-500">
        Active crawl (follows links + parses JS) — finds endpoints static analysis can&apos;t, e.g. dynamically-built ones.
      </div>
      <div className="mt-2.5 space-y-0.5">
        {shown.map((u, i) => (
          <div key={i} className="font-mono text-[11px] text-zinc-300 break-all">
            {fmt(u)}
          </div>
        ))}
      </div>
      {urls.length > 15 && (
        <button
          onClick={() => setOpen((v) => !v)}
          className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
        >
          <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
          {open ? 'show fewer' : `show all ${urls.length}`}
        </button>
      )}
    </Card>
  )
}
