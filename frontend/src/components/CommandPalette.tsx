import { useEffect, useMemo, useRef, useState } from 'react'
import { Search, CornerDownLeft, Globe, Flag, LayoutGrid } from 'lucide-react'
import { api, type Domain, type Finding } from '../api'
import { summarizeFinding } from '../lib/format'

interface PaletteItem {
  id: string
  kind: 'module' | 'domain' | 'finding'
  label: string
  sub?: string
  run: () => void
}

// Ctrl/⌘-K launcher: fuzzy-jump to any page or domain, and search findings across
// every target. Keeps navigation fast now that there are 20+ modules.
export function CommandPalette({
  open,
  onClose,
  modules,
  domains,
  navigate,
}: {
  open: boolean
  onClose: () => void
  modules: { key: string; label: string; section: string }[]
  domains: Domain[]
  navigate: (page: string, domainId?: number) => void
}) {
  const [query, setQuery] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])
  const [sel, setSel] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // On open: reset, focus, and lazily pull a bounded set of findings to search.
  useEffect(() => {
    if (!open) return
    setQuery('')
    setSel(0)
    const t = setTimeout(() => inputRef.current?.focus(), 0)
    api
      .findings({ limit: 300 })
      .then((r) => setFindings(r.findings))
      .catch(() => {})
    return () => clearTimeout(t)
  }, [open])

  const hostOf = (id: number | null) => (id == null ? 'global' : domains.find((d) => d.id === id)?.host ?? `#${id}`)

  const q = query.trim().toLowerCase()
  const items: PaletteItem[] = useMemo(() => {
    const out: PaletteItem[] = []
    for (const m of modules) {
      if (!q || m.label.toLowerCase().includes(q) || m.section.toLowerCase().includes(q)) {
        out.push({ id: `m:${m.key}`, kind: 'module', label: m.label, sub: m.section, run: () => navigate(m.key) })
      }
    }
    for (const d of domains) {
      if (!q || d.host.toLowerCase().includes(q)) {
        out.push({
          id: `d:${d.id}`,
          kind: 'domain',
          label: d.host,
          sub: d.mode === 'active_authorized' ? 'active' : 'passive',
          run: () => navigate('intel', d.id),
        })
      }
    }
    // Findings only surface once you type — otherwise they'd bury pages/domains.
    if (q.length >= 2) {
      for (const f of findings) {
        const s = summarizeFinding(f.type, f.data)
        if (s.toLowerCase().includes(q) || f.type.toLowerCase().includes(q)) {
          out.push({
            id: `f:${f.id}`,
            kind: 'finding',
            label: s,
            sub: `${f.type} · ${hostOf(f.domainId)}`,
            run: () => navigate('findings', f.domainId ?? undefined),
          })
          if (out.length > 60) break
        }
      }
    }
    return out.slice(0, 50)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, modules, domains, findings])

  useEffect(() => setSel(0), [q])
  useEffect(() => {
    listRef.current?.querySelector('[data-sel="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [sel])

  if (!open) return null

  const choose = (i: number) => {
    const it = items[i]
    if (it) {
      it.run()
      onClose()
    }
  }

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSel((s) => Math.min(s + 1, items.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSel((s) => Math.max(s - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      choose(sel)
    } else if (e.key === 'Escape') {
      onClose()
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 pt-[12vh] backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-xl border border-hair bg-ink-900 shadow-pop"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-hair px-3">
          <Search size={16} className="shrink-0 text-zinc-500" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKey}
            placeholder="Jump to a page, domain, or finding…"
            className="w-full bg-transparent py-3 text-sm text-zinc-100 outline-none placeholder:text-zinc-600"
          />
          <kbd className="shrink-0 rounded bg-ink-800 px-1.5 py-0.5 text-[10px] text-zinc-500">esc</kbd>
        </div>
        <div ref={listRef} className="max-h-[52vh] overflow-y-auto py-1">
          {items.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-zinc-500">No matches.</div>
          ) : (
            items.map((it, i) => (
              <button
                key={it.id}
                data-sel={i === sel}
                onMouseMove={() => setSel(i)}
                onClick={() => choose(i)}
                className={`flex w-full items-center gap-3 px-3 py-2 text-left text-sm transition ${
                  i === sel ? 'bg-accent-500/15' : ''
                }`}
              >
                <PaletteIcon kind={it.kind} />
                <span className={`min-w-0 flex-1 truncate ${it.kind === 'finding' ? 'font-mono text-xs' : ''} text-zinc-100`}>
                  {it.label}
                </span>
                {it.sub && <span className="shrink-0 text-xs text-zinc-500">{it.sub}</span>}
                {i === sel && <CornerDownLeft size={13} className="shrink-0 text-zinc-600" />}
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

function PaletteIcon({ kind }: { kind: PaletteItem['kind'] }) {
  const cls = 'shrink-0'
  if (kind === 'domain') return <Globe size={15} className={`${cls} text-blue-400`} />
  if (kind === 'finding') return <Flag size={15} className={`${cls} text-amber-400`} />
  return <LayoutGrid size={15} className={`${cls} text-zinc-500`} />
}
