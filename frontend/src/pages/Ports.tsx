import { useMemo, useState } from 'react'
import type { Finding } from '../api'
import { api } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Empty, PageHeader } from '../components/ui'
import { PortBadge } from '../components/PortBadge'
import { classifyPort, isNotablePort, CATEGORY_META, riskTone, type PortCategory } from '../lib/portIntel'

interface PortRow {
  host: string
  port: number
  service: string | null // from nmap (service/product/version)
  category: PortCategory | 'unknown'
  notable: boolean
}

const RISK_ORDER = { high: 0, medium: 1, low: 2 } as const

// Flatten exposure (IP → ports[]) and nmap (host → openPorts[{service…}]) into a
// single de-duped list of ports across the whole target.
function buildRows(exposure: Finding[], nmap: Finding[]): PortRow[] {
  const byKey = new Map<string, PortRow>()

  const put = (host: string, port: number, service: string | null) => {
    if (!host || !Number.isFinite(port)) return
    const key = `${host}|${port}`
    const info = classifyPort(port)
    const row: PortRow = {
      host,
      port,
      service,
      category: info?.category ?? 'unknown',
      notable: isNotablePort(port),
    }
    const existing = byKey.get(key)
    // Prefer the row that carries an nmap service label.
    if (!existing || (!existing.service && service)) byKey.set(key, row)
  }

  for (const f of exposure) {
    const d = f.data as any
    const host = d.ip ?? d.host ?? ''
    for (const p of (d.ports ?? []) as number[]) put(host, p, null)
  }
  for (const f of nmap) {
    const d = f.data as any
    const host = d.target ?? ''
    for (const op of (d.openPorts ?? []) as any[]) {
      const svc = [op.product, op.version].filter(Boolean).join(' ') || op.service || null
      put(host, Number(op.port), svc)
    }
  }

  return [...byKey.values()].sort((a, b) => {
    const ra = classifyPort(a.port)?.risk ?? 'low'
    const rb = classifyPort(b.port)?.risk ?? 'low'
    return RISK_ORDER[ra] - RISK_ORDER[rb] || a.port - b.port
  })
}

export function Ports() {
  const { selected } = useApp()
  const [exposure, setExposure] = useState<Finding[]>([])
  const [nmap, setNmap] = useState<Finding[]>([])
  const [cat, setCat] = useState<PortCategory | 'all' | 'notable'>('notable')
  const [query, setQuery] = useState('')

  usePoll(
    () => {
      if (!selected) return
      api.findings({ domainId: selected.id, type: 'exposure', limit: 500 }).then((r) => setExposure(r.findings)).catch(() => {})
      api.findings({ domainId: selected.id, type: 'nmap', limit: 500 }).then((r) => setNmap(r.findings)).catch(() => {})
    },
    5000,
    !!selected,
  )

  const rows = useMemo(() => buildRows(exposure, nmap), [exposure, nmap])

  // Which categories are actually present, for the filter chips.
  const present = useMemo(() => {
    const s = new Set<PortCategory>()
    for (const r of rows) if (r.category !== 'unknown') s.add(r.category)
    return [...s]
  }, [rows])

  const q = query.trim().toLowerCase()
  const filtered = useMemo(() => {
    return rows.filter((r) => {
      if (cat === 'notable' && !r.notable) return false
      if (cat !== 'all' && cat !== 'notable' && r.category !== cat) return false
      if (q && !`${r.host} ${r.port} ${r.service ?? ''} ${classifyPort(r.port)?.label ?? ''}`.toLowerCase().includes(q)) return false
      return true
    })
  }, [rows, cat, q])

  const notableCount = rows.filter((r) => r.notable).length

  if (!selected) return <Empty>Select a domain to view its ports.</Empty>

  return (
    <div>
      <PageHeader
        title="Ports"
        subtitle={`${selected.host} — open ports & services across all assets`}
      />

      {/* Summary */}
      <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
        <span className="text-zinc-400">
          <span className="font-semibold text-zinc-200">{rows.length}</span> open port{rows.length === 1 ? '' : 's'}
        </span>
        {notableCount > 0 && (
          <span className="text-amber-300">
            ⚠ <span className="font-semibold">{notableCount}</span> interesting
          </span>
        )}
        <span className="text-xs text-zinc-600">from Exposure (passive) + nmap (active)</span>
      </div>

      {/* Filters */}
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="flex flex-wrap gap-1.5">
          <Chip label={`⚠ Interesting (${notableCount})`} active={cat === 'notable'} onClick={() => setCat('notable')} />
          <Chip label={`All (${rows.length})`} active={cat === 'all'} onClick={() => setCat('all')} />
          {present.map((c) => (
            <Chip
              key={c}
              label={`${CATEGORY_META[c].icon} ${CATEGORY_META[c].label}`}
              active={cat === c}
              onClick={() => setCat(c)}
            />
          ))}
        </div>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search port / host / service…"
          className="rounded-lg border border-hair bg-ink-850 px-3 py-1.5 text-sm outline-none transition placeholder:text-zinc-600 hover:border-hair-strong focus:border-accent-500 sm:ml-auto sm:max-w-xs"
        />
      </div>

      {rows.length === 0 ? (
        <Empty>No port data yet. Run an Exposure scan (passive) or an nmap scan (active) on this target.</Empty>
      ) : filtered.length === 0 ? (
        <Empty>No ports match this filter.</Empty>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-hair">
          <table className="w-full min-w-[640px] text-sm">
            <thead className="bg-ink-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
              <tr>
                <th className="px-3 py-2 w-24">Port</th>
                <th className="px-3 py-2">Host / IP</th>
                <th className="px-3 py-2 w-40">Likely service</th>
                <th className="px-3 py-2 w-44">nmap service</th>
                <th className="px-3 py-2 w-24">Risk</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => {
                const info = classifyPort(r.port)
                return (
                  <tr key={`${r.host}|${r.port}`} className={`border-t border-hair/60 ${r.notable ? 'bg-amber-950/10' : ''}`}>
                    <td className="px-3 py-2">
                      <PortBadge port={r.port} />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-zinc-200 break-all">{r.host}</td>
                    <td className="px-3 py-2 text-xs">
                      {info ? (
                        <span title={info.note}>
                          {r.category !== 'unknown' && <span className="mr-1">{CATEGORY_META[info.category].icon}</span>}
                          <span className="text-zinc-200">{info.label}</span>
                        </span>
                      ) : (
                        <span className="text-zinc-600">unknown</span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-zinc-400 break-all">{r.service ?? '—'}</td>
                    <td className="px-3 py-2">
                      {info ? <Badge tone={riskTone(info.risk)}>{info.risk}</Badge> : <span className="text-xs text-zinc-600">—</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function Chip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-2.5 py-1 text-xs transition ${
        active
          ? 'border-accent-500 bg-accent-500/15 text-accent-fg'
          : 'border-hair text-zinc-400 hover:border-hair-strong hover:text-zinc-200'
      }`}
    >
      {label}
    </button>
  )
}
