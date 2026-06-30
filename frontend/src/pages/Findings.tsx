import { useCallback, useEffect, useState } from 'react'
import { api, type Finding } from '../api'
import { useApp } from '../state'
import { Badge, Empty, ExportLinks, PageHeader } from '../components/ui'
import { riskFromScore, summarizeFinding, timeAgo, type RiskLevel } from '../lib/format'

const TYPE_OPTIONS = ['', 'new_subdomain', 'exposure', 'osint', 'origin', 'nmap', 'nuclei', 'ffuf'] as const

const TYPE_LABEL: Record<string, string> = {
  new_subdomain: 'subdomain',
  exposure: 'exposure',
  osint: 'osint',
  origin: 'origin',
  nmap: 'nmap',
  nuclei: 'nuclei',
  ffuf: 'ffuf',
}

// Left-border + score colors by risk level — the at-a-glance signal.
const RISK_BORDER: Record<RiskLevel, string> = {
  high: 'border-l-red-500',
  medium: 'border-l-amber-500',
  low: 'border-l-blue-500',
  none: 'border-l-zinc-700',
}
const RISK_SCORE: Record<RiskLevel, string> = {
  high: 'bg-red-950 text-red-300 ring-red-800',
  medium: 'bg-amber-950 text-amber-300 ring-amber-800',
  low: 'bg-blue-950 text-blue-300 ring-blue-800',
  none: 'bg-zinc-800 text-zinc-400 ring-zinc-700',
}

function tagTone(tag: string): 'zinc' | 'blue' | 'amber' | 'red' | 'green' {
  if (/^(kev|cvss:critical|sev:critical|takeover|db-exposed|zone-transfer|origin-found)/.test(tag)) return 'red'
  if (/^(cvss:high|sev:high|admin-port|admin-surface|has-cve|auth-gated|waf:|kw:)/.test(tag)) return 'amber'
  if (/^(tech:|svc:|owasp:|shodan:)/.test(tag)) return 'blue'
  if (tag === 'live' || tag === 'http-2xx') return 'green'
  return 'zinc'
}

export function Findings() {
  const { domains } = useApp()
  const [domainId, setDomainId] = useState<number | ''>('')
  const [type, setType] = useState('')
  const [tagFilter, setTagFilter] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])

  const hostOf = (id: number | null) =>
    id == null ? 'global' : domains.find((d) => d.id === id)?.host ?? `#${id}`

  const load = useCallback(() => {
    api
      .findings({ domainId: domainId === '' ? undefined : domainId, type: type || undefined, limit: 500 })
      .then((r) => setFindings(r.findings))
      .catch(() => {})
  }, [domainId, type])

  useEffect(() => {
    void load()
  }, [load])

  const tagQuery = tagFilter.trim().toLowerCase()
  const filtered = tagQuery
    ? findings.filter((f) => f.tags.some((t) => t.toLowerCase().includes(tagQuery)))
    : findings

  const selectCls =
    'mt-1 block rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500'

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle="Scored, highest priority first"
        actions={
          <ExportLinks
            path="/findings/export"
            params={{ domainId: domainId === '' ? undefined : domainId, type: type || undefined }}
            formats={['csv', 'json']}
          />
        }
      />

      <div className="mb-4 flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="text-zinc-400">Domain</span>
          <select value={domainId} onChange={(e) => setDomainId(e.target.value === '' ? '' : Number(e.target.value))} className={selectCls}>
            <option value="">All domains</option>
            {domains.map((d) => (
              <option key={d.id} value={d.id}>
                {d.host}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="text-zinc-400">Type</span>
          <select value={type} onChange={(e) => setType(e.target.value)} className={selectCls}>
            {TYPE_OPTIONS.map((t) => (
              <option key={t || 'all'} value={t}>
                {t === '' ? 'All' : TYPE_LABEL[t] ?? t}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="text-zinc-400">Filter by tag</span>
          <input
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            placeholder="kev, admin-port, takeover…"
            className="mt-1 block w-56 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
          />
        </label>
        <span className="pb-1.5 text-xs text-zinc-600">{filtered.length} shown</span>
        {(tagFilter || type || domainId !== '') && (
          <button
            onClick={() => {
              setTagFilter('')
              setType('')
              setDomainId('')
            }}
            className="pb-1.5 text-xs text-zinc-500 hover:text-zinc-300"
          >
            clear filters
          </button>
        )}
      </div>

      {filtered.length === 0 ? (
        <Empty>No findings match these filters.</Empty>
      ) : (
        <div className="space-y-2">
          {filtered.map((f) => (
            <FindingRow key={f.id} f={f} host={hostOf(f.domainId)} onTag={setTagFilter} />
          ))}
        </div>
      )}
    </div>
  )
}

function FindingRow({ f, host, onTag }: { f: Finding; host: string; onTag: (t: string) => void }) {
  const [showAllTags, setShowAllTags] = useState(false)
  const risk = riskFromScore(f.score)
  const tags = f.tags ?? []
  const shownTags = showAllTags ? tags : tags.slice(0, 7)

  return (
    <div className={`flex items-start gap-3 rounded-xl border border-l-4 border-zinc-800 bg-zinc-900/40 p-3 ${RISK_BORDER[risk]}`}>
      <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-sm font-semibold ring-1 ${RISK_SCORE[risk]}`}>
        {f.score ?? '—'}
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="zinc">{TYPE_LABEL[f.type] ?? f.type}</Badge>
          <span className="min-w-0 break-all font-mono text-sm text-zinc-100">{summarizeFinding(f.type, f.data)}</span>
        </div>
        {tags.length > 0 && (
          <div className="mt-1.5 flex flex-wrap items-center gap-1">
            {shownTags.map((t) => (
              <button key={t} onClick={() => onTag(t)} title="filter by this tag">
                <Badge tone={tagTone(t)}>{t}</Badge>
              </button>
            ))}
            {!showAllTags && tags.length > 7 && (
              <button onClick={() => setShowAllTags(true)} className="text-[10px] text-zinc-500 hover:text-zinc-300">
                +{tags.length - 7} more
              </button>
            )}
          </div>
        )}
      </div>

      <div className="shrink-0 text-right text-xs text-zinc-500">
        <div className="font-mono text-zinc-400">{host}</div>
        <div>{timeAgo(new Date(f.createdAt).getTime())}</div>
      </div>
    </div>
  )
}
