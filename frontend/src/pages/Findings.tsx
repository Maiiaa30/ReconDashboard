import { useCallback, useEffect, useRef, useState } from 'react'
import { api, type Finding, type FindingStatus } from '../api'
import { useApp } from '../state'
import { Badge, Button, Empty, ExportLinks, PageHeader } from '../components/ui'
import { riskFromScore, summarizeFinding, timeAgo, type RiskLevel } from '../lib/format'

const STATUSES: FindingStatus[] = ['open', 'confirmed', 'false_positive', 'resolved', 'ignored']
const STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Open',
  confirmed: 'Confirmed',
  false_positive: 'False positive',
  resolved: 'Resolved',
  ignored: 'Ignored',
}
// Per-status select styling (border + text) for at-a-glance triage state.
const STATUS_SELECT: Record<FindingStatus, string> = {
  open: 'text-blue-300 border-blue-900/60',
  confirmed: 'text-red-300 border-red-900/60',
  false_positive: 'text-zinc-400 border-hair',
  resolved: 'text-green-300 border-green-900/60',
  ignored: 'text-zinc-500 border-hair',
}
// Statuses that are "dealt with" — dimmed and hidden from the default Active view.
const TRIAGED_AWAY: FindingStatus[] = ['false_positive', 'resolved', 'ignored']

const STATUS_FILTERS = ['active', 'all', ...STATUSES] as const
type StatusFilter = (typeof STATUS_FILTERS)[number]
const STATUS_FILTER_LABEL: Record<StatusFilter, string> = { active: 'Active', all: 'All', ...STATUS_LABEL }

const TYPE_OPTIONS = ['', 'new_subdomain', 'exposure', 'osint', 'origin', 'nmap', 'nuclei', 'ffuf'] as const

// "New since" presets — filters to findings first discovered within the window
// (createdAt is the frozen first-seen timestamp, so re-scans of unchanged
// findings never re-enter the list).
const SINCE_PRESETS = ['', '24h', '7d', '30d'] as const
type SincePreset = (typeof SINCE_PRESETS)[number]
const SINCE_LABEL: Record<SincePreset, string> = {
  '': 'Any time',
  '24h': 'Last 24h',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
}
const SINCE_MS: Record<Exclude<SincePreset, ''>, number> = {
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
}

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
  const { domains, selected } = useApp()
  const [domainId, setDomainId] = useState<number | ''>(selected?.id ?? '')
  const [type, setType] = useState('')
  const [sincePreset, setSincePreset] = useState<SincePreset>('')
  const [tagFilter, setTagFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('active')
  const [findings, setFindings] = useState<Finding[]>([])
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const lastIdxRef = useRef<number | null>(null)
  const filteredRef = useRef<Finding[]>([])
  const selectedIdsRef = useRef<Set<number>>(selectedIds)
  selectedIdsRef.current = selectedIds
  const [llmOn, setLlmOn] = useState(false)
  const [narrative, setNarrative] = useState<{ text: string; note: string } | null>(null)
  const [narrBusy, setNarrBusy] = useState(false)

  useEffect(() => {
    api.meta().then((m) => setLlmOn(Boolean(m.llm?.enabled))).catch(() => {})
  }, [])

  async function draftNarrative() {
    if (domainId === '') return
    setNarrBusy(true)
    try {
      const r = await api.generateNarrative(domainId)
      setNarrative({ text: r.narrative, note: r.note })
    } catch (e) {
      setNarrative({ text: '', note: e instanceof Error ? e.message : 'failed to generate' })
    } finally {
      setNarrBusy(false)
    }
  }

  // Follow the header target selection (selecting a domain scopes Findings to it).
  useEffect(() => {
    if (selected) setDomainId(selected.id)
  }, [selected])

  const hostOf = (id: number | null) =>
    id == null ? 'global' : domains.find((d) => d.id === id)?.host ?? `#${id}`

  const load = useCallback(() => {
    const since = sincePreset ? Date.now() - SINCE_MS[sincePreset] : undefined
    api
      .findings({ domainId: domainId === '' ? undefined : domainId, type: type || undefined, since, limit: 500 })
      .then((r) => setFindings(r.findings))
      .catch(() => {})
  }, [domainId, type, sincePreset])

  useEffect(() => {
    void load()
  }, [load])

  // Optimistically apply a triage change, then persist; revert via reload on error.
  const update = useCallback(
    async (id: number, patchBody: { status?: FindingStatus; note?: string | null }) => {
      setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, ...patchBody } : f)))
      try {
        await api.updateFinding(id, patchBody)
      } catch {
        load()
      }
    },
    [load],
  )

  // Clear selection when the filter set changes (ids may no longer be shown).
  useEffect(() => {
    setSelectedIds(new Set())
    lastIdxRef.current = null
  }, [domainId, type, statusFilter, tagFilter, sincePreset])

  const toggleSelect = useCallback((id: number, idx: number, range: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (range && lastIdxRef.current != null) {
        const [a, b] = [lastIdxRef.current, idx].sort((x, y) => x - y)
        for (let i = a; i <= b; i++) {
          const fid = filteredRef.current[i]?.id
          if (fid != null) next.add(fid)
        }
      } else if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
    lastIdxRef.current = idx
  }, [])

  const clearSelection = useCallback(() => setSelectedIds(new Set()), [])
  const selectAllFiltered = useCallback(() => setSelectedIds(new Set(filteredRef.current.map((f) => f.id))), [])

  const bulkApply = useCallback(
    async (status: FindingStatus) => {
      const ids = [...selectedIdsRef.current]
      if (!ids.length) return
      const idSet = new Set(ids)
      setFindings((prev) => prev.map((f) => (idSet.has(f.id) ? { ...f, status } : f)))
      setSelectedIds(new Set())
      try {
        await api.bulkUpdateFindings(ids, { status })
      } catch {
        load()
      }
    },
    [load],
  )

  // Keyboard triage: o/c/f/r/i set status on the selection, a = select all, esc = clear.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.key === 'Escape') return clearSelection()
      if (e.key.toLowerCase() === 'a') {
        e.preventDefault()
        return selectAllFiltered()
      }
      if (selectedIdsRef.current.size === 0) return
      const map: Record<string, FindingStatus> = { o: 'open', c: 'confirmed', f: 'false_positive', r: 'resolved', i: 'ignored' }
      const st = map[e.key.toLowerCase()]
      if (st) {
        e.preventDefault()
        void bulkApply(st)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [bulkApply, clearSelection, selectAllFiltered])

  const tagQuery = tagFilter.trim().toLowerCase()
  const matchesStatus = (f: Finding) =>
    statusFilter === 'all'
      ? true
      : statusFilter === 'active'
        ? !TRIAGED_AWAY.includes(f.status)
        : f.status === statusFilter
  const filtered = findings.filter(
    (f) => matchesStatus(f) && (tagQuery ? f.tags.some((t) => t.toLowerCase().includes(tagQuery)) : true),
  )
  filteredRef.current = filtered

  const selectCls =
    'mt-1 block rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500'

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle="Scored, highest priority first"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {domainId !== '' && (
              <>
                <a
                  href={`/api/domains/${domainId}/report`}
                  className="rounded-lg border border-hair px-2.5 py-1 text-xs text-zinc-300 transition hover:border-hair-strong hover:bg-ink-800"
                  title="Download a Markdown engagement report for this domain"
                >
                  Report (MD)
                </a>
                <a
                  href={`/api/domains/${domainId}/report?format=html`}
                  className="rounded-lg border border-hair px-2.5 py-1 text-xs text-zinc-300 transition hover:border-hair-strong hover:bg-ink-800"
                  title="Download a self-contained HTML report (open it and Ctrl-P → Save as PDF)"
                >
                  Report (HTML/PDF)
                </a>
                {llmOn && (
                  <button
                    onClick={draftNarrative}
                    disabled={narrBusy}
                    className="rounded-lg border border-accent-500/40 px-2.5 py-1 text-xs text-accent-fg transition hover:bg-accent-500/10 disabled:opacity-50"
                    title="Draft an executive summary with the configured local/cloud AI (sends target + finding summaries)"
                  >
                    {narrBusy ? 'Drafting…' : '✨ Draft AI summary'}
                  </button>
                )}
              </>
            )}
            <ExportLinks
              path="/findings/export"
              params={{ domainId: domainId === '' ? undefined : domainId, type: type || undefined }}
              formats={['csv', 'json']}
            />
          </div>
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
          <span className="text-zinc-400">Status</span>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as StatusFilter)} className={selectCls}>
            {STATUS_FILTERS.map((s) => (
              <option key={s} value={s}>
                {STATUS_FILTER_LABEL[s]}
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
          <span className="text-zinc-400">New since</span>
          <select value={sincePreset} onChange={(e) => setSincePreset(e.target.value as SincePreset)} className={selectCls}>
            {SINCE_PRESETS.map((s) => (
              <option key={s || 'any'} value={s}>
                {SINCE_LABEL[s]}
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
            className="mt-1 block w-56 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
          />
        </label>
        <span className="pb-1.5 text-xs text-zinc-600">{filtered.length} shown</span>
        {(tagFilter || type || domainId !== '' || statusFilter !== 'active' || sincePreset !== '') && (
          <button
            onClick={() => {
              setTagFilter('')
              setType('')
              setDomainId('')
              setStatusFilter('active')
              setSincePreset('')
            }}
            className="pb-1.5 text-xs text-zinc-500 hover:text-zinc-300"
          >
            clear filters
          </button>
        )}
      </div>

      {narrative && (
        <div className="mb-4 rounded-xl border border-accent-500/30 bg-ink-900/60 p-4">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wide text-accent-fg">AI-drafted executive summary</span>
            <button onClick={() => setNarrative(null)} className="text-xs text-zinc-500 hover:text-zinc-300">
              dismiss
            </button>
          </div>
          {narrative.text ? (
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-zinc-200">{narrative.text}</p>
          ) : (
            <p className="text-sm text-red-400">{narrative.note}</p>
          )}
          {narrative.text && <p className="mt-2 text-[11px] text-amber-400/80">⚠ {narrative.note}</p>}
        </div>
      )}

      {selectedIds.size > 0 && (
        <div className="sticky top-0 z-10 mb-2 flex flex-wrap items-center gap-2 rounded-lg border border-accent-500/40 bg-ink-900/95 px-3 py-2 text-sm backdrop-blur">
          <span className="font-medium text-accent-fg">{selectedIds.size} selected</span>
          <span className="text-zinc-500">set status:</span>
          {STATUSES.map((s) => (
            <button
              key={s}
              onClick={() => bulkApply(s)}
              className="rounded-md border border-hair px-2 py-0.5 text-xs text-zinc-200 hover:bg-ink-800"
            >
              {STATUS_LABEL[s]}
            </button>
          ))}
          <button onClick={selectAllFiltered} className="ml-auto text-xs text-zinc-400 hover:text-zinc-200">
            select all {filtered.length}
          </button>
          <button onClick={clearSelection} className="text-xs text-zinc-500 hover:text-zinc-300">
            clear
          </button>
          <span className="hidden text-[10px] text-zinc-600 sm:inline">keys: o/c/f/r/i · a=all · esc</span>
        </div>
      )}

      {filtered.length === 0 ? (
        <Empty>No findings match these filters.</Empty>
      ) : (
        <div className="space-y-2">
          {filtered.map((f, idx) => (
            <FindingRow
              key={f.id}
              f={f}
              idx={idx}
              host={hostOf(f.domainId)}
              selected={selectedIds.has(f.id)}
              onToggleSelect={toggleSelect}
              onTag={setTagFilter}
              onUpdate={update}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function FindingRow({
  f,
  idx,
  host,
  selected,
  onToggleSelect,
  onTag,
  onUpdate,
}: {
  f: Finding
  idx: number
  host: string
  selected: boolean
  onToggleSelect: (id: number, idx: number, range: boolean) => void
  onTag: (t: string) => void
  onUpdate: (id: number, patch: { status?: FindingStatus; note?: string | null }) => void
}) {
  const [showAllTags, setShowAllTags] = useState(false)
  const [open, setOpen] = useState(false)
  const risk = riskFromScore(f.score)
  const tags = f.tags ?? []
  const shownTags = showAllTags ? tags : tags.slice(0, 7)
  const dimmed = TRIAGED_AWAY.includes(f.status)

  return (
    <div className={`rounded-xl border border-l-4 border-hair bg-ink-850/60 ${RISK_BORDER[risk]} ${dimmed ? 'opacity-60' : ''} ${selected ? 'ring-1 ring-accent-500/50' : ''}`}>
      <div className="flex items-start gap-3 p-3">
        <input
          type="checkbox"
          checked={selected}
          onChange={() => {}}
          onClick={(e) => {
            e.stopPropagation()
            onToggleSelect(f.id, idx, e.shiftKey)
          }}
          title="select (shift-click for range)"
          className="mt-2.5 h-4 w-4 shrink-0 cursor-pointer accent-accent-500"
        />
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-sm font-semibold ring-1 ${RISK_SCORE[risk]}`}>
          {f.score ?? '—'}
        </div>

        <div
          onClick={() => setOpen((v) => !v)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              setOpen((v) => !v)
            }
          }}
          className="min-w-0 flex-1 cursor-pointer text-left"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="zinc">{TYPE_LABEL[f.type] ?? f.type}</Badge>
            <span className="min-w-0 break-all font-mono text-sm text-zinc-100">{summarizeFinding(f.type, f.data)}</span>
            <span className="text-xs text-zinc-600">{open ? '▾' : '▸'}</span>
          </div>
          {tags.length > 0 && (
            <div className="mt-1.5 flex flex-wrap items-center gap-1">
              {shownTags.map((t) => (
                <button
                  key={t}
                  onClick={(e) => {
                    e.stopPropagation()
                    onTag(t)
                  }}
                  title="filter by this tag"
                >
                  <Badge tone={tagTone(t)}>{t}</Badge>
                </button>
              ))}
              {!showAllTags && tags.length > 7 && (
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    setShowAllTags(true)
                  }}
                  className="text-[10px] text-zinc-500 hover:text-zinc-300"
                >
                  +{tags.length - 7} more
                </button>
              )}
            </div>
          )}
        </div>

        <div className="flex shrink-0 flex-col items-end gap-1 text-right text-xs text-zinc-500">
          <select
            value={f.status}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => onUpdate(f.id, { status: e.target.value as FindingStatus })}
            title="triage status"
            className={`cursor-pointer rounded-md border bg-ink-950 px-1.5 py-0.5 text-xs outline-none focus:border-accent-500 ${STATUS_SELECT[f.status]}`}
          >
            {STATUSES.map((s) => (
              <option key={s} value={s} className="text-zinc-200">
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
          <div className="font-mono text-zinc-400">{host}</div>
          <div>{timeAgo(new Date(f.createdAt).getTime())}</div>
        </div>
      </div>

      {open && <FindingDetail f={f} onUpdate={onUpdate} />}
    </div>
  )
}

function Detail({ label, value }: { label: string; value: React.ReactNode }) {
  if (value == null || value === '' || (Array.isArray(value) && value.length === 0)) return null
  return (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 text-xs uppercase tracking-wide text-zinc-600">{label}</span>
      <span className="min-w-0 break-all text-zinc-300">{value}</span>
    </div>
  )
}

// "Why this score" — the scorer's reasons, stored on the finding data.
function ScoreReasons({ score, reasons }: { score: number | null; reasons: unknown }) {
  if (!Array.isArray(reasons) || reasons.length === 0) return null
  return (
    <div className="rounded-lg border border-hair bg-ink-900/60 p-2.5">
      <div className="mb-1.5 text-xs uppercase tracking-wide text-zinc-500">
        Why this scored {score ?? '—'}
      </div>
      <ul className="space-y-1">
        {(reasons as string[]).map((r, i) => (
          <li key={i} className="flex gap-2 text-xs text-zinc-300">
            <span className="text-accent-400">•</span>
            <span>{r}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

interface CveLike { cve_id: string; summary?: string; cvss?: number; cvss_v3?: number; kev?: boolean }

function CveList({ cves, vulns }: { cves: unknown; vulns: unknown }) {
  const list: CveLike[] = Array.isArray(cves) && cves.length
    ? (cves as CveLike[])
    : Array.isArray(vulns)
      ? (vulns as string[]).map((id) => ({ cve_id: id }))
      : []
  if (!list.length) return null
  return (
    <div>
      <div className="mb-1 text-xs uppercase tracking-wide text-zinc-600">CVEs ({list.length})</div>
      <div className="space-y-1">
        {list.map((c) => {
          const cvss = c.cvss_v3 ?? c.cvss
          const tone = cvss == null ? 'zinc' : cvss >= 9 ? 'red' : cvss >= 7 ? 'amber' : cvss >= 4 ? 'blue' : 'zinc'
          return (
            <div key={c.cve_id} className="flex flex-wrap items-center gap-2 text-xs">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve_id)}`}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-sky-400 hover:underline"
              >
                {c.cve_id}
              </a>
              {cvss != null && <Badge tone={tone}>CVSS {cvss}</Badge>}
              {c.kev && <Badge tone="red">KEV — exploited</Badge>}
              {c.summary && <span className="min-w-0 flex-1 truncate text-zinc-500">{c.summary}</span>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function NoteEditor({ f, onUpdate }: { f: Finding; onUpdate: (id: number, patch: { note?: string | null }) => void }) {
  const [note, setNote] = useState(f.note ?? '')
  const dirty = note !== (f.note ?? '')
  return (
    <div className="space-y-1">
      <span className="text-xs uppercase tracking-wide text-zinc-600">Triage note</span>
      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="why confirmed / false-positive, repro steps, links…"
        rows={2}
        className="block w-full rounded-lg border border-hair bg-ink-950 px-2.5 py-1.5 text-sm outline-none focus:border-accent-500"
      />
      {dirty && (
        <div className="flex gap-1.5">
          <Button variant="loud" className="px-2 py-1 text-xs" onClick={() => onUpdate(f.id, { note: note.trim() || null })}>
            Save note
          </Button>
          <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => setNote(f.note ?? '')}>
            Reset
          </Button>
        </div>
      )}
    </div>
  )
}

function FindingDetail({ f, onUpdate }: { f: Finding; onUpdate: (id: number, patch: { status?: FindingStatus; note?: string | null }) => void }) {
  const d = f.data ?? {}
  return (
    <div className="space-y-3 border-t border-hair/60 bg-ink-900/50 p-3 text-sm">
      <ScoreReasons score={f.score} reasons={d._scoreReasons} />
      <div className="space-y-1">
        {f.type === 'new_subdomain' && (
          <>
            <Detail label="Host" value={<span className="font-mono">{d.host}</span>} />
            <Detail label="HTTP" value={d.status != null ? `${d.status}` : 'no response'} />
            <Detail label="Title" value={d.title} />
            <Detail label="Server" value={d.server} />
            <Detail label="IP" value={<span className="font-mono">{d.ip}</span>} />
            <Detail label="CNAMEs" value={Array.isArray(d.cnames) && d.cnames.length ? d.cnames.join(', ') : null} />
            {d.takeover?.service && (
              <Detail label="Takeover" value={<span className="text-red-400">candidate: {d.takeover.service} ({d.takeover.cname})</span>} />
            )}
            {d.status != null && d.scheme && (
              <Detail
                label="Open"
                value={
                  <a href={`${d.scheme}://${d.host}`} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">
                    {d.scheme}://{d.host} ↗
                  </a>
                }
              />
            )}
          </>
        )}
        {f.type === 'exposure' && (
          <>
            <Detail label="IP" value={<span className="font-mono">{d.ip}</span>} />
            <Detail label="Hostnames" value={Array.isArray(d.hostnames) ? d.hostnames.join(', ') : null} />
            <Detail label="Ports" value={Array.isArray(d.ports) ? d.ports.join(', ') : null} />
            <Detail label="CPEs" value={Array.isArray(d.cpes) ? d.cpes.join(', ') : null} />
            <CveList cves={d.cves} vulns={d.vulns} />
          </>
        )}
        {f.type === 'origin' && (
          <>
            <Detail label="WAF/CDN" value={d.provider ?? 'none'} />
            <Detail label="Apex IP" value={<span className="font-mono">{d.apexIp}</span>} />
            <Detail
              label="Origins"
              value={(d.confirmedOrigins ?? []).map((o: any) => o.ip).join(', ') || null}
            />
          </>
        )}
        {(f.type === 'nuclei' || f.type === 'nmap' || f.type === 'ffuf' || f.type === 'osint') && (
          <>
            <Detail label="Target" value={<span className="font-mono">{d.target ?? d.domain}</span>} />
            <Detail label="Name" value={d.name} />
            <Detail label="Severity" value={d.severity} />
            <Detail label="Matched" value={d.matched ? <span className="font-mono">{d.matched}</span> : null} />
            <Detail label="URL" value={d.url ? <span className="font-mono">{d.url}</span> : null} />
          </>
        )}
      </div>
      <NoteEditor f={f} onUpdate={onUpdate} />

      <details>
        <summary className="cursor-pointer text-xs text-zinc-500 hover:text-zinc-300">raw data</summary>
        <pre className="mt-1 max-h-72 overflow-auto whitespace-pre-wrap break-all text-xs text-zinc-400">
          {JSON.stringify(f.data, null, 2)}
        </pre>
      </details>
    </div>
  )
}
