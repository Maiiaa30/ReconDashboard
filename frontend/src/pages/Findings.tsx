import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Bot, Sparkles, AlertTriangle } from 'lucide-react'
import { api, type Finding, type FindingStatus, type FindingSummary, type TriageSuggestion } from '../api'
import { useApp } from '../state'
import { Card, Empty, ExportLinks, PageHeader, SkeletonList } from '../components/ui'
import { useToast } from '../components/Toast'
import { summarizeFinding } from '../lib/format'
import { takePendingFindingFilter } from '../lib/navigationHandoff'
import {
  PAGE_SIZE,
  SEVERITY_OPTIONS,
  SINCE_LABEL,
  SINCE_MS,
  SINCE_PRESETS,
  STATUS_FILTER_LABEL,
  STATUS_FILTERS,
  STATUS_LABEL,
  STATUS_SELECT,
  STATUSES,
  TYPE_LABEL,
  TYPE_OPTIONS,
  type SincePreset,
  type StatusFilter,
} from './findings/constants'
import { FindingRow } from './findings/FindingRow'
import { SnapshotsPanel } from './findings/SnapshotsPanel'


export function Findings({ navigate }: { navigate?: (page: string, domainId?: number) => void }) {
  const { domains, selected } = useApp()
  const toast = useToast()
  const [loaded, setLoaded] = useState(false)
  const [domainId, setDomainId] = useState<number | ''>(selected?.id ?? '')
  const [type, setType] = useState('')
  const [sincePreset, setSincePreset] = useState<SincePreset>('')
  const [tagFilter, setTagFilter] = useState('')
  const [assetFilter, setAssetFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('active')
  const [severityFilter, setSeverityFilter] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const [summary, setSummary] = useState<FindingSummary | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const lastIdxRef = useRef<number | null>(null)
  const filteredRef = useRef<Finding[]>([])
  const selectedIdsRef = useRef<Set<number>>(selectedIds)
  selectedIdsRef.current = selectedIds
  // Latest cursor, read by "load more" without re-creating the loader on paging.
  const cursorRef = useRef<string | null>(null)
  cursorRef.current = nextCursor
  const [llmOn, setLlmOn] = useState(false)
  const [narrative, setNarrative] = useState<{ text: string; note: string } | null>(null)
  const [narrBusy, setNarrBusy] = useState(false)
  // AI triage suggestions — suggest-only; nothing is applied until the operator clicks Apply.
  const [suggestions, setSuggestions] = useState<TriageSuggestion[] | null>(null)
  const [aiNote, setAiNote] = useState<string | null>(null)
  const [aiBusy, setAiBusy] = useState(false)
  const [aiApplied, setAiApplied] = useState<Set<number>>(new Set())

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
      const note = e instanceof Error ? e.message : 'failed to generate'
      setNarrative({ text: '', note })
      toast.error(`AI summary failed: ${note}`)
    } finally {
      setNarrBusy(false)
    }
  }

  // Ask the AI for a suggested triage status per finding. Suggest-only: the
  // response never mutates anything — the operator applies rows explicitly.
  async function suggestTriage() {
    if (domainId === '') return
    setAiBusy(true)
    try {
      const r = await api.triageSuggest(Number(domainId))
      setAiApplied(new Set())
      if (!r.enabled || r.suggestions.length === 0) {
        setSuggestions([])
        setAiNote(r.note ?? (r.enabled ? 'No triage suggestions right now.' : 'AI is disabled.'))
      } else {
        setSuggestions(r.suggestions)
        setAiNote(r.note ?? null)
      }
    } catch (e) {
      const note = e instanceof Error ? e.message : 'failed to fetch suggestions'
      toast.error(`AI triage failed: ${note}`)
    } finally {
      setAiBusy(false)
    }
  }

  function dismissSuggestions() {
    setSuggestions(null)
    setAiNote(null)
    setAiApplied(new Set())
  }

  // Apply a single suggestion through the existing optimistic single-triage path.
  function applyOne(s: TriageSuggestion) {
    void update(s.findingId, { status: s.suggestedStatus })
    setAiApplied((prev) => new Set(prev).add(s.findingId))
  }

  // Apply every still-pending suggestion, grouped by status into bulk calls, then
  // clear the panel and refetch so the list reflects the persisted state.
  async function applyAllSuggestions() {
    const pending = (suggestions ?? []).filter((s) => !aiApplied.has(s.findingId))
    if (!pending.length) return
    const groups = new Map<FindingStatus, number[]>()
    for (const s of pending) {
      const arr = groups.get(s.suggestedStatus) ?? []
      arr.push(s.findingId)
      groups.set(s.suggestedStatus, arr)
    }
    try {
      for (const [status, ids] of groups) {
        await api.bulkUpdateFindings(ids, { status })
      }
      toast.success(`Applied ${pending.length} AI suggestion${pending.length > 1 ? 's' : ''}`)
      dismissSuggestions()
      load()
    } catch {
      toast.error('Apply all failed — reverting.')
      load()
    }
  }

  // Follow the header target selection (selecting a domain scopes Findings to it).
  useEffect(() => {
    if (selected) setDomainId(selected.id)
  }, [selected])

  useEffect(() => {
    const pending = takePendingFindingFilter()
    if (!pending) return
    if (pending.domainId != null) setDomainId(pending.domainId)
    setAssetFilter(pending.asset)
    setStatusFilter('all')
  }, [])

  const hostOf = (id: number | null) =>
    id == null ? 'global' : domains.find((d) => d.id === id)?.host ?? `#${id}`

  // Server-side query params for the current filter set. Every facet is pushed to
  // the backend so the page fetches one bounded page instead of the whole table.
  const query = useMemo(
    () => ({
      domainId: domainId === '' ? undefined : domainId,
      type: type || undefined,
      status: statusFilter,
      severity: severityFilter || undefined,
      asset: assetFilter.trim() || undefined,
      tag: tagFilter.trim() || undefined,
      since: sincePreset ? Date.now() - SINCE_MS[sincePreset] : undefined,
    }),
    [domainId, type, statusFilter, severityFilter, assetFilter, tagFilter, sincePreset],
  )

  // Reload the first page for the current filter set. `since` is recomputed here
  // so a stale relative window isn't captured in the memo above.
  const load = useCallback(() => {
    const q = { ...query, since: sincePreset ? Date.now() - SINCE_MS[sincePreset] : undefined, limit: PAGE_SIZE }
    api
      .findings(q)
      .then((r) => {
        setFindings(r.findings)
        setNextCursor(r.nextCursor)
      })
      .catch(() => toast.error('Failed to load findings.'))
      .finally(() => setLoaded(true))
  }, [query, sincePreset, toast])

  // Append the next page using the cursor from the last response.
  const loadMore = useCallback(() => {
    const cursor = cursorRef.current
    if (!cursor || loadingMore) return
    setLoadingMore(true)
    api
      .findings({ ...query, limit: PAGE_SIZE, cursor })
      .then((r) => {
        setFindings((prev) => [...prev, ...r.findings])
        setNextCursor(r.nextCursor)
      })
      .catch(() => toast.error('Failed to load more findings.'))
      .finally(() => setLoadingMore(false))
  }, [query, loadingMore, toast])

  // Facet counts (total + per-status/per-severity), independent of the status and
  // severity filters so the chips show how much sits behind each option.
  const loadSummary = useCallback(() => {
    api
      .findingsSummary({ domainId: query.domainId, type: query.type, asset: query.asset, tag: query.tag, since: query.since })
      .then(setSummary)
      .catch(() => setSummary(null))
  }, [query])

  // Debounced so typing in the tag/asset inputs doesn't fire a request per key.
  useEffect(() => {
    const t = setTimeout(() => void load(), 200)
    return () => clearTimeout(t)
  }, [load])

  useEffect(() => {
    const t = setTimeout(() => void loadSummary(), 200)
    return () => clearTimeout(t)
  }, [loadSummary])

  // Optimistically apply a triage change, then persist; revert via reload on error.
  const update = useCallback(
    async (id: number, patchBody: { status?: FindingStatus; note?: string | null }) => {
      setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, ...patchBody } : f)))
      try {
        await api.updateFinding(id, patchBody)
      } catch {
        toast.error('Update failed — reverting.')
        load()
      }
    },
    [load, toast],
  )

  // Clear selection when the filter set changes (ids may no longer be shown).
  useEffect(() => {
    setSelectedIds(new Set())
    lastIdxRef.current = null
  }, [domainId, type, statusFilter, severityFilter, tagFilter, assetFilter, sincePreset])

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
        toast.success(`${ids.length} finding${ids.length > 1 ? 's' : ''} → ${STATUS_LABEL[status]}`)
      } catch {
        toast.error('Bulk update failed — reverting.')
        load()
      }
    },
    [load, toast],
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

  // Filtering now happens server-side; `findings` is already the filtered page(s).
  // The alias keeps the rest of the render + selection code unchanged.
  const filtered = findings
  filteredRef.current = filtered
  const anyFilterActive =
    tagFilter !== '' || assetFilter !== '' || type !== '' || severityFilter !== '' || domainId !== '' || statusFilter !== 'active' || sincePreset !== ''

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
                    className="inline-flex items-center gap-1.5 rounded-lg border border-accent-500/40 px-2.5 py-1 text-xs text-accent-fg transition hover:bg-accent-500/10 disabled:opacity-50"
                    title="Draft an executive summary with the configured local/cloud AI (sends target + finding summaries)"
                  >
                    <Sparkles size={13} /> {narrBusy ? 'Drafting…' : 'Draft AI summary'}
                  </button>
                )}
              </>
            )}
            <button
              onClick={suggestTriage}
              disabled={domainId === '' || aiBusy}
              className="inline-flex items-center gap-1.5 rounded-lg border border-accent-500/40 px-2.5 py-1 text-xs text-accent-fg transition hover:bg-accent-500/10 disabled:opacity-50"
              title="Ask the configured AI to suggest a triage status per finding for this domain (suggest-only — nothing is applied until you click Apply)"
            >
              <Bot size={13} /> {aiBusy ? 'Thinking…' : 'Suggest triage'}
            </button>
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
          <span className="text-zinc-400">Severity</span>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className={selectCls}>
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s || 'all'} value={s}>
                {s === '' ? 'All' : `${s[0].toUpperCase()}${s.slice(1)}`}
                {s !== '' && summary ? ` (${summary.bySeverity[s] ?? 0})` : ''}
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
        <label className="text-sm">
          <span className="text-zinc-400">Asset</span>
          <input
            value={assetFilter}
            onChange={(e) => setAssetFilter(e.target.value)}
            placeholder="host or IP"
            className="mt-1 block w-44 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
          />
        </label>
        <span className="pb-1.5 text-xs text-zinc-600">
          {findings.length}
          {summary && summary.total > findings.length ? ` of ${summary.total}` : ''} shown
        </span>
        {anyFilterActive && (
          <button
            onClick={() => {
              setTagFilter('')
              setAssetFilter('')
              setType('')
              setSeverityFilter('')
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
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-accent-fg">
              <Sparkles size={13} /> AI-drafted executive summary
            </span>
            <button onClick={() => setNarrative(null)} className="text-xs text-zinc-500 hover:text-zinc-300">
              dismiss
            </button>
          </div>
          {narrative.text ? (
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-zinc-200">{narrative.text}</p>
          ) : (
            <p className="text-sm text-red-400">{narrative.note}</p>
          )}
          {narrative.text && (
            <p className="mt-2 inline-flex items-center gap-1.5 text-[11px] text-amber-400/80">
              <AlertTriangle size={12} /> {narrative.note}
            </p>
          )}
        </div>
      )}

      {domainId !== '' && <SnapshotsPanel domainId={domainId} />}

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

      {suggestions !== null && (
        <Card className="mb-4 border-accent-500/30">
          <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-accent-fg">
              <Bot size={13} /> AI triage suggestions
            </span>
            <div className="flex items-center gap-2">
              {suggestions.length > 0 && (
                <button
                  onClick={applyAllSuggestions}
                  className="rounded-md border border-accent-500/40 px-2 py-0.5 text-xs text-accent-fg transition hover:bg-accent-500/10"
                >
                  Apply all
                </button>
              )}
              <button onClick={dismissSuggestions} className="text-xs text-zinc-500 hover:text-zinc-300">
                Dismiss
              </button>
            </div>
          </div>
          <p className="mb-3 text-[11px] text-zinc-500">
            AI suggestions — review before applying. Nothing changes until you click Apply.
          </p>
          {suggestions.length === 0 ? (
            <p className="text-sm text-zinc-400">{aiNote ?? 'No triage suggestions right now.'}</p>
          ) : (
            <div className="space-y-1.5">
              {suggestions.map((s) => {
                const f = findings.find((x) => x.id === s.findingId)
                const label = f ? summarizeFinding(f.type, f.data) : `#${s.findingId}`
                const applied = aiApplied.has(s.findingId)
                return (
                  <div key={s.findingId} className="rounded-lg border border-hair/60 bg-ink-950/40 px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`shrink-0 rounded-md border px-1.5 py-0.5 text-xs ${STATUS_SELECT[s.suggestedStatus]}`}>
                        {STATUS_LABEL[s.suggestedStatus]}
                      </span>
                      <span className="min-w-0 flex-1 break-all font-mono text-xs text-zinc-100">{label}</span>
                      {applied ? (
                        <span className="shrink-0 text-xs text-green-400">✓ applied</span>
                      ) : (
                        <button
                          onClick={() => applyOne(s)}
                          className="shrink-0 rounded-md border border-accent-500/40 px-2 py-0.5 text-xs text-accent-fg transition hover:bg-accent-500/10"
                        >
                          Apply
                        </button>
                      )}
                    </div>
                    <p className="mt-1 text-xs text-zinc-500">{s.reason}</p>
                    <p className="mt-0.5 text-xs text-zinc-500">Next: {s.nextAction}</p>
                  </div>
                )
              })}
            </div>
          )}
        </Card>
      )}

      {!loaded ? (
        <SkeletonList rows={6} />
      ) : filtered.length === 0 ? (
        <Empty>No findings match these filters.</Empty>
      ) : (
        <>
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
                navigate={navigate}
              />
            ))}
          </div>
          {nextCursor && (
            <div className="mt-3 flex justify-center">
              <button
                onClick={loadMore}
                disabled={loadingMore}
                className="rounded-lg border border-hair px-4 py-1.5 text-sm text-zinc-300 transition hover:border-hair-strong hover:bg-ink-800 disabled:opacity-50"
              >
                {loadingMore ? 'Loading…' : `Load more${summary ? ` (${summary.total - findings.length} more)` : ''}`}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
