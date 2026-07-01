import { useCallback, useEffect, useState } from 'react'
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
  const [tagFilter, setTagFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('active')
  const [findings, setFindings] = useState<Finding[]>([])

  // Follow the header target selection (selecting a domain scopes Findings to it).
  useEffect(() => {
    if (selected) setDomainId(selected.id)
  }, [selected])

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
          <span className="text-zinc-400">Filter by tag</span>
          <input
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            placeholder="kev, admin-port, takeover…"
            className="mt-1 block w-56 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
          />
        </label>
        <span className="pb-1.5 text-xs text-zinc-600">{filtered.length} shown</span>
        {(tagFilter || type || domainId !== '' || statusFilter !== 'active') && (
          <button
            onClick={() => {
              setTagFilter('')
              setType('')
              setDomainId('')
              setStatusFilter('active')
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
            <FindingRow key={f.id} f={f} host={hostOf(f.domainId)} onTag={setTagFilter} onUpdate={update} />
          ))}
        </div>
      )}
    </div>
  )
}

function FindingRow({
  f,
  host,
  onTag,
  onUpdate,
}: {
  f: Finding
  host: string
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
    <div className={`rounded-xl border border-l-4 border-hair bg-ink-850/60 ${RISK_BORDER[risk]} ${dimmed ? 'opacity-60' : ''}`}>
      <div className="flex items-start gap-3 p-3">
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
