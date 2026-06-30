import { FormEvent, useCallback, useState } from 'react'
import { api, ApiError, type DomainMode, type DomainOverview } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { riskFromScore, timeAgo } from '../lib/format'

const RISK_STYLES: Record<string, { dot: string; label: string; tone: 'zinc' | 'blue' | 'amber' | 'red' }> = {
  none: { dot: 'bg-zinc-600', label: 'no signal', tone: 'zinc' },
  low: { dot: 'bg-blue-500', label: 'low', tone: 'blue' },
  medium: { dot: 'bg-amber-500', label: 'medium', tone: 'amber' },
  high: { dot: 'bg-red-500', label: 'high', tone: 'red' },
}

export function Domains() {
  const { refreshDomains, select, selectedId } = useApp()
  const [overview, setOverview] = useState<DomainOverview[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [busyAction, setBusyAction] = useState<string | null>(null)

  const load = useCallback(() => {
    api.domainsOverview().then((r) => setOverview(r.overview)).catch(() => {})
  }, [])

  // Poll so cards update live while jobs run.
  usePoll(load, 5000)

  return (
    <div>
      <PageHeader
        title="Domains"
        subtitle="Your targets at a glance. Active/loud scans require active_authorized."
        actions={
          <Button variant={showAdd ? 'ghost' : 'default'} onClick={() => setShowAdd((v) => !v)}>
            {showAdd ? 'Close' : '+ Add domain'}
          </Button>
        }
      />

      {showAdd && (
        <AddDomainForm
          onAdded={async () => {
            setShowAdd(false)
            await refreshDomains()
            load()
          }}
        />
      )}

      {overview.length === 0 ? (
        <Empty>No domains yet. Click “+ Add domain” to start recon.</Empty>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {overview.map((d) => (
            <DomainCard
              key={d.id}
              d={d}
              selected={selectedId === d.id}
              busyAction={busyAction}
              onSelect={() => select(d.id)}
              onAction={async (kind, fn) => {
                setBusyAction(`${d.id}:${kind}`)
                try {
                  await fn()
                  load()
                } finally {
                  setBusyAction(null)
                }
              }}
              onChanged={async () => {
                await refreshDomains()
                load()
              }}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function DomainCard({
  d,
  selected,
  busyAction,
  onSelect,
  onAction,
  onChanged,
}: {
  d: DomainOverview
  selected: boolean
  busyAction: string | null
  onSelect: () => void
  onAction: (kind: string, fn: () => Promise<unknown>) => Promise<void>
  onChanged: () => Promise<void>
}) {
  const risk = riskFromScore(d.findings.maxScore)
  const rs = RISK_STYLES[risk]
  const active = d.mode === 'active_authorized'

  const [editing, setEditing] = useState(false)
  const [labelDraft, setLabelDraft] = useState(d.label ?? '')
  const [modeDraft, setModeDraft] = useState<DomainMode>(d.mode)

  async function saveEdit() {
    if (
      modeDraft === 'active_authorized' &&
      d.mode !== 'active_authorized' &&
      !confirm(
        `Set ${d.host} to active_authorized? This permits LOUD/active scans (nmap/nuclei/ffuf/OWASP). Only for targets you are authorized to actively test.`,
      )
    )
      return
    await api.updateDomain(d.id, { label: labelDraft.trim() || null, mode: modeDraft })
    setEditing(false)
    await onChanged()
  }

  async function toggleMode() {
    const next: DomainMode = active ? 'passive_only' : 'active_authorized'
    if (
      next === 'active_authorized' &&
      !confirm(
        `Mark ${d.host} as active_authorized? This permits LOUD/active scans (nmap/nuclei/ffuf). Only do this for a target you are authorized to actively test.`,
      )
    )
      return
    await api.setDomainMode(d.id, next)
    await onChanged()
  }

  async function remove() {
    if (!confirm(`Delete ${d.host} and all its data (subdomains, findings)?`)) return
    await api.deleteDomain(d.id)
    await onChanged()
  }

  const isBusy = (kind: string) => busyAction === `${d.id}:${kind}`

  return (
    <Card className={`flex flex-col gap-3 transition ${selected ? 'ring-1 ring-zinc-500' : 'hover:border-zinc-700'}`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <button onClick={onSelect} className="min-w-0 text-left">
          <div className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${rs.dot}`} title={`risk: ${rs.label}`} />
            <span className="truncate font-medium text-zinc-100">{d.host}</span>
          </div>
          <div className="mt-0.5 truncate text-xs text-zinc-500">{d.label || 'no label'}</div>
        </button>
        <button onClick={toggleMode} title="click to toggle mode">
          {active ? <Badge tone="amber">active</Badge> : <Badge tone="green">passive</Badge>}
        </button>
      </div>

      {/* Stat tiles */}
      <div className="grid grid-cols-3 gap-2">
        <Stat label="Subdomains" value={d.subdomains.total} sub={d.subdomains.new > 0 ? `+${d.subdomains.new} new` : undefined} subTone="blue" />
        <Stat
          label="Top risk"
          value={d.findings.maxScore ?? '—'}
          sub={rs.label}
          subTone={rs.tone}
        />
        <Stat label="Findings" value={d.findings.total} />
        <Stat label="Exposed IPs" value={d.exposure.ips} />
        <Stat label="Open ports" value={d.exposure.openPorts} />
        <Stat label="CVEs" value={d.exposure.cves} subTone="red" sub={d.exposure.cves > 0 ? 'review' : undefined} />
      </div>

      <div className="text-[11px] text-zinc-500">Last recon: {timeAgo(d.lastActivity)}</div>

      {/* Edit panel */}
      {editing && (
        <div className="space-y-2 rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
          <label className="block text-xs text-zinc-400">
            Label
            <input
              value={labelDraft}
              onChange={(e) => setLabelDraft(e.target.value)}
              placeholder="e.g. Client X"
              className="mt-1 block w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2.5 py-1 text-sm outline-none focus:border-zinc-500"
            />
          </label>
          <label className="block text-xs text-zinc-400">
            Scan mode
            <select
              value={modeDraft}
              onChange={(e) => setModeDraft(e.target.value as DomainMode)}
              className="mt-1 block w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2.5 py-1 text-sm"
            >
              <option value="passive_only">passive_only (safe — no loud scans)</option>
              <option value="active_authorized">active_authorized (enables nmap/nuclei/ffuf/OWASP)</option>
            </select>
          </label>
          <div className="flex gap-1.5">
            <Button onClick={saveEdit}>Save</Button>
            <Button
              variant="ghost"
              onClick={() => {
                setEditing(false)
                setLabelDraft(d.label ?? '')
                setModeDraft(d.mode)
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {/* Quick actions */}
      <div className="flex flex-wrap gap-1.5 border-t border-zinc-800 pt-3">
        <Button variant="ghost" onClick={() => onAction('discover', () => api.discover(d.id))} disabled={isBusy('discover')}>
          {isBusy('discover') ? '…' : 'Discover'}
        </Button>
        <Button variant="ghost" onClick={() => onAction('exposure', () => api.exposure(d.id))} disabled={isBusy('exposure')}>
          {isBusy('exposure') ? '…' : 'Exposure'}
        </Button>
        <Button variant="ghost" onClick={() => onAction('osint', () => api.osint(d.id))} disabled={isBusy('osint')}>
          {isBusy('osint') ? '…' : 'OSINT'}
        </Button>
        <div className="ml-auto flex gap-1.5">
          <Button variant="ghost" onClick={() => setEditing((v) => !v)}>
            {editing ? 'Close' : 'Edit'}
          </Button>
          <Button variant="ghost" onClick={onSelect}>
            {selected ? '✓ Target' : 'Select'}
          </Button>
          <Button variant="danger" onClick={remove}>
            Delete
          </Button>
        </div>
      </div>
    </Card>
  )
}

function Stat({
  label,
  value,
  sub,
  subTone = 'zinc',
}: {
  label: string
  value: number | string
  sub?: string
  subTone?: 'zinc' | 'blue' | 'amber' | 'red'
}) {
  const subColor = {
    zinc: 'text-zinc-500',
    blue: 'text-blue-400',
    amber: 'text-amber-400',
    red: 'text-red-400',
  }[subTone]
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-2">
      <div className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</div>
      <div className="text-lg font-semibold leading-tight text-zinc-100">{value}</div>
      <div className={`h-3.5 text-[10px] ${subColor}`}>{sub ?? ''}</div>
    </div>
  )
}

function AddDomainForm({ onAdded }: { onAdded: () => void }) {
  const [host, setHost] = useState('')
  const [label, setLabel] = useState('')
  const [mode, setMode] = useState<DomainMode>('passive_only')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function add(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await api.createDomain(host.trim(), mode, label.trim() || undefined)
      setHost('')
      setLabel('')
      onAdded()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to add domain')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card className="mb-5">
      <form onSubmit={add} className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="text-zinc-400">Domain</span>
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="example.com"
            autoFocus
            className="mt-1 block w-56 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
          />
        </label>
        <label className="text-sm">
          <span className="text-zinc-400">Label (optional)</span>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Client X"
            className="mt-1 block w-44 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
          />
        </label>
        <label className="text-sm">
          <span className="text-zinc-400">Mode</span>
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as DomainMode)}
            className="mt-1 block rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
          >
            <option value="passive_only">passive_only</option>
            <option value="active_authorized">active_authorized</option>
          </select>
        </label>
        <Button type="submit" disabled={busy || !host.trim()}>
          {busy ? 'Adding…' : 'Add domain'}
        </Button>
      </form>
      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
    </Card>
  )
}
