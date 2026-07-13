import { FormEvent, useCallback, useState } from 'react'
import {
  Network, Flag, Server, Cable, Bug, Clock, Plus, Search, Radar, Eye, Zap,
  type LucideIcon,
} from 'lucide-react'
import { api, ApiError, type DomainMode, type DomainOverview } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/Confirm'
import { riskFromScore, timeAgo } from '../lib/format'

const RISK_STYLES: Record<string, { label: string; tone: 'zinc' | 'blue' | 'amber' | 'red' }> = {
  none: { label: 'no signal', tone: 'zinc' },
  low: { label: 'low', tone: 'blue' },
  medium: { label: 'medium', tone: 'amber' },
  high: { label: 'high', tone: 'red' },
}

const CHIP: Record<string, string> = {
  blue: 'bg-blue-500/15 text-blue-400',
  amber: 'bg-amber-500/15 text-amber-400',
  green: 'bg-green-500/15 text-green-400',
  red: 'bg-red-500/15 text-red-400',
  purple: 'bg-purple-500/15 text-purple-400',
}

// datetime-local <-> epoch-ms helpers for the authorization window.
function toLocalInput(iso: string | null | undefined): string {
  if (!iso) return ''
  const dt = new Date(iso)
  if (isNaN(dt.getTime())) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}`
}
function fromLocalInput(v: string): number | null {
  if (!v) return null
  const t = new Date(v).getTime()
  return Number.isFinite(t) ? t : null
}
function linesToList(s: string): string[] {
  return s.split('\n').map((x) => x.trim()).filter(Boolean)
}

export function Domains() {
  const { refreshDomains, select, selectedId } = useApp()
  const [overview, setOverview] = useState<DomainOverview[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [busyAction, setBusyAction] = useState<string | null>(null)

  const load = useCallback(() => {
    api.domainsOverview().then((r) => setOverview(r.overview)).catch(() => {})
  }, [])

  // Poll so cards update live while jobs run (backend caches overview ~8s).
  usePoll(load, 8000)

  const totals = overview.reduce(
    (a, d) => ({
      subs: a.subs + d.subdomains.total,
      findings: a.findings + d.findings.total,
      ips: a.ips + d.exposure.ips,
      cves: a.cves + d.exposure.cves,
    }),
    { subs: 0, findings: 0, ips: 0, cves: 0 },
  )

  return (
    <div>
      <PageHeader
        title="Domains"
        subtitle={
          overview.length
            ? `${overview.length} target${overview.length > 1 ? 's' : ''} · live recon overview`
            : 'Your targets at a glance. Active/loud scans require active_authorized.'
        }
        actions={
          <Button variant={showAdd ? 'ghost' : 'loud'} onClick={() => setShowAdd((v) => !v)}>
            {showAdd ? 'Close' : <><Plus size={16} /> Add domain</>}
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
        <Empty>No domains yet. Click “Add domain” to start recon.</Empty>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            <Kpi icon={Network} tone="blue" label="Subdomains" value={totals.subs} />
            <Kpi icon={Flag} tone="amber" label="Findings" value={totals.findings} />
            <Kpi icon={Server} tone="green" label="Exposed IPs" value={totals.ips} />
            <Kpi icon={Bug} tone="red" label="Critical CVEs" value={totals.cves} />
          </div>

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
        </>
      )}
    </div>
  )
}

function Kpi({ icon: Icon, tone, label, value }: { icon: LucideIcon; tone: string; label: string; value: number }) {
  return (
    <Card className="!p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className={`flex h-6 w-6 items-center justify-center rounded-md ${CHIP[tone]}`}>
          <Icon size={14} />
        </span>
        <span className="text-xs text-zinc-400">{label}</span>
      </div>
      <div className="text-2xl font-semibold leading-none text-zinc-50">{value}</div>
    </Card>
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
  const { domains: allDomains } = useApp()
  const toast = useToast()
  const confirm = useConfirm()
  const full = allDomains.find((x) => x.id === d.id)
  const risk = riskFromScore(d.findings.maxScore)
  const rs = RISK_STYLES[risk]
  const active = d.mode === 'active_authorized'

  const [editing, setEditing] = useState(false)
  const [labelDraft, setLabelDraft] = useState(d.label ?? '')
  const [modeDraft, setModeDraft] = useState<DomainMode>(d.mode)
  const [allowDraft, setAllowDraft] = useState('')
  const [denyDraft, setDenyDraft] = useState('')
  const [fromDraft, setFromDraft] = useState('')
  const [untilDraft, setUntilDraft] = useState('')

  function openEdit() {
    setLabelDraft(d.label ?? '')
    setModeDraft(d.mode)
    setAllowDraft((full?.scopeConfig?.allow ?? []).join('\n'))
    setDenyDraft((full?.scopeConfig?.deny ?? []).join('\n'))
    setFromDraft(toLocalInput(full?.authorizedFrom))
    setUntilDraft(toLocalInput(full?.authorizedUntil))
    setEditing(true)
  }

  async function saveEdit() {
    if (modeDraft === 'active_authorized' && d.mode !== 'active_authorized') {
      const ok = await confirm({
        title: 'Enable active scanning?',
        message: `Set ${d.host} to active_authorized? This permits LOUD/active scans (nmap/nuclei/ffuf/OWASP). Only for targets you are authorized to actively test.`,
        confirmLabel: 'Enable',
        tone: 'danger',
      })
      if (!ok) return
    }
    try {
      await api.updateDomain(d.id, {
        label: labelDraft.trim() || null,
        mode: modeDraft,
        scopeConfig: { allow: linesToList(allowDraft), deny: linesToList(denyDraft) },
        authorizedFrom: fromLocalInput(fromDraft),
        authorizedUntil: fromLocalInput(untilDraft),
      })
      setEditing(false)
      await onChanged()
    } catch (err) {
      toast.error(`Failed to save: ${err instanceof Error ? err.message : 'error'}`)
    }
  }

  async function toggleMode() {
    const next: DomainMode = active ? 'passive_only' : 'active_authorized'
    if (next === 'active_authorized') {
      const ok = await confirm({
        title: 'Enable active scanning?',
        message: `Mark ${d.host} as active_authorized? This permits LOUD/active scans (nmap/nuclei/ffuf). Only do this for a target you are authorized to actively test.`,
        confirmLabel: 'Enable',
        tone: 'danger',
      })
      if (!ok) return
    }
    try {
      await api.setDomainMode(d.id, next)
      await onChanged()
    } catch (err) {
      toast.error(`Failed to change mode: ${err instanceof Error ? err.message : 'error'}`)
    }
  }

  async function remove() {
    const ok = await confirm({
      title: 'Delete target?',
      message: `Delete ${d.host} and all its data (subdomains, findings)? This can't be undone.`,
      confirmLabel: 'Delete',
      tone: 'danger',
    })
    if (!ok) return
    try {
      await api.deleteDomain(d.id)
      toast.success(`${d.host} deleted.`)
      await onChanged()
    } catch (err) {
      toast.error(`Failed to delete: ${err instanceof Error ? err.message : 'error'}`)
    }
  }

  async function clearData() {
    const ok = await confirm({
      title: 'Clear all data?',
      message: `Delete all recon data for ${d.host} — findings, subdomains, jobs, captured traffic, replay history, screenshots — but keep the target and its settings. This can't be undone.`,
      confirmLabel: 'Clear data',
      tone: 'danger',
    })
    if (!ok) return
    try {
      await api.purgeDomainData(d.id)
      toast.success(`Cleared all data for ${d.host}.`)
      await onChanged()
    } catch (err) {
      toast.error(`Failed to clear data: ${err instanceof Error ? err.message : 'error'}`)
    }
  }

  const isBusy = (kind: string) => busyAction === `${d.id}:${kind}`

  async function setMonitor(hours: number) {
    try {
      await api.updateDomain(d.id, { monitorIntervalHours: hours })
      await onChanged()
    } catch (err) {
      toast.error(`Failed to set monitoring: ${err instanceof Error ? err.message : 'error'}`)
    }
  }

  return (
    <Card className={`flex flex-col gap-3 transition ${selected ? 'ring-1 ring-accent-500/60 border-accent-500/40' : 'hover:border-hair-strong'}`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <button
            onClick={onSelect}
            className="block max-w-full truncate text-left font-mono text-sm font-medium text-zinc-100 hover:text-white"
          >
            {d.host}
          </button>
          <div className="mt-1 flex items-center gap-1.5">
            <button onClick={toggleMode} title="click to toggle mode">
              {active ? <Badge tone="amber">active</Badge> : <Badge tone="green">passive</Badge>}
            </button>
            {d.subdomains.new > 0 && <Badge tone="blue">+{d.subdomains.new} new</Badge>}
            {d.monitorIntervalHours > 0 && <Badge tone="indigo">auto {d.monitorIntervalHours}h</Badge>}
          </div>
        </div>
        <Badge tone={rs.tone}>
          {d.findings.maxScore != null ? `${d.findings.maxScore} · ${rs.label}` : rs.label}
        </Badge>
      </div>

      {/* Stat strip */}
      <div className="grid grid-cols-3 gap-2">
        <Stat icon={Network} color="text-blue-400" label="subdomains" value={d.subdomains.total} />
        <Stat icon={Flag} color="text-amber-400" label="findings" value={d.findings.total} />
        <Stat icon={Server} color="text-green-400" label="exposed IPs" value={d.exposure.ips} />
        <Stat icon={Cable} color="text-purple-400" label="open ports" value={d.exposure.openPorts} />
        <Stat icon={Bug} color="text-red-400" label="CVEs" value={d.exposure.cves} />
        <Stat icon={Clock} color="text-zinc-400" label="last recon" value={timeAgo(d.lastActivity)} />
      </div>

      {/* Edit panel */}
      {editing && (
        <div className="space-y-2 rounded-lg border border-hair bg-ink-900/70 p-3">
          <label className="block text-xs text-zinc-400">
            Label
            <input
              value={labelDraft}
              onChange={(e) => setLabelDraft(e.target.value)}
              placeholder="e.g. Client X"
              className="mt-1 block w-full rounded-lg border border-hair bg-ink-950 px-2.5 py-1 text-sm outline-none focus:border-accent-500"
            />
          </label>
          <label className="block text-xs text-zinc-400">
            Scan mode
            <select
              value={modeDraft}
              onChange={(e) => setModeDraft(e.target.value as DomainMode)}
              className="mt-1 block w-full rounded-lg border border-hair bg-ink-950 px-2.5 py-1 text-sm"
            >
              <option value="passive_only">passive_only (safe — no loud scans)</option>
              <option value="active_authorized">active_authorized (enables nmap/nuclei/ffuf/OWASP)</option>
            </select>
          </label>

          {/* Engagement scope + authorization window (enforced on active scans) */}
          <div className="mt-1 border-t border-hair/60 pt-2">
            <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
              Authorized scope & window
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="block text-xs text-zinc-400">
                Allow (hosts / CIDRs)
                <textarea
                  value={allowDraft}
                  onChange={(e) => setAllowDraft(e.target.value)}
                  rows={3}
                  placeholder={'example.com\n203.0.113.0/24'}
                  className="mt-1 block w-full rounded-lg border border-hair bg-ink-950 px-2.5 py-1 font-mono text-xs outline-none focus:border-accent-500"
                />
              </label>
              <label className="block text-xs text-zinc-400">
                Deny (hosts / CIDRs)
                <textarea
                  value={denyDraft}
                  onChange={(e) => setDenyDraft(e.target.value)}
                  rows={3}
                  placeholder={'staging.example.com'}
                  className="mt-1 block w-full rounded-lg border border-hair bg-ink-950 px-2.5 py-1 font-mono text-xs outline-none focus:border-accent-500"
                />
              </label>
            </div>
            <p className="mt-1 text-[10px] text-zinc-600">
              Empty allow = anything within the domain. Deny always wins. Enforced on active scans only.
            </p>
            <div className="mt-2 grid grid-cols-2 gap-2">
              <label className="block text-xs text-zinc-400">
                Authorized from
                <input
                  type="datetime-local"
                  value={fromDraft}
                  onChange={(e) => setFromDraft(e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-hair bg-ink-950 px-2.5 py-1 text-xs outline-none focus:border-accent-500"
                />
              </label>
              <label className="block text-xs text-zinc-400">
                Authorized until
                <input
                  type="datetime-local"
                  value={untilDraft}
                  onChange={(e) => setUntilDraft(e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-hair bg-ink-950 px-2.5 py-1 text-xs outline-none focus:border-accent-500"
                />
              </label>
            </div>
            <p className="mt-1 text-[10px] text-zinc-600">
              Outside this window, active scans are refused. Leave blank for no time limit.
            </p>
          </div>

          <div className="flex gap-1.5">
            <Button variant="loud" onClick={saveEdit}>Save</Button>
            <Button variant="ghost" onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      {/* Actions — recon on top, card management below */}
      <div className="mt-3 space-y-2 border-t border-hair pt-3">
        {/* Recon actions */}
        <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
          <Button
            variant="loud"
            title={
              active
                ? 'One-click recon: subdomain discovery (→ exposure + screenshots) + OSINT + origin + API surface + nmap (active)'
                : 'One-click passive recon: subdomain discovery (→ exposure + screenshots) + OSINT + origin + API surface'
            }
            onClick={() =>
              onAction('recon', () => {
                // Full passive sweep; add nmap only when the domain is authorized
                // for active/loud scans.
                const jobs = [api.discover(d.id), api.osint(d.id), api.findOrigin(d.id), api.apiDiscovery(d.id)]
                if (active) jobs.push(api.nmap(d.id, { confirm: false }))
                return Promise.all(jobs)
              })
            }
            disabled={busyAction?.startsWith(`${d.id}:`)}
          >
            <Zap size={14} /> {isBusy('recon') ? 'Running…' : 'Run recon'}
          </Button>
          <Button variant="ghost" onClick={() => onAction('discover', () => api.discover(d.id))} disabled={isBusy('discover')}>
            <Search size={14} /> {isBusy('discover') ? '…' : 'Discover'}
          </Button>
          <Button variant="ghost" onClick={() => onAction('exposure', () => api.exposure(d.id))} disabled={isBusy('exposure')}>
            <Radar size={14} /> {isBusy('exposure') ? '…' : 'Exposure'}
          </Button>
          <Button variant="ghost" onClick={() => onAction('osint', () => api.osint(d.id))} disabled={isBusy('osint')}>
            <Eye size={14} /> {isBusy('osint') ? '…' : 'OSINT'}
          </Button>
        </div>
        {/* Card management */}
        <div className="flex flex-wrap items-center gap-1.5">
          <select
            value={d.monitorIntervalHours || 0}
            onChange={(e) => setMonitor(Number(e.target.value))}
            title="Auto re-run passive recon on a schedule"
            className="rounded-lg border border-hair bg-ink-950 px-2 py-1 text-xs text-zinc-300 outline-none hover:border-hair-strong focus:border-accent-500"
          >
            <option value={0}>Monitor: off</option>
            <option value={6}>every 6h</option>
            <option value={12}>every 12h</option>
            <option value={24}>every 24h</option>
          </select>
          <div className="ml-auto flex gap-1.5">
            <Button variant="ghost" onClick={() => (editing ? setEditing(false) : openEdit())}>
              {editing ? 'Close' : 'Edit'}
            </Button>
            <Button variant={selected ? 'default' : 'ghost'} onClick={onSelect}>
              {selected ? '✓ Target' : 'Select'}
            </Button>
            <Button variant="ghost" onClick={clearData} title="Delete all recon data but keep the target">
              Clear data
            </Button>
            <Button variant="danger" onClick={remove}>
              Delete
            </Button>
          </div>
        </div>
      </div>
    </Card>
  )
}

function Stat({
  icon: Icon,
  color,
  label,
  value,
}: {
  icon: LucideIcon
  color: string
  label: string
  value: number | string
}) {
  return (
    <div className="rounded-lg border border-hair-soft bg-ink-900/50 p-2">
      <div className="flex items-center gap-1.5">
        <Icon size={13} className={color} />
        <span className="text-[15px] font-semibold leading-none text-zinc-100">{value}</span>
      </div>
      <div className="mt-1 text-[10px] uppercase tracking-wide text-zinc-500">{label}</div>
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
            className="mt-1 block w-56 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
          />
        </label>
        <label className="text-sm">
          <span className="text-zinc-400">Label (optional)</span>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Client X"
            className="mt-1 block w-44 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
          />
        </label>
        <label className="text-sm">
          <span className="text-zinc-400">Mode</span>
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as DomainMode)}
            className="mt-1 block rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
          >
            <option value="passive_only">passive_only</option>
            <option value="active_authorized">active_authorized</option>
          </select>
        </label>
        <Button type="submit" variant="loud" disabled={busy || !host.trim()}>
          {busy ? 'Adding…' : 'Add domain'}
        </Button>
      </form>
      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
    </Card>
  )
}
