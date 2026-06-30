import { FormEvent, useState } from 'react'
import { api, ApiError, type DomainMode } from '../api'
import { useApp } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'

export function Domains() {
  const { domains, refreshDomains, select, selectedId } = useApp()
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
      setMode('passive_only')
      await refreshDomains()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to add domain')
    } finally {
      setBusy(false)
    }
  }

  async function toggleMode(id: number, current: DomainMode) {
    const next: DomainMode = current === 'active_authorized' ? 'passive_only' : 'active_authorized'
    if (
      next === 'active_authorized' &&
      !confirm('Mark this domain active_authorized? This permits LOUD/active scans. Only do this for targets you are authorized to actively test.')
    )
      return
    await api.setDomainMode(id, next)
    await refreshDomains()
  }

  async function remove(id: number, hostName: string) {
    if (!confirm(`Delete ${hostName} and all its data (subdomains, findings)?`)) return
    await api.deleteDomain(id)
    await refreshDomains()
  }

  return (
    <div>
      <PageHeader title="Domains" subtitle="Targets you track. Active/loud scans require active_authorized." />

      <Card className="mb-6">
        <form onSubmit={add} className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="text-zinc-400">Domain</span>
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="example.com"
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

      {domains.length === 0 ? (
        <Empty>No domains yet. Add one above to start recon.</Empty>
      ) : (
        <div className="space-y-2">
          {domains.map((d) => (
            <Card key={d.id} className={`flex flex-wrap items-center justify-between gap-3 ${selectedId === d.id ? 'ring-1 ring-zinc-600' : ''}`}>
              <button onClick={() => select(d.id)} className="text-left">
                <div className="font-medium">{d.host}</div>
                <div className="text-xs text-zinc-500">{d.label || 'no label'}</div>
              </button>
              <div className="flex items-center gap-2">
                <button onClick={() => toggleMode(d.id, d.mode)} title="click to toggle">
                  {d.mode === 'active_authorized' ? (
                    <Badge tone="amber">active_authorized</Badge>
                  ) : (
                    <Badge tone="green">passive_only</Badge>
                  )}
                </button>
                <Button variant="ghost" onClick={() => select(d.id)}>
                  Select
                </Button>
                <Button variant="danger" onClick={() => remove(d.id, d.host)}>
                  Delete
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
