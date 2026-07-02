import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type Finding, type MetaStatus } from '../api'
import { useApp, useHosts, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { timeAgo } from '../lib/format'

interface ToolDef {
  id: string
  label: string
  desc: string
  metaKey?: keyof MetaStatus['tools'] // omit → always available (HTTP routine)
}

const TOOLS: ToolDef[] = [
  { id: 'katana', label: 'katana', desc: 'Crawl the site for URLs and parameters (depth 2, JS-aware).', metaKey: 'katana' },
  { id: 'naabu', label: 'naabu', desc: 'Fast TCP connect port scan (top 1000 ports).', metaKey: 'naabu' },
  { id: 'dalfox', label: 'dalfox', desc: 'Active cross-site-scripting (XSS) scanner.', metaKey: 'dalfox' },
  { id: 'sslscan', label: 'sslscan', desc: 'TLS protocol & cipher audit (weak/expired detection).', metaKey: 'sslscan' },
  { id: 'sqlmap', label: 'sqlmap', desc: 'Active SQL-injection scanner (crawls + tests URLs/forms, --batch).', metaKey: 'sqlmap' },
  { id: 'wpenum', label: 'WordPress enum', desc: 'Version, users (REST), plugins, exposed endpoints. No binary.', metaKey: 'wpenum' },
  { id: 'bypass403', label: '403 bypass', desc: 'Retries protected (401/403) paths with header, path & method tricks. No binary.', metaKey: 'bypass403' },
  { id: 'methods', label: 'HTTP methods', desc: 'Verb-tampering audit — flags write methods (PUT/DELETE/PATCH) the server accepts. No binary.', metaKey: 'methods' },
  { id: 'datastores', label: 'Exposed datastores', desc: 'Probes no-auth Elasticsearch/CouchDB, Spring actuator & DB admin panels (phpMyAdmin/Adminer/…). Proof-only, no data pulled. No binary.', metaKey: 'datastores' },
]

function severityTone(sev: unknown): 'zinc' | 'green' | 'amber' | 'red' | 'blue' {
  switch (String(sev ?? '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'red'
    case 'medium':
      return 'amber'
    case 'low':
      return 'blue'
    default:
      return 'zinc'
  }
}

export function Tools() {
  const { selected } = useApp()
  const hosts = useHosts(selected)
  const [meta, setMeta] = useState<MetaStatus | null>(null)
  const [target, setTarget] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    api.meta().then(setMeta).catch(() => setMeta(null))
  }, [])
  useEffect(() => {
    setTarget(selected?.host ?? '')
  }, [selected])

  const selectedId = selected?.id ?? null
  const load = useCallback(() => {
    if (selectedId == null) return
    api.findings({ domainId: selectedId, type: 'tool', limit: 100 }).then((r) => setFindings(r.findings)).catch(() => {})
  }, [selectedId])
  usePoll(load, 4000, selectedId != null)

  if (!selected) return <Empty>Select a domain to run tools.</Empty>

  const active = selected.mode === 'active_authorized'

  async function runTool(tool: string) {
    if (!selected) return
    if (!active) {
      const ok = confirm(
        `⚠ ${selected.host} is passive_only.\n\nThis is a LOUD, active tool. Only run it against ${target} if you are authorized to actively test this target.\n\nRun anyway?`,
      )
      if (!ok) return
    }
    setBusy(tool)
    setMsg(null)
    try {
      const { jobId } = await api.runTool(selected.id, { tool, target, confirm: !active })
      setMsg({ ok: true, text: `Queued ${tool} job #${jobId} on ${target} — results appear below.` })
    } catch (err) {
      setMsg({ ok: false, text: err instanceof ApiError ? err.message : 'failed to start tool' })
    } finally {
      setBusy(null)
    }
  }

  const runLabel = (tool: string, label: string) =>
    busy === tool ? 'Queuing…' : active ? `Run ${label}` : `Run ${label} (confirm)`

  return (
    <div>
      <PageHeader
        title="Tools"
        subtitle={`${selected.host} — extra active recon tooling`}
        actions={<Badge tone="amber">LOUD / ACTIVE</Badge>}
      />

      <Card className="mb-4">
        <label className="text-sm">
          <span className="text-zinc-400">Target host</span>
          <select
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="mt-1 block w-72 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-accent-500"
          >
            {hosts.length === 0 && <option value={selected.host}>{selected.host}</option>}
            {hosts.map((h) => (
              <option key={h.host} value={h.host}>
                {h.host}
                {h.live ? ' • live' : ''}
              </option>
            ))}
          </select>
        </label>
      </Card>

      {msg && <p className={`mb-3 text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>{msg.text}</p>}

      <div className="grid gap-3 sm:grid-cols-2">
        {TOOLS.map((t) => {
          const available = !t.metaKey || !meta || meta.tools[t.metaKey] !== false
          return (
            <Card key={t.id} className="flex flex-col gap-2">
              <div className="flex items-center justify-between gap-2">
                <h2 className="font-mono text-sm font-semibold text-zinc-100">{t.label}</h2>
                {!available && <span className="text-xs text-zinc-500">not installed</span>}
              </div>
              <p className="text-sm text-zinc-400">{t.desc}</p>
              <div>
                <Button variant="loud" disabled={!available || busy != null || !target} onClick={() => runTool(t.id)}>
                  {runLabel(t.id, t.label)}
                </Button>
              </div>
            </Card>
          )
        })}
      </div>

      <h2 className="mb-3 mt-8 text-sm font-semibold text-zinc-200">Results</h2>
      {findings.length === 0 ? (
        <Empty>No tool findings yet. Run a tool above.</Empty>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => {
            const d = f.data ?? {}
            const items: string[] = Array.isArray(d.items) ? d.items : []
            return (
              <Card key={f.id}>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="indigo">{String(d.tool ?? 'tool')}</Badge>
                  <Badge tone={severityTone(d.severity)}>{String(d.severity ?? 'info')}</Badge>
                  <span className="text-sm font-medium text-zinc-100">{String(d.title ?? 'finding')}</span>
                  <span className="font-mono text-xs text-zinc-500">{String(d.target ?? '')}</span>
                  <span className="ml-auto text-xs text-zinc-500">{timeAgo(new Date(f.createdAt).getTime())}</span>
                </div>
                {d.detail && <p className="mt-1 text-xs text-zinc-400">{String(d.detail)}</p>}
                {items.length > 0 && (
                  <div className="mt-2 max-h-64 space-y-0.5 overflow-auto rounded-lg border border-hair bg-ink-950/60 p-2 font-mono text-xs text-zinc-300">
                    {items.map((it, i) => (
                      <div key={i} className="break-all">{it}</div>
                    ))}
                  </div>
                )}
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
