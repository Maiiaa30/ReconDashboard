import { useCallback, useState } from 'react'
import { CheckCircle2, CircleOff, Database, HardDrive, Radio, RefreshCw, ShieldCheck, Wrench } from 'lucide-react'
import { api, type MetaStatus } from '../api'
import { usePoll } from '../state'
import { Badge, Button, Card, PageHeader, SkeletonList } from '../components/ui'

const CORE_TOOLS = ['subfinder', 'nmap', 'nuclei', 'ffuf', 'chromium'] as const

export function summarizeReadiness(meta: MetaStatus, now = Date.now()): { tone: 'green' | 'amber' | 'red'; label: string; issues: string[] } {
  const issues: string[] = []
  if (!meta.readiness.database.ok) issues.push('database check failed')
  const workerFresh = meta.readiness.worker.running
    && meta.readiness.worker.lastTickAt != null
    && now - meta.readiness.worker.lastTickAt < 15_000
  if (!workerFresh) issues.push('job worker is not checking in')
  const missingTools = CORE_TOOLS.filter((tool) => !meta.tools[tool])
  if (missingTools.length > 0) issues.push(`missing tools: ${missingTools.join(', ')}`)
  if (meta.readiness.storage.freeBytes != null && meta.readiness.storage.freeBytes < 1024 ** 3) issues.push('less than 1 GB storage free')

  if (!meta.readiness.database.ok || !workerFresh) return { tone: 'red', label: 'Action required', issues }
  if (issues.length > 0) return { tone: 'amber', label: 'Partially ready', issues }
  return { tone: 'green', label: 'Ready', issues }
}

function formatBytes(value: number | null): string {
  if (value == null) return 'unavailable'
  if (value < 1024 ** 2) return `${Math.round(value / 1024).toLocaleString()} KB`
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`
  return `${(value / 1024 ** 3).toFixed(1)} GB`
}

function relativeTime(value: number | null, now: number): string {
  if (value == null) return 'never'
  const seconds = Math.max(0, Math.round((now - value) / 1000))
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`
  return `${Math.round(seconds / 3600)}h ago`
}

export function Readiness() {
  const [meta, setMeta] = useState<MetaStatus | null>(null)
  const [error, setError] = useState(false)
  const [now, setNow] = useState(Date.now())

  const load = useCallback((signal: AbortSignal) => api.meta({ signal }).then((result) => {
    if (signal.aborted) return
    setMeta(result)
    setNow(Date.now())
    setError(false)
  }).catch(() => {
    if (!signal.aborted) setError(true)
  }), [])
  usePoll(load, 10_000)

  if (!meta && !error) return <SkeletonList rows={6} />
  if (!meta) {
    return <Card className="border-red-900/50 text-sm text-red-300">Readiness data is unavailable. The dashboard will retry automatically.</Card>
  }

  const summary = summarizeReadiness(meta, now)
  const captureSeenRecently = meta.readiness.capture.extensionSeenAt != null && now - meta.readiness.capture.extensionSeenAt < 60_000
  const installedTools = Object.entries(meta.tools).filter(([, installed]) => installed).map(([tool]) => tool)
  const missingTools = Object.entries(meta.tools).filter(([, installed]) => !installed).map(([tool]) => tool)

  return (
    <div className="space-y-5">
      <PageHeader
        title="Readiness"
        subtitle="One preflight view for this local operator instance"
        actions={<Button variant="ghost" onClick={() => void load(new AbortController().signal)}><RefreshCw size={14} /> Refresh</Button>}
      />

      <Card className={summary.tone === 'red' ? 'border-red-900/60' : summary.tone === 'amber' ? 'border-amber-900/60' : 'border-emerald-900/60'}>
        <div className="flex items-start gap-3">
          {summary.tone === 'green' ? <CheckCircle2 className="text-emerald-400" /> : <CircleOff className={summary.tone === 'red' ? 'text-red-400' : 'text-amber-400'} />}
          <div>
            <div className="flex items-center gap-2"><h2 className="font-semibold">{summary.label}</h2><Badge tone={summary.tone}>{summary.issues.length === 0 ? 'all core checks passed' : `${summary.issues.length} issue${summary.issues.length === 1 ? '' : 's'}`}</Badge></div>
            {summary.issues.length > 0 && <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-zinc-400">{summary.issues.map((issue) => <li key={issue}>{issue}</li>)}</ul>}
            {error && <p className="mt-2 text-xs text-amber-400">The latest refresh failed; showing the last successful result.</p>}
          </div>
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <StatusCard icon={Database} title="Database" badge={meta.readiness.database.ok ? 'healthy' : 'failed'} tone={meta.readiness.database.ok ? 'green' : 'red'}>
          <Line label="Database size" value={formatBytes(meta.readiness.database.sizeBytes)} />
          <Line label="Storage free" value={formatBytes(meta.readiness.storage.freeBytes)} />
          <Line label="Last check" value={relativeTime(meta.readiness.checkedAt, now)} />
        </StatusCard>

        <StatusCard icon={ShieldCheck} title="Worker and queue" badge={meta.readiness.worker.running ? 'running' : 'stopped'} tone={meta.readiness.worker.running ? 'green' : 'red'}>
          <Line label="Worker heartbeat" value={relativeTime(meta.readiness.worker.lastTickAt, now)} />
          <Line label="Queued / running" value={`${meta.readiness.queue.queued} / ${meta.readiness.queue.running}`} />
          <Line label="Failed retained" value={String(meta.readiness.queue.failed)} />
        </StatusCard>

        <StatusCard icon={Wrench} title="Scanner tools" badge={`${installedTools.length} installed`} tone={missingTools.length === 0 ? 'green' : 'amber'}>
          <p className="text-sm text-zinc-400">{installedTools.join(' · ') || 'No external tools detected'}</p>
          {missingTools.length > 0 && <p className="mt-2 text-xs text-amber-300">Missing: {missingTools.join(' · ')}</p>}
          <Line label="Wordlists" value={String(meta.wordlists.length)} />
        </StatusCard>

        <StatusCard icon={Radio} title="Optional services" badge="configuration" tone="zinc">
          <Line label="Browser capture" value={!meta.readiness.capture.enabled ? 'off' : captureSeenRecently ? 'connected' : 'enabled, not detected'} />
          <Line label="LLM drafting" value={meta.llm?.enabled ? meta.llm.model ?? 'enabled' : 'off'} />
          <Line label="Leak provider" value={meta.leaks?.enabled ? meta.leaks.provider ?? 'enabled' : 'off'} />
          <Line label="Discord alerts" value={meta.discordConfigured ? 'configured' : 'off'} />
          <Line label="Backup protection" value={meta.readiness.backup.serverPassphraseConfigured ? 'server passphrase' : 'passphrase per export'} />
        </StatusCard>
      </div>
    </div>
  )
}

function StatusCard({ icon: Icon, title, badge, tone, children }: { icon: typeof HardDrive; title: string; badge: string; tone: 'green' | 'amber' | 'red' | 'zinc'; children: React.ReactNode }) {
  return <Card><div className="mb-3 flex items-center gap-2"><Icon size={17} className="text-zinc-400" /><h2 className="font-semibold">{title}</h2><span className="ml-auto"><Badge tone={tone}>{badge}</Badge></span></div><div className="space-y-2">{children}</div></Card>
}

function Line({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between gap-4 text-sm"><span className="text-zinc-500">{label}</span><span className="text-right text-zinc-300">{value}</span></div>
}
