import { useCallback, useState } from 'react'
import {
  AlertTriangle, Bell, Flag, Radar, Search, Sparkles, Globe, ShieldAlert, Bug, ArrowRight,
  type LucideIcon,
} from 'lucide-react'
import { api, type DomainOverview, type HomeFinding, type RecentChange } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, SkeletonList } from '../components/ui'
import { useToast } from '../components/Toast'
import { riskFromScore, summarizeFinding, timeAgo, type RiskLevel } from '../lib/format'

const RISK_SCORE: Record<RiskLevel, string> = {
  high: 'bg-red-950 text-red-300 ring-red-800',
  medium: 'bg-amber-950 text-amber-300 ring-amber-800',
  low: 'bg-blue-950 text-blue-300 ring-blue-800',
  none: 'bg-zinc-800 text-zinc-400 ring-zinc-700',
}

// Cross-target landing page: a prioritized action list, not a SOC dashboard.
export function Home({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { domains } = useApp()
  const toast = useToast()
  const [loaded, setLoaded] = useState(false)
  const [overview, setOverview] = useState<DomainOverview[]>([])
  const [top, setTop] = useState<HomeFinding[]>([])
  const [changes, setChanges] = useState<RecentChange[]>([])

  const load = useCallback(() => {
    api.home().then((r) => {
      setOverview(r.overview)
      setTop(r.topFindings)
      setChanges(r.recentChanges ?? [])
    }).catch(() => toast.error('Failed to load overview.')).finally(() => setLoaded(true))
  }, [toast])
  usePoll(load, 8000)

  const hostOf = (id: number | null) => (id == null ? 'global' : domains.find((d) => d.id === id)?.host ?? `#${id}`)

  // Attention buckets derived from the overview.
  const neverScanned = overview.filter((d) => d.lastActivity == null)
  const withNewSubs = overview.filter((d) => d.subdomains.new > 0)
  const highRisk = overview.filter((d) => (d.findings.maxScore ?? 0) >= 70)

  const totals = overview.reduce(
    (a, d) => ({
      findings: a.findings + d.findings.total,
      cves: a.cves + d.exposure.cves,
      newSubs: a.newSubs + d.subdomains.new,
    }),
    { findings: 0, cves: 0, newSubs: 0 },
  )
  const lastActivity = overview.reduce((m, d) => Math.max(m, d.lastActivity ?? 0), 0) || null

  if (!loaded) {
    return (
      <div>
        <Hero count={0} lastActivity={null} navigate={navigate} />
        <SkeletonList rows={5} />
      </div>
    )
  }

  if (overview.length === 0) {
    return (
      <div>
        <Hero count={0} lastActivity={null} navigate={navigate} />
        <Empty>
          <div className="flex flex-col items-start gap-3">
            <span>No targets yet — add a domain to begin recon.</span>
            <Button variant="primary" onClick={() => navigate('domains')}>
              <Globe size={15} /> Add your first target
            </Button>
          </div>
        </Empty>
      </div>
    )
  }

  return (
    <div>
      <Hero count={overview.length} lastActivity={lastActivity} navigate={navigate} />

      {/* Headline stats — the dashboard "vitals" */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <StatTile icon={Globe} label="Targets" value={overview.length} tone="indigo" onClick={() => navigate('domains')} />
        <StatTile icon={Flag} label="Findings" value={totals.findings} tone="zinc" onClick={() => navigate('findings')} />
        <StatTile icon={Bug} label="CVEs" value={totals.cves} tone="red" onClick={() => navigate('exposure')} />
        <StatTile icon={ShieldAlert} label="High-risk" value={highRisk.length} tone="amber" onClick={() => navigate('findings')} />
        <StatTile icon={Sparkles} label="New subs" value={totals.newSubs} tone="blue" onClick={() => navigate('subdomains')} />
      </div>

      {/* Attention row */}
      <div className="mb-5 grid gap-3 md:grid-cols-3">
        <AttentionCard
          icon={Search}
          tone="blue"
          title="Never scanned"
          items={neverScanned.map((d) => ({ id: d.id, host: d.host, note: 'no recon yet' }))}
          onPick={(id) => navigate('domains', id)}
          empty="All targets have recon data."
        />
        <AttentionCard
          icon={Sparkles}
          tone="amber"
          title="New subdomains"
          items={withNewSubs.map((d) => ({ id: d.id, host: d.host, note: `+${d.subdomains.new} new` }))}
          onPick={(id) => navigate('subdomains', id)}
          empty="Nothing new since last acknowledge."
        />
        <AttentionCard
          icon={AlertTriangle}
          tone="red"
          title="High-risk targets"
          items={highRisk.map((d) => ({ id: d.id, host: d.host, note: `max ${d.findings.maxScore}` }))}
          onPick={(id) => navigate('findings', id)}
          empty="No high-severity findings."
        />
      </div>

      {/* What changed — new CVEs that appeared on already-tracked assets */}
      {changes.length > 0 && (
        <Card className="mb-5 border-red-900/50 bg-red-950/10">
          <div className="mb-2 flex items-center gap-2">
            <Bell size={16} className="text-red-400" />
            <h2 className="text-sm font-semibold text-red-200">What changed — new CVEs on known assets</h2>
            <span className="ml-auto text-xs text-zinc-500">{changes.length}</span>
          </div>
          <div className="space-y-1.5">
            {changes.map((c) => (
              <button
                key={c.id}
                onClick={() => navigate('findings', c.domainId ?? undefined)}
                className="flex w-full items-center gap-3 rounded-lg border border-red-900/30 bg-ink-900/50 px-3 py-2 text-left transition hover:border-red-800/60"
              >
                <span className="flex h-7 shrink-0 items-center rounded-lg bg-red-950 px-2 text-xs font-semibold text-red-300 ring-1 ring-red-800">
                  {c.score ?? '—'}
                </span>
                <span className="font-mono text-sm text-zinc-100">{c.data.cveId ?? 'CVE'}</span>
                {c.data.kev && <Badge tone="red">KEV</Badge>}
                {c.data.cvss != null && <span className="text-xs text-zinc-400">CVSS {c.data.cvss}</span>}
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-400">
                  on {c.data.host ?? c.data.ip ?? '?'}
                </span>
                <span className="shrink-0 text-xs text-zinc-500">{timeAgo(new Date(c.createdAt).getTime())}</span>
              </button>
            ))}
          </div>
        </Card>
      )}

      {/* Top open findings — the main action list */}
      <Card>
        <div className="mb-3 flex items-center gap-2">
          <Flag size={16} className="text-amber-400" />
          <h2 className="text-sm font-semibold">Top open findings across all targets</h2>
        </div>
        {top.length === 0 ? (
          <p className="text-sm text-zinc-500">No open findings above the noise floor. Run some recon.</p>
        ) : (
          <div className="space-y-1.5">
            {top.map((f) => {
              const risk = riskFromScore(f.score)
              return (
                <button
                  key={f.id}
                  onClick={() => navigate('findings', f.domainId ?? undefined)}
                  className="flex w-full items-center gap-3 rounded-lg border border-hair bg-ink-900/50 px-3 py-2 text-left transition hover:border-hair-strong hover:bg-ink-850"
                >
                  <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-xs font-semibold ring-1 ${RISK_SCORE[risk]}`}>
                    {f.score ?? '—'}
                  </span>
                  <Badge tone="zinc">{f.type}</Badge>
                  <span className="min-w-0 flex-1 truncate font-mono text-sm text-zinc-200">{summarizeFinding(f.type, f.data)}</span>
                  <span className="shrink-0 font-mono text-xs text-zinc-500">{hostOf(f.domainId)}</span>
                </button>
              )
            })}
          </div>
        )}
      </Card>

      {/* Recently active */}
      <div className="mt-5">
        <div className="mb-2 flex items-center gap-2">
          <Radar size={16} className="text-zinc-400" />
          <h2 className="text-sm font-semibold text-zinc-300">Targets by last activity</h2>
        </div>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {[...overview]
            .sort((a, b) => (b.lastActivity ?? 0) - (a.lastActivity ?? 0))
            .map((d) => (
              <button
                key={d.id}
                onClick={() => navigate('findings', d.id)}
                className="flex items-center justify-between rounded-lg border border-hair bg-ink-900/50 px-3 py-2 text-left transition hover:border-hair-strong"
              >
                <span className="min-w-0">
                  <span className="block truncate font-mono text-sm text-zinc-200">{d.host}</span>
                  <span className="text-xs text-zinc-500">{d.findings.total} findings · {d.exposure.cves} CVEs</span>
                </span>
                <span className="shrink-0 text-xs text-zinc-500">{timeAgo(d.lastActivity)}</span>
              </button>
            ))}
        </div>
      </div>
    </div>
  )
}

// A proper landing banner so Home reads as the dashboard, not a findings dump.
function Hero({
  count,
  lastActivity,
  navigate,
}: {
  count: number
  lastActivity: number | null
  navigate: (page: string, domainId?: number) => void
}) {
  return (
    <div className="mb-6 overflow-hidden rounded-2xl border border-hair bg-gradient-to-br from-ink-850 via-ink-900 to-ink-950 p-5 sm:p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-accent-fg/80">
            <Radar size={14} /> Recon Dashboard
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">Engagement overview</h1>
          <p className="mt-1 text-sm text-zinc-400">
            {count === 0 ? 'No targets under recon yet.' : `${count} target${count > 1 ? 's' : ''} under recon`}
            {lastActivity ? ` · last activity ${timeAgo(lastActivity)}` : ''}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" onClick={() => navigate('domains')}>
            <Globe size={15} /> Manage targets
          </Button>
          <Button variant="ghost" onClick={() => navigate('findings')}>
            <Flag size={15} /> All findings <ArrowRight size={13} className="text-zinc-500" />
          </Button>
        </div>
      </div>
    </div>
  )
}

const STAT_TONE: Record<string, { ring: string; text: string; icon: string }> = {
  indigo: { ring: 'ring-accent-500/20', text: 'text-accent-fg', icon: 'text-accent-400' },
  zinc: { ring: 'ring-zinc-700/40', text: 'text-zinc-200', icon: 'text-zinc-400' },
  red: { ring: 'ring-red-800/40', text: 'text-red-300', icon: 'text-red-400' },
  amber: { ring: 'ring-amber-800/40', text: 'text-amber-300', icon: 'text-amber-400' },
  blue: { ring: 'ring-blue-800/40', text: 'text-blue-300', icon: 'text-blue-400' },
}

function StatTile({
  icon: Icon,
  label,
  value,
  tone,
  onClick,
}: {
  icon: LucideIcon
  label: string
  value: number
  tone: keyof typeof STAT_TONE
  onClick?: () => void
}) {
  const t = STAT_TONE[tone]
  return (
    <button
      onClick={onClick}
      className={`group rounded-xl border border-hair bg-ink-850 p-3 text-left shadow-card ring-1 ${t.ring} transition hover:border-hair-strong hover:bg-ink-800`}
    >
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-medium uppercase tracking-wide text-zinc-500">{label}</span>
        <Icon size={15} className={t.icon} />
      </div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${value > 0 ? t.text : 'text-zinc-500'}`}>{value}</div>
    </button>
  )
}

function AttentionCard({
  icon: Icon,
  tone,
  title,
  items,
  onPick,
  empty,
}: {
  icon: LucideIcon
  tone: 'blue' | 'amber' | 'red'
  title: string
  items: { id: number; host: string; note: string }[]
  onPick: (id: number) => void
  empty: string
}) {
  const chip = { blue: 'text-blue-400', amber: 'text-amber-400', red: 'text-red-400' }[tone]
  return (
    <Card className="!p-3">
      <div className="mb-2 flex items-center gap-2">
        <Icon size={15} className={chip} />
        <span className="text-sm font-medium text-zinc-200">{title}</span>
        <span className="ml-auto text-xs text-zinc-500">{items.length}</span>
      </div>
      {items.length === 0 ? (
        <p className="text-xs text-zinc-600">{empty}</p>
      ) : (
        <div className="space-y-1">
          {items.slice(0, 6).map((it) => (
            <button
              key={it.id}
              onClick={() => onPick(it.id)}
              className="flex w-full items-center justify-between rounded-md px-2 py-1 text-left text-sm transition hover:bg-ink-800"
            >
              <span className="min-w-0 truncate font-mono text-zinc-300">{it.host}</span>
              <span className="shrink-0 text-xs text-zinc-500">{it.note}</span>
            </button>
          ))}
        </div>
      )}
    </Card>
  )
}
