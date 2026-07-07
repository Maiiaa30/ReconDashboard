import { useCallback, useMemo, useState } from 'react'
import { Copy, Check, Eye, EyeOff, ShieldAlert, RefreshCw, Search } from 'lucide-react'
import { api, type Finding, type LeaksResponse } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Card, Empty, PageHeader, ScoreBadge } from '../components/ui'
import { timeAgo } from '../lib/format'

// Domain breach/leak exposure. Queries a configured provider (HIBP / DeHashed /
// LeakCheck) for accounts on the selected domain and lists the exposed records.
// Active domains are auto-checked daily; passive domains use "Check now".
export function DataLeaks() {
  const { selected } = useApp()
  const [state, setState] = useState<LeaksResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [reveal, setReveal] = useState(false)
  const [query, setQuery] = useState('')

  const load = useCallback(() => {
    if (!selected) {
      setState(null)
      return
    }
    api.leaks(selected.id).then(setState).catch(() => setState(null))
  }, [selected])
  usePoll(load, 6000, true)

  async function checkNow() {
    if (!selected || busy) return
    setBusy(true)
    setErr('')
    try {
      await api.checkLeaks(selected.id)
      load()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'failed to start check')
    } finally {
      setBusy(false)
    }
  }

  const q = query.trim().toLowerCase()
  const rows = useMemo(() => {
    const f = state?.findings ?? []
    if (!q) return f
    return f.filter((r) =>
      [r.data?.email, r.data?.username, r.data?.source, r.data?.name, r.data?.password]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(q),
    )
  }, [state, q])

  if (!selected) {
    return (
      <div>
        <PageHeader title="Data Leaks" subtitle="Breach exposure by domain" />
        <Empty>Select a target domain to check for leaked credentials.</Empty>
      </div>
    )
  }

  const withPw = (state?.findings ?? []).filter((r) => r.data?.password || r.data?.hashedPassword).length

  return (
    <div>
      <PageHeader
        title="Data Leaks"
        subtitle={`Breach exposure — ${selected.host}`}
        actions={
          <button
            onClick={checkNow}
            disabled={busy || !state?.enabled || state?.pending}
            className="inline-flex items-center gap-2 rounded-lg bg-accent-500 px-3 py-1.5 text-sm font-medium text-white shadow-sm shadow-accent-500/20 transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-40"
            title={state?.enabled ? 'Query the configured provider now' : 'Configure a provider first'}
          >
            <RefreshCw size={15} className={state?.pending ? 'animate-spin' : ''} />
            {state?.pending ? 'Checking…' : 'Check now'}
          </button>
        }
      />

      <div className="mb-4 flex items-start gap-2 rounded-xl border border-amber-900/50 bg-amber-950/20 p-3 text-xs text-amber-200/90">
        <ShieldAlert size={16} className="mt-0.5 shrink-0 text-amber-400" />
        <span>
          Breach-exposure lookup for <strong>authorized</strong> engagements. The domain is sent to the configured
          provider. Recovered credentials are for exposure assessment — never authenticate with them outside
          explicit authorization.
        </span>
      </div>

      {/* Status strip */}
      <div className="mb-5 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        {state?.enabled ? (
          <span className="inline-flex items-center gap-1.5 text-zinc-400">
            Provider <Badge tone="indigo">{state.provider}</Badge>
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 text-zinc-400">
            Provider <Badge tone="zinc">not configured</Badge>
          </span>
        )}
        {state?.autoDaily ? (
          <Badge tone="green">auto-checked daily</Badge>
        ) : (
          <Badge tone="zinc">manual only (passive domain)</Badge>
        )}
        <span className="text-zinc-500">Last check: {timeAgo(state?.lastCheckedAt ? new Date(state.lastCheckedAt).getTime() : null)}</span>
        {err && <span className="text-red-400">{err}</span>}
      </div>

      {!state?.enabled && (
        <Card className="mb-5 border-hair-strong">
          <h3 className="text-sm font-semibold text-zinc-100">No breach provider configured</h3>
          <p className="mt-1.5 text-xs leading-relaxed text-zinc-400">
            Set <code className="rounded bg-ink-900 px-1 text-zinc-300">LEAK_PROVIDER</code> (one of{' '}
            <code className="rounded bg-ink-900 px-1 text-zinc-300">hibp</code>,{' '}
            <code className="rounded bg-ink-900 px-1 text-zinc-300">dehashed</code>,{' '}
            <code className="rounded bg-ink-900 px-1 text-zinc-300">leakcheck</code>) and{' '}
            <code className="rounded bg-ink-900 px-1 text-zinc-300">LEAK_API_KEY</code> in your{' '}
            <code className="rounded bg-ink-900 px-1 text-zinc-300">.env</code>, then recreate the backend
            (<code className="rounded bg-ink-900 px-1 text-zinc-300">docker compose up -d</code>). See{' '}
            <code className="rounded bg-ink-900 px-1 text-zinc-300">.env.example</code> for details.
          </p>
        </Card>
      )}

      {/* Results */}
      {(state?.findings ?? []).length === 0 ? (
        <Empty>
          {state?.enabled
            ? 'No leaked records recorded yet. Run “Check now”.'
            : 'No leaked records recorded for this domain.'}
        </Empty>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm text-zinc-400">
              <span className="font-semibold text-zinc-200">{state!.findings.length}</span> exposed record
              {state!.findings.length === 1 ? '' : 's'}
              {withPw > 0 && <span className="ml-1 text-amber-400">· {withPw} with password</span>}
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setReveal((v) => !v)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-hair px-2.5 py-1.5 text-xs text-zinc-300 transition hover:bg-ink-800 hover:border-hair-strong"
              >
                {reveal ? <EyeOff size={13} /> : <Eye size={13} />}
                {reveal ? 'Hide passwords' : 'Reveal passwords'}
              </button>
              <div className="relative">
                <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter…"
                  className="w-40 rounded-lg border border-hair bg-ink-850 py-1.5 pl-8 pr-2 text-xs outline-none transition placeholder:text-zinc-600 focus:border-accent-500"
                />
              </div>
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-hair">
            <table className="w-full min-w-[760px] text-sm">
              <thead className="bg-ink-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
                <tr>
                  <th className="px-3 py-2 w-14"></th>
                  <th className="px-3 py-2">Account</th>
                  <th className="px-3 py-2">Password</th>
                  <th className="px-3 py-2 w-40">Breach / source</th>
                  <th className="px-3 py-2 w-28">Date</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <LeakRow key={r.id} finding={r} reveal={reveal} />
                ))}
              </tbody>
            </table>
          </div>
          {rows.length === 0 && <p className="mt-3 text-xs text-zinc-500">No records match “{query}”.</p>}
        </>
      )}
    </div>
  )
}

function LeakRow({ finding, reveal }: { finding: Finding; reveal: boolean }) {
  const d = finding.data ?? {}
  const account = d.email ?? d.username ?? '—'
  const secondary = d.email && d.username && d.email !== d.username ? d.username : d.name ?? null
  const pw: string | null = d.password ?? null
  const hashed: string | null = d.hashedPassword ?? null

  return (
    <tr className="border-t border-hair/60 align-top">
      <td className="px-3 py-2">
        <ScoreBadge score={finding.score} />
      </td>
      <td className="px-3 py-2">
        <div className="font-mono text-xs text-zinc-100 break-all">{account}</div>
        {secondary && <div className="text-[11px] text-zinc-500 break-all">{secondary}</div>}
        {d.ip && <div className="text-[11px] text-zinc-600">{d.ip}</div>}
      </td>
      <td className="px-3 py-2">
        {pw ? (
          <Secret value={pw} reveal={reveal} />
        ) : hashed ? (
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-[11px] text-zinc-500">{reveal ? hashed : '••••••••'}</span>
            <Badge tone="zinc">hash</Badge>
          </div>
        ) : (
          <span className="text-xs text-zinc-600">—</span>
        )}
      </td>
      <td className="px-3 py-2 text-xs text-zinc-300">{d.source ?? '—'}</td>
      <td className="px-3 py-2 text-xs text-zinc-500">{d.breachDate ?? '—'}</td>
    </tr>
  )
}

function Secret({ value, reveal }: { value: string; reveal: boolean }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked */
    }
  }
  return (
    <div className="flex items-center gap-1.5">
      <span className="font-mono text-xs text-amber-300 break-all">{reveal ? value : '•'.repeat(Math.min(12, value.length))}</span>
      <button
        onClick={copy}
        title="Copy password"
        className="shrink-0 rounded border border-hair bg-ink-900 p-1 text-zinc-500 transition hover:text-zinc-200 hover:border-hair-strong"
      >
        {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
      </button>
    </div>
  )
}
