import { useCallback, useMemo, useState } from 'react'
import { Copy, Check, Eye, EyeOff, ShieldAlert, RefreshCw, Search, ExternalLink, Mail } from 'lucide-react'
import { api, type Finding, type FreeEmailResult, type LeaksResponse } from '../api'
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
          Breach-exposure lookup for <strong>authorized</strong> engagements. The domain / email is sent to the
          provider. Recovered credentials are for exposure assessment — never authenticate with them outside
          explicit authorization.
        </span>
      </div>

      {/* Free tools — always available, no API key required */}
      <FreeTools domainId={selected.id} domainHost={selected.host} onStored={load} />

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

// Free, keyless lookups that work without any provider configured.
function FreeTools({ domainId, domainHost, onStored }: { domainId: number; domainHost: string; onStored: () => void }) {
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState<FreeEmailResult | null>(null)
  const [err, setErr] = useState('')

  async function check() {
    const e = email.trim()
    if (!e || busy) return
    setBusy(true)
    setErr('')
    setRes(null)
    try {
      const r = await api.checkEmailLeak(domainId, e)
      setRes(r.result)
      onStored() // refresh the findings table (metadata rows are stored)
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : 'lookup failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card className="mb-5">
      <div className="mb-1 flex items-center gap-2">
        <h3 className="text-sm font-semibold text-zinc-100">Free lookups</h3>
        <Badge tone="green">no API key</Badge>
      </div>
      <p className="mb-3 text-xs text-zinc-500">
        Metadata only — which breaches an address appears in (never the password). For full credentials, configure
        a paid provider above.
      </p>

      <div className="grid gap-4 sm:grid-cols-2">
        {/* Free per-email breach check */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-zinc-400">Email breach check</label>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Mail size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && check()}
                placeholder={`someone@${domainHost}`}
                className="w-full rounded-lg border border-hair bg-ink-850 py-1.5 pl-8 pr-2 text-sm outline-none transition placeholder:text-zinc-600 focus:border-accent-500"
              />
            </div>
            <button
              onClick={check}
              disabled={busy || !email.trim()}
              className="shrink-0 rounded-lg border border-hair px-3 py-1.5 text-sm text-zinc-200 transition hover:bg-ink-800 hover:border-hair-strong disabled:opacity-40"
            >
              {busy ? 'Checking…' : 'Check'}
            </button>
          </div>
          {err && <p className="mt-2 text-xs text-red-400">{err}</p>}
          {res && (
            <div className="mt-2 text-xs">
              {res.found === 0 ? (
                <p className="text-green-400">No breaches found for {res.email}.</p>
              ) : (
                <>
                  <p className="text-amber-300">
                    {res.found} breach{res.found === 1 ? '' : 'es'} — stored in the table below.
                  </p>
                  {res.fields.length > 0 && (
                    <p className="mt-1 text-zinc-500">
                      Exposed fields: <span className="text-zinc-300">{res.fields.join(', ')}</span>
                    </p>
                  )}
                  <ul className="mt-1.5 flex flex-wrap gap-1.5">
                    {res.sources.map((s, i) => (
                      <li key={i} className="rounded bg-ink-800 px-1.5 py-0.5 text-[11px] text-zinc-300">
                        {s.name}
                        {s.date ? ` (${s.date})` : ''}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
        </div>

        {/* Free HIBP domain dashboard (manual) */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-zinc-400">Whole-domain (HIBP)</label>
          <a
            href="https://haveibeenpwned.com/DomainSearch"
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-2 rounded-lg border border-hair px-3 py-1.5 text-sm text-zinc-200 transition hover:bg-ink-800 hover:border-hair-strong"
          >
            Open HIBP domain search <ExternalLink size={13} className="text-zinc-500" />
          </a>
          <p className="mt-2 text-[11px] leading-snug text-zinc-500">
            Free list of every breached account on <span className="font-mono text-zinc-400">{domainHost}</span> once
            you verify domain ownership on HIBP (one-time). No passwords, manual, not auto-run.
          </p>
        </div>
      </div>
    </Card>
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
