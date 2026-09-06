import { useEffect, useMemo, useState } from 'react'
import { Webhook, ShieldAlert, Route, Crosshair } from 'lucide-react'
import { api, ApiError, type Finding, type Subdomain } from '../api'
import { useApp, usePoll } from '../state'
import { Button, Empty, PageHeader } from '../components/ui'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/Confirm'
import { setPendingReplay, type PendingReplay } from '../lib/replayHandoff'
import type { SpecData, GqlData, JsData } from './apisurface/types'
import { GraphqlCard } from './apisurface/GraphqlCard'
import { SpecCard } from './apisurface/SpecCard'
import { JsCard } from './apisurface/JsCard'
import { CrawlCard } from './apisurface/CrawlCard'
import { FfufCard } from './apisurface/FfufCard'
import { JwtInspector } from './apisurface/JwtInspector'

export function ApiSurface({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const toast = useToast()
  const ask = useConfirm()
  // Drop a starter request into the Repeater and jump there.
  const sendToReplay = (r: PendingReplay) => {
    setPendingReplay(r)
    navigate('replay')
  }

  // Optional single-host target for discovery ('' = apex + all live subdomains).
  const [subs, setSubs] = useState<Subdomain[]>([])
  const [scanHost, setScanHost] = useState('')
  useEffect(() => {
    setScanHost('')
    if (!selected) {
      setSubs([])
      return
    }
    api
      .subdomains(selected.id)
      .then((r) => setSubs(r.subdomains))
      .catch(() => {})
  }, [selected])
  const [findings, setFindings] = useState<Finding[]>([])
  const [crawlFindings, setCrawlFindings] = useState<Finding[]>([])
  const [ffufFindings, setFfufFindings] = useState<Finding[]>([])
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [crawlBusy, setCrawlBusy] = useState(false)
  const [fuzzBusy, setFuzzBusy] = useState(false)
  const hostOptions = useMemo(() => {
    if (!selected) return []
    const base = selected.host.toLowerCase()
    const inScope = (h: string) => h === base || h.endsWith('.' + base)
    const extra = new Set<string>()
    // Live discovered subdomains.
    for (const s of subs) if (s.httpStatus != null && s.host !== selected.host) extra.add(s.host)
    // API-base hosts the app itself declares in its exposed config (e.g.
    // VITE_PUBLIC_*_API_BASE=https://api.target.com) — often where the real API
    // lives, and frequently NOT in the subdomain list, so surface them here too.
    for (const f of findings) {
      const d = f.data as { kind?: string; env?: { value: string | null }[] }
      if (d?.kind !== 'js' || !Array.isArray(d.env)) continue
      for (const e of d.env) {
        const m = typeof e?.value === 'string' ? e.value.match(/^https?:\/\/([a-z0-9.-]+)/i) : null
        if (m && inScope(m[1].toLowerCase()) && m[1].toLowerCase() !== base) extra.add(m[1].toLowerCase())
      }
    }
    return [selected.host, ...[...extra].sort()]
  }, [selected, subs, findings])

  usePoll(
    () => {
      if (!selected) return
      api
        .findings({ domainId: selected.id, type: 'api', limit: 200 })
        .then((r) => setFindings(r.findings))
        .catch(() => {})
        .finally(() => setLoaded(true))
      // katana crawl results are stored as 'tool' findings.
      api
        .findings({ domainId: selected.id, type: 'tool', limit: 50 })
        .then((r) => setCrawlFindings(r.findings.filter((f) => (f.data as any)?.tool === 'katana')))
        .catch(() => {})
      // API path-fuzz results are stored as 'ffuf' findings (shared with the Fuzzing page).
      api
        .findings({ domainId: selected.id, type: 'ffuf', limit: 200 })
        .then((r) => setFfufFindings(r.findings))
        .catch(() => {})
    },
    6000,
    !!selected,
    selected?.id,
  )

  // Classify by an actual identifying field (not just "not graphql") so a
  // malformed / legacy finding can't fall through to SpecCard and crash it.
  const specs = useMemo(
    () => findings.filter((f) => !!(f.data as any)?.specUrl).map((f) => ({ f, d: f.data as unknown as SpecData })),
    [findings],
  )
  const gqls = useMemo(
    () =>
      findings
        .filter((f) => (f.data as any)?.kind === 'graphql' || (!!(f.data as any)?.endpoint && !(f.data as any)?.specUrl))
        .map((f) => ({ f, d: f.data as unknown as GqlData })),
    [findings],
  )
  const jsCards = useMemo(() => {
    const all = findings
      .filter((f) => (f.data as any)?.kind === 'js')
      .map((f) => ({ f, d: f.data as unknown as JsData }))
    // apex and www (or any hosts serving the same bundles behind a wildcard cert)
    // mine byte-identical JS, so they'd render as duplicate cards. Collapse by a
    // host-independent content signature, keeping the shortest host (the apex).
    const sig = (d: JsData) =>
      JSON.stringify([
        [...(d.endpoints ?? [])].sort(),
        [...(d.params ?? [])].sort(),
        [...(d.secrets ?? [])].map((s) => `${s.pattern}:${s.sample}`).sort(),
      ])
    const best = new Map<string, { f: Finding; d: JsData }>()
    for (const card of all) {
      const key = sig(card.d)
      const cur = best.get(key)
      if (!cur || (card.d.host?.length ?? 0) < (cur.d.host?.length ?? 0)) best.set(key, card)
    }
    return all.filter((c) => best.get(sig(c.d)) === c)
  }, [findings])
  const introspectable = gqls.filter((g) => g.d.introspectionEnabled).length
  const jsSecrets = jsCards.reduce((n, j) => n + (Array.isArray(j.d.secrets) ? j.d.secrets.length : 0), 0)
  // Katana-crawled URLs (dedup across findings), narrowed to API-looking ones.
  const crawlEndpoints = useMemo(() => {
    const urls = new Set<string>()
    for (const f of crawlFindings) {
      for (const u of ((f.data as any)?.items ?? []) as unknown[]) if (typeof u === 'string') urls.add(u)
    }
    return [...urls].filter(isApiUrl)
  }, [crawlFindings])
  // ffuf path-fuzz hits (dedup by URL), narrowed to API-looking ones. Each hit is
  // a path that actually responded (200/401/403 = exists), so it's a confirmed
  // endpoint, not just a reference.
  const fuzzHits = useMemo(() => {
    const seen = new Map<string, { url: string; status: number }>()
    for (const f of ffufFindings) {
      const d = f.data as any
      if (typeof d?.url === 'string' && isApiUrl(d.url) && !seen.has(d.url)) {
        seen.set(d.url, { url: d.url, status: Number(d.status) || 0 })
      }
    }
    return [...seen.values()].sort((a, b) => a.url.localeCompare(b.url))
  }, [ffufFindings])
  const empty =
    specs.length === 0 &&
    gqls.length === 0 &&
    jsCards.length === 0 &&
    crawlEndpoints.length === 0 &&
    fuzzHits.length === 0

  async function discover() {
    if (!selected || busy) return
    setBusy(true)
    try {
      const { jobId } = await api.apiDiscovery(selected.id, scanHost || undefined)
      toast.success(`API discovery queued (job #${jobId})${scanHost ? ` for ${scanHost}` : ''} — results appear here.`)
    } catch {
      toast.error('Failed to queue API discovery.')
    } finally {
      setBusy(false)
    }
  }

  // Deep crawl with katana — ACTIVE (headless-ish crawl + JS parsing), so it's
  // gated like the loud scans: a passive domain needs an explicit confirm.
  async function deepCrawl() {
    if (!selected || crawlBusy) return
    const activeMode = selected.mode === 'active_authorized'
    if (!activeMode) {
      const ok = await ask({
        title: 'Run an active crawl?',
        message: `${selected.host} is passive_only.\n\nkatana actively crawls the site (many requests + JS parsing) to find endpoints static analysis can't. Only run it if you are authorized to actively test this target.`,
        confirmLabel: 'Crawl anyway',
        tone: 'danger',
      })
      if (!ok) return
    }
    setCrawlBusy(true)
    try {
      const { jobId } = await api.runTool(selected.id, { tool: 'katana', confirm: !activeMode })
      toast.success(`Deep crawl queued (job #${jobId}) — discovered endpoints appear here when it finishes.`)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to queue crawl.')
    } finally {
      setCrawlBusy(false)
    }
  }

  // Active API path fuzz with ffuf + an API-focused wordlist — finds endpoints
  // nothing references. Loud (hundreds of requests), so gated like the crawl:
  // a passive domain needs an explicit confirm.
  async function fuzzApi() {
    if (!selected || fuzzBusy) return
    const activeMode = selected.mode === 'active_authorized'
    if (!activeMode) {
      const ok = await ask({
        title: 'Run an active API fuzz?',
        message: `${selected.host} is passive_only.\n\nffuf brute-forces common API paths (hundreds of requests) against the host to find endpoints nothing references. Only run it if you are authorized to actively test this target.`,
        confirmLabel: 'Fuzz anyway',
        tone: 'danger',
      })
      if (!ok) return
    }
    setFuzzBusy(true)
    try {
      const { jobId } = await api.ffuf(selected.id, {
        wordlist: '/usr/share/wordlists/api-endpoints.txt',
        path: 'FUZZ',
        confirm: !activeMode,
      })
      toast.success(`API fuzz queued (job #${jobId}) — discovered paths appear here when it finishes.`)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to queue API fuzz.')
    } finally {
      setFuzzBusy(false)
    }
  }

  if (!selected) return <Empty>Select a domain to map its API surface.</Empty>

  return (
    <div>
      <PageHeader
        title="API Surface"
        subtitle={`${selected.host} — specs, GraphQL, endpoints mined from JS & a JWT inspector`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={scanHost}
              onChange={(e) => setScanHost(e.target.value)}
              title="Limit API discovery to a single host, or scan the whole domain"
              className="rounded-lg border border-hair bg-ink-950 px-2.5 py-2 text-sm text-zinc-300 outline-none focus:border-accent-500"
            >
              <option value="">All hosts (apex + subdomains)</option>
              {hostOptions.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>
            <Button variant="loud" onClick={discover} disabled={busy}>
              <Webhook size={15} /> {busy ? 'Queuing…' : 'Discover API surface'}
            </Button>
            <Button
              variant="ghost"
              onClick={deepCrawl}
              disabled={crawlBusy}
              title="Active: crawl the site with katana (follows links + parses JS) to find endpoints static analysis misses. Loud — gated like a scan."
            >
              <Route size={15} /> {crawlBusy ? 'Queuing…' : 'Deep crawl (katana)'}
            </Button>
            <Button
              variant="ghost"
              onClick={fuzzApi}
              disabled={fuzzBusy}
              title="Active: brute-force common API paths with ffuf to find endpoints nothing references. Loud — gated like a scan."
            >
              <Crosshair size={15} /> {fuzzBusy ? 'Queuing…' : 'Fuzz API paths (ffuf)'}
            </Button>
          </div>
        }
      />

      {/* Summary */}
      <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
        <span className="text-zinc-400">
          <span className="font-semibold text-zinc-200">{specs.length}</span> spec{specs.length === 1 ? '' : 's'}
        </span>
        <span className="text-zinc-400">
          <span className="font-semibold text-zinc-200">{gqls.length}</span> GraphQL endpoint{gqls.length === 1 ? '' : 's'}
        </span>
        <span className="text-zinc-400">
          <span className="font-semibold text-zinc-200">{jsCards.reduce((n, j) => n + (j.d.endpoints?.length ?? 0), 0)}</span> JS
          endpoint(s)
        </span>
        {introspectable > 0 && (
          <span className="inline-flex items-center gap-1.5 text-red-300">
            <ShieldAlert size={14} /> {introspectable} with introspection enabled
          </span>
        )}
        {crawlEndpoints.length > 0 && (
          <span className="text-zinc-400">
            <span className="font-semibold text-zinc-200">{crawlEndpoints.length}</span> crawled (katana)
          </span>
        )}
        {fuzzHits.length > 0 && (
          <span className="text-zinc-400">
            <span className="font-semibold text-zinc-200">{fuzzHits.length}</span> fuzzed (ffuf)
          </span>
        )}
        {jsSecrets > 0 && (
          <span className="inline-flex items-center gap-1.5 text-red-300">
            <ShieldAlert size={14} /> {jsSecrets} possible secret(s) in JS
          </span>
        )}
        <span className="text-xs text-zinc-600">Discover = passive · Deep crawl = active (katana)</span>
      </div>

      {loaded && empty ? (
        <Empty>
          <div className="space-y-1.5">
            <div>No API surface found for this target yet.</div>
            <div className="text-xs leading-relaxed text-zinc-500">
              <span className="text-zinc-300">Discover API surface</span> probes for OpenAPI/Swagger specs, GraphQL, and API
              endpoints mined from the site&apos;s JavaScript. Two tips if it comes back empty: run{' '}
              <span className="text-zinc-300">Subdomains</span> discovery first so it also checks{' '}
              <span className="font-mono">api.*</span> / <span className="font-mono">backend.*</span> hosts; and note that
              heavily-minified SPAs (e.g. large apps) often expose no endpoints in static JS — for those, run{' '}
              <span className="text-zinc-300">katana</span> on the Tools page, which crawls with a real browser and captures the
              live requests.
            </div>
          </div>
        </Empty>
      ) : (
        <div className="space-y-3">
          {gqls.map(({ f, d }) => (
            <GraphqlCard key={f.id} d={d} at={f.createdAt} score={f.score} onReplay={sendToReplay} />
          ))}
          {specs.map(({ f, d }) => (
            <SpecCard key={f.id} d={d} at={f.createdAt} score={f.score} onReplay={sendToReplay} />
          ))}
          {jsCards.map(({ f, d }) => (
            <JsCard key={f.id} d={d} at={f.createdAt} score={f.score} />
          ))}
          {crawlEndpoints.length > 0 && <CrawlCard urls={crawlEndpoints} />}
          {fuzzHits.length > 0 && <FfufCard hits={fuzzHits} />}
        </div>
      )}

      <div className="mt-8">
        <JwtInspector />
      </div>
    </div>
  )
}

function isApiUrl(u: string): boolean {
  try {
    const url = new URL(u)
    if (/\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|pdf|xml|txt)$/i.test(url.pathname)) return false
    if (url.search) return true
    return /(^|\/)(api|apis|rest|graphql|graphiql|gql|v\d+|internal|services?|oauth|auth|token|admin|webhook|callback|wp-json|actuator|swagger|openapi|\.well-known)(\/|$)|\.(json|yaml|yml)$/i.test(
      url.pathname,
    )
  } catch {
    return false
  }
}
