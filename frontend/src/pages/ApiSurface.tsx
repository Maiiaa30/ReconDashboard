import { useMemo, useState } from 'react'
import { Braces, Webhook, KeyRound, ShieldAlert, ChevronRight, Code, AlertTriangle, Route, Crosshair } from 'lucide-react'
import { api, ApiError, type Finding } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/Confirm'
import { timeAgo } from '../lib/format'

interface SpecData {
  kind: 'openapi'
  host: string
  specUrl: string
  format: 'openapi' | 'swagger'
  version: string | null
  title: string | null
  apiVersion: string | null
  servers: string[]
  authSchemes: string[]
  operationCount: number
  endpoints: { method: string; path: string }[]
}
interface GqlData {
  kind: 'graphql'
  host: string
  endpoint: string
  introspectionEnabled: boolean
  queryType: string | null
  typeCount: number
}
interface JsData {
  kind: 'js'
  host: string
  filesScanned: number
  endpoints: string[]
  params: string[]
  secrets: { pattern: string; sample: string; file: string }[]
  fromCorpus?: number // how many endpoints came from passive URLs (wayback/crawl), not JS
}

export function ApiSurface() {
  const { selected } = useApp()
  const toast = useToast()
  const ask = useConfirm()
  const [findings, setFindings] = useState<Finding[]>([])
  const [crawlFindings, setCrawlFindings] = useState<Finding[]>([])
  const [ffufFindings, setFfufFindings] = useState<Finding[]>([])
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [crawlBusy, setCrawlBusy] = useState(false)
  const [fuzzBusy, setFuzzBusy] = useState(false)

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
      const { jobId } = await api.apiDiscovery(selected.id)
      toast.success(`API discovery queued (job #${jobId}) — results appear here.`)
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
          <div className="flex flex-wrap gap-2">
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
            <GraphqlCard key={f.id} d={d} at={f.createdAt} score={f.score} />
          ))}
          {specs.map(({ f, d }) => (
            <SpecCard key={f.id} d={d} at={f.createdAt} score={f.score} />
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

function GraphqlCard({ d, at, score }: { d: GqlData; at: string; score: number | null }) {
  return (
    <Card className={d.introspectionEnabled ? 'border-red-900/50' : ''}>
      <div className="flex flex-wrap items-center gap-2">
        <Braces size={16} className="text-purple-400" />
        <Badge tone="purple">GraphQL</Badge>
        <span className="font-mono text-sm text-zinc-100 break-all">{d.endpoint}</span>
        {d.introspectionEnabled ? (
          <Badge tone="red">introspection enabled</Badge>
        ) : (
          <Badge tone="green">introspection disabled</Badge>
        )}
        {score != null && <span className="ml-auto text-xs text-zinc-500">score {score}</span>}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-400">
        <span>host: <span className="font-mono text-zinc-300">{d.host}</span></span>
        {d.queryType && <span>query type: <span className="font-mono text-zinc-300">{d.queryType}</span></span>}
        {d.typeCount > 0 && <span>{d.typeCount} schema types</span>}
        <span className="ml-auto text-zinc-600">{timeAgo(new Date(at).getTime())}</span>
      </div>
      {d.introspectionEnabled && (
        <p className="mt-2 text-xs text-red-300/90">
          Introspection exposes the entire schema (queries, mutations, types) to anyone — usually disabled in production.
        </p>
      )}
    </Card>
  )
}

const METHOD_TONE: Record<string, string> = {
  GET: 'text-green-300 bg-green-500/10',
  POST: 'text-blue-300 bg-blue-500/10',
  PUT: 'text-amber-300 bg-amber-500/10',
  PATCH: 'text-amber-300 bg-amber-500/10',
  DELETE: 'text-red-300 bg-red-500/10',
}

function SpecCard({ d, at, score }: { d: SpecData; at: string; score: number | null }) {
  const [open, setOpen] = useState(false)
  // Defend against any legacy/partial finding missing these arrays.
  const endpoints = Array.isArray(d.endpoints) ? d.endpoints : []
  const servers = Array.isArray(d.servers) ? d.servers : []
  const authSchemes = Array.isArray(d.authSchemes) ? d.authSchemes : []
  const shown = open ? endpoints : endpoints.slice(0, 8)
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <Braces size={16} className="text-accent-400" />
        <Badge tone="indigo">{d.format ?? 'openapi'}</Badge>
        <span className="text-sm font-medium text-zinc-100">{d.title ?? 'API'}</span>
        {d.apiVersion && <span className="text-xs text-zinc-500">v{d.apiVersion}</span>}
        {authSchemes.length === 0 && <Badge tone="amber">no auth scheme</Badge>}
        {score != null && <span className="ml-auto text-xs text-zinc-500">score {score}</span>}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-400">
        <a href={d.specUrl} target="_blank" rel="noreferrer" className="font-mono text-sky-400 hover:underline break-all">
          {d.specUrl} ↗
        </a>
        <span className="ml-auto">{d.operationCount ?? endpoints.length} operations</span>
      </div>
      {authSchemes.length > 0 && (
        <div className="mt-1 text-xs text-zinc-500">auth: {authSchemes.join(', ')}</div>
      )}
      {servers.length > 0 && (
        <div className="mt-1 text-xs text-zinc-500 break-all">servers: {servers.slice(0, 4).join(', ')}</div>
      )}

      {endpoints.length > 0 && (
        <div className="mt-2.5">
          <div className="flex flex-wrap gap-1">
            {shown.map((e, i) => (
              <span key={i} className="inline-flex items-center gap-1 rounded border border-hair bg-ink-900/50 px-1.5 py-0.5 font-mono text-[11px]">
                <span className={`rounded px-1 ${METHOD_TONE[e.method] ?? 'text-zinc-300 bg-ink-800'}`}>{e.method}</span>
                <span className="text-zinc-300 break-all">{e.path}</span>
              </span>
            ))}
          </div>
          {endpoints.length > 8 && (
            <button onClick={() => setOpen((v) => !v)} className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300">
              <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
              {open ? 'show fewer' : `show all ${endpoints.length}`}
            </button>
          )}
        </div>
      )}
      <div className="mt-2 text-right text-[11px] text-zinc-600">{timeAgo(new Date(at).getTime())}</div>
    </Card>
  )
}

function JsCard({ d, at, score }: { d: JsData; at: string; score: number | null }) {
  const [open, setOpen] = useState(false)
  const endpoints = Array.isArray(d.endpoints) ? d.endpoints : []
  const params = Array.isArray(d.params) ? d.params : []
  const secrets = Array.isArray(d.secrets) ? d.secrets : []
  const shown = open ? endpoints : endpoints.slice(0, 12)
  return (
    <Card className={secrets.length ? 'border-red-900/50' : ''}>
      <div className="flex flex-wrap items-center gap-2">
        <Code size={16} className="text-green-400" />
        <Badge tone="green">JS recon</Badge>
        <span className="font-mono text-sm text-zinc-100 break-all">{d.host}</span>
        {secrets.length > 0 && <Badge tone="red">{secrets.length} secret(s)</Badge>}
        {score != null && <span className="ml-auto text-xs text-zinc-500">score {score}</span>}
      </div>
      <div className="mt-1 text-xs text-zinc-500">
        {endpoints.length} API endpoint(s) · {params.length} param(s) · from {d.filesScanned ?? 0} JS file(s)
        {d.fromCorpus ? ` + ${d.fromCorpus} from passive URLs (wayback/crawl)` : ''}
      </div>

      {/* Leaked secrets — highest signal, shown first */}
      {secrets.length > 0 && (
        <div className="mt-2 space-y-1 rounded-lg border border-red-900/40 bg-red-950/20 p-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-red-200">
            <AlertTriangle size={13} className="text-red-400" /> Possible secrets (review — may be false positives)
          </div>
          {secrets.slice(0, 15).map((s, i) => (
            <div key={i} className="flex flex-wrap items-center gap-x-2 font-mono text-[11px] text-red-200/90">
              <span className="text-red-300">{s.pattern}:</span>
              <span className="break-all">{s.sample}</span>
              <span className="text-zinc-500 break-all">({s.file})</span>
            </div>
          ))}
        </div>
      )}

      {endpoints.length > 0 && (
        <div className="mt-2.5">
          <div className="flex flex-wrap gap-1">
            {shown.map((e, i) => (
              <span key={i} className="rounded border border-hair bg-ink-900/50 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300 break-all">
                {e}
              </span>
            ))}
          </div>
          {endpoints.length > 12 && (
            <button onClick={() => setOpen((v) => !v)} className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300">
              <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
              {open ? 'show fewer' : `show all ${endpoints.length}`}
            </button>
          )}
        </div>
      )}

      {params.length > 0 && (
        <div className="mt-2">
          <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">Parameters</div>
          <div className="flex flex-wrap gap-1">
            {params.slice(0, 40).map((p, i) => (
              <span key={i} className="rounded bg-ink-800/70 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">{p}</span>
            ))}
          </div>
        </div>
      )}
      <div className="mt-2 text-right text-[11px] text-zinc-600">{timeAgo(new Date(at).getTime())}</div>
    </Card>
  )
}

// A crawled URL is "API-looking" if it has a query string or an API-ish path.
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

function CrawlCard({ urls }: { urls: string[] }) {
  const [open, setOpen] = useState(false)
  const shown = open ? urls : urls.slice(0, 15)
  const fmt = (u: string) => {
    try {
      const x = new URL(u)
      return x.host + x.pathname + x.search
    } catch {
      return u
    }
  }
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <Route size={16} className="text-blue-400" />
        <Badge tone="blue">katana crawl</Badge>
        <span className="text-sm font-medium text-zinc-100">{urls.length} API-looking URL(s) discovered</span>
      </div>
      <div className="mt-1 text-xs text-zinc-500">
        Active crawl (follows links + parses JS) — finds endpoints static analysis can&apos;t, e.g. dynamically-built ones.
      </div>
      <div className="mt-2.5 space-y-0.5">
        {shown.map((u, i) => (
          <div key={i} className="font-mono text-[11px] text-zinc-300 break-all">
            {fmt(u)}
          </div>
        ))}
      </div>
      {urls.length > 15 && (
        <button
          onClick={() => setOpen((v) => !v)}
          className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
        >
          <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
          {open ? 'show fewer' : `show all ${urls.length}`}
        </button>
      )}
    </Card>
  )
}

const FFUF_STATUS_TONE = (s: number) =>
  s === 200 || s === 204
    ? 'text-green-300 bg-green-500/10'
    : s === 401 || s === 403
      ? 'text-amber-300 bg-amber-500/10'
      : s >= 300 && s < 400
        ? 'text-sky-300 bg-sky-500/10'
        : 'text-zinc-300 bg-ink-800'

function FfufCard({ hits }: { hits: { url: string; status: number }[] }) {
  const [open, setOpen] = useState(false)
  const shown = open ? hits : hits.slice(0, 15)
  const fmt = (u: string) => {
    try {
      const x = new URL(u)
      return x.host + x.pathname + x.search
    } catch {
      return u
    }
  }
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <Crosshair size={16} className="text-orange-400" />
        <Badge tone="amber">ffuf fuzz</Badge>
        <span className="text-sm font-medium text-zinc-100">{hits.length} API path(s) that responded</span>
      </div>
      <div className="mt-1 text-xs text-zinc-500">
        Active brute-force of common API paths — each hit is a path that actually answered (200 = open, 401/403 = exists but
        protected), so it&apos;s a confirmed endpoint, not just a reference.
      </div>
      <div className="mt-2.5 space-y-0.5">
        {shown.map((h, i) => (
          <div key={i} className="flex items-center gap-2 font-mono text-[11px]">
            <span className={`rounded px-1 ${FFUF_STATUS_TONE(h.status)}`}>{h.status || '—'}</span>
            <span className="text-zinc-300 break-all">{fmt(h.url)}</span>
          </div>
        ))}
      </div>
      {hits.length > 15 && (
        <button
          onClick={() => setOpen((v) => !v)}
          className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
        >
          <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
          {open ? 'show fewer' : `show all ${hits.length}`}
        </button>
      )}
    </Card>
  )
}

// --- Client-side JWT inspector (decode only; never verifies/needs a secret) ---
function b64urlToJson(part: string): Record<string, unknown> | null {
  try {
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
    const bin = atob(b64)
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return null
  }
}

function JwtInspector() {
  const [token, setToken] = useState('')
  const parsed = useMemo(() => {
    const t = token.trim()
    if (!t) return null
    const parts = t.split('.')
    if (parts.length < 2) return { error: 'Not a JWT (expected header.payload.signature).' }
    const header = b64urlToJson(parts[0])
    const payload = b64urlToJson(parts[1])
    if (!header || !payload) return { error: 'Could not decode the JWT segments (invalid base64url).' }
    return { header, payload, hasSig: parts.length >= 3 && !!parts[2] }
  }, [token])

  const alg = parsed && 'header' in parsed ? String((parsed.header as any).alg ?? '') : ''
  const exp = parsed && 'payload' in parsed ? Number((parsed.payload as any).exp) : NaN
  const expired = Number.isFinite(exp) && exp * 1000 < Date.now()

  return (
    <Card>
      <div className="mb-2 flex items-center gap-2">
        <KeyRound size={16} className="text-amber-400" />
        <h2 className="text-sm font-semibold text-zinc-200">JWT inspector</h2>
        <span className="text-xs text-zinc-600">decodes locally — nothing is sent anywhere</span>
      </div>
      <textarea
        value={token}
        onChange={(e) => setToken(e.target.value)}
        placeholder="Paste a JWT (eyJ…) to decode its header and claims"
        rows={3}
        className="block w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
      />
      {parsed && 'error' in parsed && <p className="mt-2 text-sm text-amber-400">{parsed.error}</p>}
      {parsed && 'header' in parsed && (
        <div className="mt-3 space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge tone={alg.toLowerCase() === 'none' ? 'red' : 'zinc'}>alg: {alg || '—'}</Badge>
            {alg.toLowerCase() === 'none' && <span className="text-red-300">⚠ &quot;none&quot; algorithm — signature not enforced</span>}
            {Number.isFinite(exp) && <Badge tone={expired ? 'red' : 'green'}>{expired ? 'expired' : 'exp valid'}</Badge>}
            {!parsed.hasSig && <Badge tone="amber">no signature segment</Badge>}
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            <JsonBlock label="Header" value={parsed.header} />
            <JsonBlock label="Payload (claims)" value={parsed.payload} />
          </div>
        </div>
      )}
    </Card>
  )
}

function JsonBlock({ label, value }: { label: string; value: unknown }) {
  return (
    <div>
      <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">{label}</div>
      <pre className="max-h-56 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 text-[11px] text-zinc-300">
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  )
}
