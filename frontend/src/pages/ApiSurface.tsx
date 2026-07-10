import { useMemo, useState } from 'react'
import { Braces, Webhook, KeyRound, ShieldAlert, ChevronRight } from 'lucide-react'
import { api, type Finding } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'
import { useToast } from '../components/Toast'
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

export function ApiSurface() {
  const { selected } = useApp()
  const toast = useToast()
  const [findings, setFindings] = useState<Finding[]>([])
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)

  usePoll(
    () => {
      if (!selected) return
      api
        .findings({ domainId: selected.id, type: 'api', limit: 200 })
        .then((r) => setFindings(r.findings))
        .catch(() => {})
        .finally(() => setLoaded(true))
    },
    6000,
    !!selected,
    selected?.id,
  )

  const specs = useMemo(
    () => findings.filter((f) => (f.data as any)?.kind !== 'graphql').map((f) => ({ f, d: f.data as unknown as SpecData })),
    [findings],
  )
  const gqls = useMemo(
    () => findings.filter((f) => (f.data as any)?.kind === 'graphql').map((f) => ({ f, d: f.data as unknown as GqlData })),
    [findings],
  )
  const introspectable = gqls.filter((g) => g.d.introspectionEnabled).length

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

  if (!selected) return <Empty>Select a domain to map its API surface.</Empty>

  return (
    <div>
      <PageHeader
        title="API Surface"
        subtitle={`${selected.host} — OpenAPI/Swagger specs, GraphQL endpoints & a JWT inspector`}
        actions={
          <Button variant="loud" onClick={discover} disabled={busy}>
            <Webhook size={15} /> {busy ? 'Queuing…' : 'Discover API surface'}
          </Button>
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
        {introspectable > 0 && (
          <span className="inline-flex items-center gap-1.5 text-red-300">
            <ShieldAlert size={14} /> {introspectable} with introspection enabled
          </span>
        )}
        <span className="text-xs text-zinc-600">passive — probes the apex + likely API subdomains</span>
      </div>

      {loaded && specs.length === 0 && gqls.length === 0 ? (
        <Empty>
          No API surface found yet. Click <span className="text-zinc-300">Discover API surface</span> to probe for OpenAPI/Swagger
          specs and GraphQL endpoints.
        </Empty>
      ) : (
        <div className="space-y-3">
          {gqls.map(({ f, d }) => (
            <GraphqlCard key={f.id} d={d} at={f.createdAt} score={f.score} />
          ))}
          {specs.map(({ f, d }) => (
            <SpecCard key={f.id} d={d} at={f.createdAt} score={f.score} />
          ))}
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
  const shown = open ? d.endpoints : d.endpoints.slice(0, 8)
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <Braces size={16} className="text-accent-400" />
        <Badge tone="indigo">{d.format ?? 'openapi'}</Badge>
        <span className="text-sm font-medium text-zinc-100">{d.title ?? 'API'}</span>
        {d.apiVersion && <span className="text-xs text-zinc-500">v{d.apiVersion}</span>}
        {d.authSchemes.length === 0 && <Badge tone="amber">no auth scheme</Badge>}
        {score != null && <span className="ml-auto text-xs text-zinc-500">score {score}</span>}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-400">
        <a href={d.specUrl} target="_blank" rel="noreferrer" className="font-mono text-sky-400 hover:underline break-all">
          {d.specUrl} ↗
        </a>
        <span className="ml-auto">{d.operationCount} operations</span>
      </div>
      {d.authSchemes.length > 0 && (
        <div className="mt-1 text-xs text-zinc-500">auth: {d.authSchemes.join(', ')}</div>
      )}
      {d.servers.length > 0 && (
        <div className="mt-1 text-xs text-zinc-500 break-all">servers: {d.servers.slice(0, 4).join(', ')}</div>
      )}

      {d.endpoints.length > 0 && (
        <div className="mt-2.5">
          <div className="flex flex-wrap gap-1">
            {shown.map((e, i) => (
              <span key={i} className="inline-flex items-center gap-1 rounded border border-hair bg-ink-900/50 px-1.5 py-0.5 font-mono text-[11px]">
                <span className={`rounded px-1 ${METHOD_TONE[e.method] ?? 'text-zinc-300 bg-ink-800'}`}>{e.method}</span>
                <span className="text-zinc-300 break-all">{e.path}</span>
              </span>
            ))}
          </div>
          {d.endpoints.length > 8 && (
            <button onClick={() => setOpen((v) => !v)} className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300">
              <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
              {open ? 'show fewer' : `show all ${d.endpoints.length}`}
            </button>
          )}
        </div>
      )}
      <div className="mt-2 text-right text-[11px] text-zinc-600">{timeAgo(new Date(at).getTime())}</div>
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
