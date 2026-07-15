// Parameter discovery (Arjun-style): find query parameters a target HONORS but
// doesn't document — ?debug=, ?is_admin=, mass-assignment fields — the raw
// material for IDOR/SSRF/auth-bypass. Chunk many candidate params per request,
// then bisect on any deviation to pin down which one mattered.
//
// The network probe is INJECTED so the bisection logic is unit-testable and this
// module never calls fetch directly (the SSRF-guarded probe lives in the handler).

export interface ParamHit {
  param: string
  reason: 'reflected' | 'status' | 'length'
  evidence: string
}

export interface ProbeResult {
  status: number
  body: string
}

export type Probe = (params: Record<string, string>) => Promise<ProbeResult | null>

// Where a candidate parameter is placed. Mass-assignment / IDOR params live in the
// request body; a few auth/routing params only take effect as headers.
export type Transport = 'query' | 'json' | 'form' | 'header'

// Request-header params that commonly change server behavior (access control /
// routing / host confusion) — the candidate list for the 'header' transport.
export const HEADER_PARAMS: readonly string[] = [
  'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Forwarded-Port', 'X-Forwarded-Server',
  'X-Original-URL', 'X-Rewrite-URL', 'X-Original-Host', 'X-Host', 'X-Real-IP', 'X-Client-IP',
  'X-Remote-IP', 'X-Remote-Addr', 'X-Custom-IP-Authorization', 'X-Override-URL', 'X-HTTP-Method-Override',
]

// A minimal fetch the probe factory drives — injected so makeProbe is testable
// without a network (the handler supplies the SSRF-guarded implementation).
export type ProbeFetch = (url: string, init: { method: string; headers: Record<string, string>; body?: string }) => Promise<ProbeResult | null>

// Build a Probe that places the candidate params in the chosen transport. The
// bisection engine is transport-agnostic — it just calls the Probe — so adding
// body/header discovery is purely this factory.
export function makeProbe(transport: Transport, baseUrl: string, doFetch: ProbeFetch): Probe {
  return async (kv) => {
    if (transport === 'query') {
      let u: URL
      try {
        u = new URL(baseUrl)
      } catch {
        return null
      }
      for (const [k, v] of Object.entries(kv)) u.searchParams.set(k, v)
      return doFetch(u.toString(), { method: 'GET', headers: {} })
    }
    if (transport === 'header') {
      return doFetch(baseUrl, { method: 'GET', headers: { ...kv } })
    }
    if (transport === 'json') {
      return doFetch(baseUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(kv) })
    }
    // form-encoded body
    return doFetch(baseUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(kv).toString() })
  }
}

// A compact, high-signal candidate list. The handler prepends params actually
// observed for the target (from JS recon / the URL corpus), which are the most
// likely to be honored.
export const BUILTIN_PARAMS: readonly string[] = [
  'debug', 'test', 'admin', 'is_admin', 'isadmin', 'role', 'user', 'user_id', 'userid', 'uid', 'id', 'account',
  'page', 'callback', 'jsonp', 'redirect', 'redirect_uri', 'return', 'returnUrl', 'next', 'url', 'dest', 'continue',
  'file', 'path', 'template', 'lang', 'locale', 'format', 'view', 'action', 'cmd', 'exec', 'query', 'q', 'search',
  'sort', 'order', 'filter', 'fields', 'include', 'expand', 'limit', 'offset', 'preview', 'draft', 'test_mode',
  'api_key', 'apikey', 'token', 'access_token', 'key', 'secret', 'password', 'email', 'username', 'ref', 'source',
  // mass-assignment fields — most valuable in a JSON/form body.
  'verified', 'is_verified', 'active', 'is_active', 'enabled', 'approved', 'confirmed', 'owner', 'owner_id', 'is_staff',
]

const CHUNK_SIZE = 25
const CANARY_PREFIX = 'pxq'

function canaryFor(runToken: string, param: string): string {
  return `${CANARY_PREFIX}${runToken}${param.replace(/[^a-z0-9]/gi, '')}`
}

// Two responses "differ enough" to imply an honored param when the status changes
// or the body length moves beyond the observed noise floor. Reflections are
// handled separately (per-param canary), so they don't count as length noise here.
function deviates(base: ProbeResult, resp: ProbeResult, noiseFloor: number): 'status' | 'length' | null {
  if (resp.status !== base.status) return 'status'
  if (Math.abs(resp.body.length - base.body.length) > noiseFloor) return 'length'
  return null
}

// Bisect a set of candidate params to find those whose presence deviates from the
// baseline. Splits recursively; a single deviating param is a hit. `budget` caps
// total probes so a pathological target can't cause unbounded requests.
async function bisect(
  params: string[],
  base: ProbeResult,
  noiseFloor: number,
  probe: Probe,
  runToken: string,
  budget: { left: number },
  signal?: AbortSignal,
): Promise<string[]> {
  if (params.length === 0 || budget.left <= 0 || signal?.aborted) return []
  budget.left--
  const resp = await probe(Object.fromEntries(params.map((p) => [p, canaryFor(runToken, p)])))
  if (!resp) return []
  if (!deviates(base, resp, noiseFloor)) return []
  if (params.length === 1) return params
  const mid = Math.floor(params.length / 2)
  const left = await bisect(params.slice(0, mid), base, noiseFloor, probe, runToken, budget, signal)
  const right = await bisect(params.slice(mid), base, noiseFloor, probe, runToken, budget, signal)
  return [...left, ...right]
}

export interface DiscoverOptions {
  signal?: AbortSignal
  maxProbes?: number // hard cap on total requests
  runToken: string // unique per run so canaries can't collide with page content
}

// Discover honored params. Takes two baselines to estimate the page's natural
// length variance (dynamic content), then chunk-tests all candidates: per-param
// canaries catch reflection immediately; length/status deviation triggers a
// bisect over the non-reflected params in the chunk.
export async function discoverParams(candidates: string[], probe: Probe, opts: DiscoverOptions): Promise<ParamHit[]> {
  const params = [...new Set(candidates.filter((p) => /^[a-zA-Z0-9_.-]{1,40}$/.test(p)))]
  if (params.length === 0) return []
  const budget = { left: Math.max(10, Math.min(opts.maxProbes ?? 400, 2000)) }

  const base1 = await probe({})
  const base2 = await probe({})
  budget.left -= 2
  if (!base1 || !base2) return []
  // Noise floor: at least twice the natural variance between two clean baselines,
  // and never below a small floor, so ordinary dynamic jitter isn't flagged.
  const noiseFloor = Math.max(48, Math.abs(base1.body.length - base2.body.length) * 2)

  const hits: ParamHit[] = []
  const seen = new Set<string>()
  for (let i = 0; i < params.length; i += CHUNK_SIZE) {
    if (opts.signal?.aborted || budget.left <= 0) break
    const chunk = params.slice(i, i + CHUNK_SIZE)
    budget.left--
    const resp = await probe(Object.fromEntries(chunk.map((p) => [p, canaryFor(opts.runToken, p)])))
    if (!resp) continue

    // Reflection: a per-param canary echoed back pins the param exactly.
    const reflected: string[] = []
    for (const p of chunk) {
      if (resp.body.includes(canaryFor(opts.runToken, p))) {
        reflected.push(p)
        if (!seen.has(p)) {
          seen.add(p)
          hits.push({ param: p, reason: 'reflected', evidence: `value of ?${p}= is reflected in the response` })
        }
      }
    }

    // Deviation (status/length) not explained by a reflection ⇒ bisect the rest.
    if (deviates(base1, resp, noiseFloor)) {
      const rest = chunk.filter((p) => !reflected.includes(p))
      const honored = await bisect(rest, base1, noiseFloor, probe, opts.runToken, budget, opts.signal)
      for (const p of honored) {
        if (seen.has(p)) continue
        seen.add(p)
        hits.push({ param: p, reason: 'length', evidence: `adding ?${p}= changed the response vs baseline` })
      }
    }
  }
  return hits
}
