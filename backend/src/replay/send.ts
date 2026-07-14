import zlib from 'node:zlib'
import { assertPublicHost } from '../sources/guard'
import { applyRules, type MatchReplaceRule } from './matchReplace'

// Server-side HTTP sender for the Replay (Repeater) + Intruder tools: take a
// fully-specified request the operator composed, send it, and return the full
// response (status, ALL headers, body, timing). This is the offensive twin of
// sources/guard.guardedFetch — same per-hop SSRF discipline (re-resolve + refuse
// internal on every redirect), but it returns response headers + timing and lets
// the caller drive an arbitrary method/headers/body, which a passive probe never
// needs. Bounded: capped body, bounded redirects, hard timeout.

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
const MAX_BODY_BYTES = 2 * 1024 * 1024
const MAX_DECODED_BYTES = 4 * 1024 * 1024 // decompression can amplify — cap the output
const DEFAULT_TIMEOUT_MS = 15_000
const MAX_TIMEOUT_MS = 60_000
const MAX_REDIRECTS = 10

// Headers fetch/undici derives or forbids the caller from setting; passing them
// through throws "invalid header" or corrupts framing. The operator's Host is the
// URL's host by design, and Content-Length is computed from the body.
const RESERVED_HEADERS = new Set([
  'host',
  'content-length',
  'connection',
  'transfer-encoding',
  'keep-alive',
  'upgrade',
  'http2-settings',
  'te',
  'trailer',
])

export class ReplayError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message)
    this.name = 'ReplayError'
  }
}

export interface ReplayRequest {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
  followRedirects?: boolean
  timeoutMs?: number
}

export interface ReplayResponse {
  status: number
  statusText: string
  headers: [string, string][]
  body: string
  bodyBytes: number
  truncated: boolean
  timeMs: number
  finalUrl: string
  redirects: { status: number; location: string }[]
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, Number.isFinite(n) ? n : lo))
}

// Remove credential-bearing headers (used when a redirect crosses to a new host).
function stripCredentialHeaders(h: Record<string, string>): void {
  for (const k of Object.keys(h)) {
    const lk = k.toLowerCase()
    if (lk === 'cookie' || lk === 'authorization' || lk === 'proxy-authorization') delete h[k]
  }
}

// Pure variant: a copy of the headers with credential-bearing ones removed. Used
// by the authz helper to build the anonymous / identity-B request variants.
export function withoutCredentialHeaders(h: Record<string, string> = {}): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(h)) {
    const lk = k.toLowerCase()
    if (lk === 'cookie' || lk === 'authorization' || lk === 'proxy-authorization') continue
    out[k] = v
  }
  return out
}

function sanitizeHeaders(headers: Record<string, string> = {}): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    if (typeof k !== 'string' || typeof v !== 'string') continue
    const name = k.trim()
    if (!name || RESERVED_HEADERS.has(name.toLowerCase())) continue
    out[name] = v
  }
  return out
}

// Read the raw response bytes, stopping at `max` so a huge download can't blow up
// memory. Returns the wire bytes + whether the stream was cut short.
async function readRawCapped(res: Response, max: number): Promise<{ buf: Buffer; truncated: boolean }> {
  if (!res.body) {
    const ab = await res.arrayBuffer()
    const buf = Buffer.from(ab)
    return { buf: buf.subarray(0, max), truncated: buf.length > max }
  }
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let kept = 0
  let truncated = false
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (!value) continue
    const remaining = max - kept
    if (value.length > remaining) {
      chunks.push(value.subarray(0, remaining))
      kept = max
      truncated = true
      try {
        await reader.cancel()
      } catch {
        /* stream already closing */
      }
      break
    }
    chunks.push(value)
    kept += value.length
  }
  return { buf: Buffer.concat(chunks), truncated }
}

// Node's fetch only auto-decompresses when IT chose the Accept-Encoding. A Replay
// request usually carries the operator's own Accept-Encoding (copied from a real
// browser), so the body comes back compressed and must be inflated here or the UI
// shows binary garbage. Bounded output so a decompression bomb can't OOM us.
function tryDecompress(buf: Buffer, encoding: string): Buffer | null {
  const opts = { maxOutputLength: MAX_DECODED_BYTES }
  const z = zlib as unknown as { zstdDecompressSync?: (b: Buffer, o?: unknown) => Buffer }
  try {
    switch (encoding) {
      case 'gzip':
      case 'x-gzip':
        return zlib.gunzipSync(buf, opts)
      case 'br':
        return zlib.brotliDecompressSync(buf, opts)
      case 'deflate':
        try {
          return zlib.inflateSync(buf, opts)
        } catch {
          return zlib.inflateRawSync(buf, opts) // some servers send raw (headerless) deflate
        }
      case 'zstd':
        return typeof z.zstdDecompressSync === 'function' ? z.zstdDecompressSync(buf, opts) : null
      default:
        return null // unknown / multiple encodings — show raw
    }
  } catch {
    return null // corrupt/truncated stream — fall back to raw bytes
  }
}

function decodeBody(buf: Buffer, contentEncoding: string, wasTruncated: boolean): { text: string; bytes: number } {
  const enc = contentEncoding.toLowerCase().trim()
  // A truncated compressed stream can't be inflated, so only decompress a complete one.
  if (enc && !wasTruncated) {
    const dec = tryDecompress(buf, enc)
    if (dec) return { text: dec.toString('utf8'), bytes: dec.length }
  }
  return { text: buf.toString('utf8'), bytes: buf.length }
}

/**
 * Send one operator-composed request and return the full response.
 * SSRF-guarded on every hop. Throws ReplayError on bad input / too many
 * redirects, or SsrfBlockedError if a (redirect) host resolves internal.
 */
export async function sendRawRequest(
  req: ReplayRequest,
  opts: { signal?: AbortSignal; rules?: MatchReplaceRule[] } = {},
): Promise<ReplayResponse> {
  // Match/replace rules run ONCE, up front — before sanitizeHeaders and the
  // redirect loop — so reserved-header stripping, per-hop assertPublicHost, and
  // cross-host credential stripping all still apply to the rewritten request.
  const r = opts.rules?.length ? applyRules(req, opts.rules) : req
  const method = (r.method || 'GET').toUpperCase()
  if (!ALLOWED_METHODS.has(method)) throw new ReplayError(`unsupported method: ${method}`)
  const timeoutMs = clamp(r.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1_000, MAX_TIMEOUT_MS)
  const follow = r.followRedirects ?? false
  const headers = sanitizeHeaders(r.headers)
  const hasBody = method !== 'GET' && method !== 'HEAD' && r.body != null
  const redirects: { status: number; location: string }[] = []
  const started = Date.now()
  let current = r.url

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (opts.signal?.aborted) throw new ReplayError('request aborted', 499)
    let u: URL
    try {
      u = new URL(current)
    } catch {
      throw new ReplayError(`invalid url: ${current}`)
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      throw new ReplayError('only http:// and https:// URLs are allowed')
    }
    // SSRF: refuse a host (or redirect target) that resolves to an internal address.
    await assertPublicHost(u.hostname)

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    const signal = opts.signal ? AbortSignal.any([controller.signal, opts.signal]) : controller.signal
    let res: Response
    try {
      res = await fetch(current, {
        method,
        headers,
        body: hasBody ? r.body : undefined,
        redirect: 'manual',
        signal,
      })
    } catch (err) {
      throw new ReplayError(`request failed: ${err instanceof Error ? err.message : String(err)}`, 502)
    } finally {
      clearTimeout(timer)
    }

    if (follow && res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location')
      if (loc) {
        redirects.push({ status: res.status, location: loc })
        let next: URL
        try {
          next = new URL(loc, current)
        } catch {
          throw new ReplayError(`redirect to invalid url: ${loc}`, 502)
        }
        // Don't carry credentials across a host change (as browsers do) — a
        // 302 from an in-scope host to an attacker's host must not re-send the
        // operator's Cookie/Authorization.
        if (next.host !== u.host) stripCredentialHeaders(headers)
        current = next.toString()
        continue
      }
    }

    const capped = await readRawCapped(res, MAX_BODY_BYTES)
    const decoded = decodeBody(capped.buf, res.headers.get('content-encoding') ?? '', capped.truncated)
    return {
      status: res.status,
      statusText: res.statusText,
      headers: [...res.headers.entries()],
      body: decoded.text,
      bodyBytes: decoded.bytes,
      truncated: capped.truncated,
      timeMs: Date.now() - started,
      finalUrl: current,
      redirects,
    }
  }
  throw new ReplayError('too many redirects', 502)
}
