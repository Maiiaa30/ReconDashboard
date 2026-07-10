// Passive HTTP helpers for external recon sources. Uses Node's global fetch
// with a timeout, a small response-size cap, and a stable User-Agent.

const DEFAULT_TIMEOUT_MS = 20_000
const MAX_BYTES = 8 * 1024 * 1024 // 8 MB cap to avoid memory blowups
const USER_AGENT = 'recon-dashboard/0.1 (+passive recon)'

// A real-browser UA for fetching pages/JS that gate content on the User-Agent
// (many CDNs serve a bot/challenge page to non-browser agents, which would
// otherwise hide the app's real script bundles).
export const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

interface GetOptions {
  timeoutMs?: number
  accept?: string
}

async function readCapped(res: Response): Promise<string> {
  const reader = res.body?.getReader()
  if (!reader) return ''
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (value) {
      total += value.byteLength
      if (total > MAX_BYTES) {
        await reader.cancel()
        throw new HttpError(0, 'response exceeded size cap')
      }
      chunks.push(value)
    }
  }
  return Buffer.concat(chunks).toString('utf8')
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// --- Per-provider concurrency governor ---------------------------------------
// Cap concurrent in-flight requests to any single host so parallel scans (e.g.
// the exposure fan-out) stay polite and don't get themselves rate-limited or
// banned. Keyed by hostname — unrelated hosts still run fully in parallel. It's
// a counting semaphore: a freed slot is handed directly to the next waiter, so
// the active count can never exceed the limit.
const PER_HOST_LIMIT = 4
const hostActive = new Map<string, number>()
const hostQueue = new Map<string, Array<() => void>>()

function hostnameOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}

function acquireHost(host: string): Promise<void> {
  const active = hostActive.get(host) ?? 0
  if (active < PER_HOST_LIMIT) {
    hostActive.set(host, active + 1)
    return Promise.resolve()
  }
  return new Promise<void>((resolve) => {
    const q = hostQueue.get(host) ?? []
    q.push(resolve)
    hostQueue.set(host, q)
  })
}

function releaseHost(host: string): void {
  const q = hostQueue.get(host)
  if (q && q.length) {
    // Transfer the slot straight to the next waiter (active count unchanged).
    q.shift()!()
    if (q.length === 0) hostQueue.delete(host)
    return
  }
  const next = Math.max(0, (hostActive.get(host) ?? 1) - 1)
  if (next === 0) hostActive.delete(host)
  else hostActive.set(host, next)
}

/** Run `fn` while holding a per-host concurrency slot. */
export async function withHostLimit<T>(url: string, fn: () => Promise<T>): Promise<T> {
  const host = hostnameOf(url)
  await acquireHost(host)
  try {
    return await fn()
  } finally {
    releaseHost(host)
  }
}

// Statuses worth retrying: 429 plus transient upstream errors.
const RETRYABLE = new Set([429, 502, 503, 504])

// Parse a Retry-After header (delta-seconds or HTTP-date) into ms, capped so a
// hostile/broken header can't blow the job's time budget.
function retryAfterMs(header: string | null, attempt: number): number {
  const CAP = 30_000
  if (header) {
    const secs = Number(header)
    if (Number.isFinite(secs)) return Math.min(Math.max(0, secs * 1000), CAP)
    const date = Date.parse(header)
    if (!Number.isNaN(date)) return Math.min(Math.max(0, date - Date.now()), CAP)
  }
  // Exponential-ish default with light jitter when no header is supplied.
  return Math.min(1000 * (attempt + 1) + Math.floor((attempt + 1) * 250), CAP)
}

export async function getText(url: string, opts: GetOptions = {}): Promise<string> {
  // Retry on 429 + transient 5xx; keyless public APIs rate-limit / 5xx hard.
  const MAX_RETRIES = 2
  return withHostLimit(url, async () => {
    for (let attempt = 0; ; attempt++) {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS)
      try {
        const res = await fetch(url, {
          signal: controller.signal,
          headers: {
            'User-Agent': USER_AGENT,
            ...(opts.accept ? { Accept: opts.accept } : {}),
          },
          redirect: 'follow',
        })
        if (RETRYABLE.has(res.status) && attempt < MAX_RETRIES) {
          const wait = retryAfterMs(res.headers.get('retry-after'), attempt)
          await res.body?.cancel().catch(() => {})
          clearTimeout(timer)
          await sleep(wait)
          continue
        }
        const text = await readCapped(res)
        if (!res.ok) {
          throw new HttpError(res.status, `HTTP ${res.status} for ${url}`)
        }
        return text
      } finally {
        clearTimeout(timer)
      }
    }
  })
}

export async function getJson<T>(url: string, opts: GetOptions = {}): Promise<T> {
  const text = await getText(url, { ...opts, accept: 'application/json' })
  return JSON.parse(text) as T
}

/** Like getJson but returns null on 404 instead of throwing. */
export async function getJsonOrNull<T>(url: string, opts: GetOptions = {}): Promise<T | null> {
  try {
    return await getJson<T>(url, opts)
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) return null
    throw err
  }
}
