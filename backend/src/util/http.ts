// Passive HTTP helpers for external recon sources. Uses Node's global fetch
// with a timeout, a small response-size cap, and a stable User-Agent.

const DEFAULT_TIMEOUT_MS = 20_000
const MAX_BYTES = 8 * 1024 * 1024 // 8 MB cap to avoid memory blowups
const USER_AGENT = 'recon-dashboard/0.1 (+passive recon)'

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

export async function getText(url: string, opts: GetOptions = {}): Promise<string> {
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
    const text = await readCapped(res)
    if (!res.ok) {
      throw new HttpError(res.status, `HTTP ${res.status} for ${url}`)
    }
    return text
  } finally {
    clearTimeout(timer)
  }
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
