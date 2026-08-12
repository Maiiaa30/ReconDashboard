import { getText, HttpError } from '../util/http'
import { hostBelongsToDomain, normalizeHost } from '../util/validate'

interface CrtShEntry {
  name_value?: string
  common_name?: string
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// Per-attempt timeouts grow: a transient 502 fails fast and retries quickly,
// while a genuinely slow (but alive) crt.sh gets more time on later attempts.
const ATTEMPT_TIMEOUTS_MS = [15_000, 30_000, 45_000]

function extractHosts(entries: CrtShEntry[], domain: string): string[] {
  const hosts = new Set<string>()
  for (const entry of entries) {
    const raw = `${entry.name_value ?? ''}\n${entry.common_name ?? ''}`
    for (const line of raw.split('\n')) {
      const host = normalizeHost(line)
      if (host && hostBelongsToDomain(host, domain)) hosts.add(host)
    }
  }
  return [...hosts]
}

// Passive subdomain discovery via crt.sh certificate-transparency logs.
// crt.sh is frequently slow / 502s / serves an HTML "busy" page with a 200 —
// so we retry with escalating timeouts and jittered backoff, treating a
// non-JSON body as a retryable failure rather than an empty result. certspotter
// is the redundant CT source that covers crt.sh outages (see the discovery
// handler and the OSINT fallback).
export async function crtShSubdomains(domain: string, signal?: AbortSignal): Promise<string[]> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`

  let lastErr: unknown = null
  for (let attempt = 0; attempt < ATTEMPT_TIMEOUTS_MS.length; attempt++) {
    if (signal?.aborted) throw signal.reason ?? new Error('crt.sh cancelled')
    if (attempt > 0) await sleep(1200 * attempt + Math.floor(Math.random() * 800))
    try {
      const text = await getText(url, { timeoutMs: ATTEMPT_TIMEOUTS_MS[attempt], accept: 'application/json', signal })
      const trimmed = text.trimStart()
      // A healthy response is a JSON array. When overloaded, crt.sh returns a
      // 200 with an HTML holding page — retry instead of silently yielding [].
      if (trimmed[0] !== '[' && trimmed[0] !== '{') {
        lastErr = new Error('crt.sh returned a non-JSON response (server busy)')
        continue
      }
      try {
        return extractHosts(JSON.parse(trimmed) as CrtShEntry[], domain)
      } catch {
        lastErr = new Error('crt.sh returned malformed JSON')
        continue
      }
    } catch (err) {
      lastErr = err
    }
  }

  // Surface a clean reason instead of the raw "operation was aborted".
  if (lastErr instanceof HttpError) throw new Error(`crt.sh unavailable (HTTP ${lastErr.status})`)
  const msg = lastErr instanceof Error ? lastErr.message : String(lastErr)
  throw new Error(/abort/i.test(msg) ? 'crt.sh timed out' : `crt.sh error: ${msg}`)
}
