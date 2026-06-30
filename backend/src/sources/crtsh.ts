import { getText, HttpError } from '../util/http'
import { hostBelongsToDomain, normalizeHost } from '../util/validate'

interface CrtShEntry {
  name_value?: string
  common_name?: string
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// Passive subdomain discovery via crt.sh certificate transparency logs.
// crt.sh is frequently slow / returns 502s, so we retry a couple of times with
// backoff. Returns normalized hosts that belong to `domain`.
export async function crtShSubdomains(domain: string): Promise<string[]> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`

  let text = ''
  let lastErr: unknown = null
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await sleep(2000 * attempt)
    try {
      text = await getText(url, { timeoutMs: 25_000, accept: 'application/json' })
      lastErr = null
      break
    } catch (err) {
      lastErr = err
    }
  }
  if (lastErr) {
    // Surface a clean reason instead of the raw "operation was aborted".
    if (lastErr instanceof HttpError) throw new Error(`crt.sh unavailable (HTTP ${lastErr.status})`)
    const msg = lastErr instanceof Error ? lastErr.message : String(lastErr)
    throw new Error(/abort/i.test(msg) ? 'crt.sh timed out' : `crt.sh error: ${msg}`)
  }

  let entries: CrtShEntry[]
  try {
    entries = JSON.parse(text) as CrtShEntry[]
  } catch {
    // crt.sh occasionally returns concatenated JSON objects or HTML when busy.
    return []
  }

  const hosts = new Set<string>()
  for (const entry of entries) {
    const raw = `${entry.name_value ?? ''}\n${entry.common_name ?? ''}`
    for (const line of raw.split('\n')) {
      const host = normalizeHost(line)
      if (host && hostBelongsToDomain(host, domain)) {
        hosts.add(host)
      }
    }
  }
  return [...hosts]
}
