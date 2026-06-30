import { getText } from '../util/http'
import { hostBelongsToDomain, normalizeHost } from '../util/validate'

interface CrtShEntry {
  name_value?: string
  common_name?: string
}

// Passive subdomain discovery via crt.sh certificate transparency logs.
// Returns normalized hosts that belong to `domain`.
export async function crtShSubdomains(domain: string): Promise<string[]> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`
  const text = await getText(url, { timeoutMs: 30_000, accept: 'application/json' })

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
