import { guardedFetch } from './guard'
import { grabTlsCert } from './tlsCert'
import { faviconHashFor } from './fingerprint'

// Collect the correlation signatures for one host: its TLS cert fingerprint and
// its mmh3 favicon hash. Both survive CDN fronting (a shared cert or identical
// favicon links two hosts even on different edge IPs). SSRF-guarded, byte-capped,
// best-effort — any piece that fails is simply null.

export interface HostSignature {
  certFp: string | null
  faviconHash: number | null
  title: string | null
  reachable: boolean
}

export async function collectHostSignature(host: string, signal?: AbortSignal): Promise<HostSignature> {
  let certFp: string | null = null
  try {
    certFp = (await grabTlsCert(host))?.fingerprint256 ?? null
  } catch {
    /* no TLS / unreachable */
  }
  let favicon: number | null = null
  let title: string | null = null
  let reachable = false
  if (!signal?.aborted) {
    for (const scheme of ['https', 'http']) {
      const base = `${scheme}://${host}`
      const page = await guardedFetch(base, { maxBytes: 96 * 1024, signal })
      if (!page || page.status < 200 || page.status >= 500) continue
      reachable = true
      title = (page.body.match(/<title[^>]*>([^<]{1,300})<\/title>/i)?.[1] ?? '').trim() || null
      favicon = await faviconHashFor(base, page.body, signal)
      if (favicon != null) break
    }
  }
  return { certFp, faviconHash: favicon, title, reachable }
}
