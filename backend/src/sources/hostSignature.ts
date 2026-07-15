import { guardedFetchBytes } from './guard'
import { grabTlsCert } from './tlsCert'
import { faviconHash } from '../util/mmh3'

// Collect the correlation signatures for one host: its TLS cert fingerprint and
// its mmh3 favicon hash. Both survive CDN fronting (a shared cert or identical
// favicon links two hosts even on different edge IPs). SSRF-guarded, byte-capped,
// best-effort — any piece that fails is simply null.

const MAX_FAVICON_BYTES = 256 * 1024

export interface HostSignature {
  certFp: string | null
  faviconHash: number | null
}

export async function collectHostSignature(host: string, signal?: AbortSignal): Promise<HostSignature> {
  let certFp: string | null = null
  try {
    certFp = (await grabTlsCert(host))?.fingerprint256 ?? null
  } catch {
    /* no TLS / unreachable */
  }
  let favicon: number | null = null
  if (!signal?.aborted) {
    const res = await guardedFetchBytes(`https://${host}/favicon.ico`, { maxBytes: MAX_FAVICON_BYTES, signal })
    if (res && res.status === 200 && res.bytes.length > 0) favicon = faviconHash(res.bytes)
  }
  return { certFp, faviconHash: favicon }
}
