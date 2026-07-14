// Cloud storage bucket discovery (S3 / GCS / Azure Blob). Open buckets are a top
// real-world finding and fully keyless to check. Candidate names are derived from
// the target domain (+ optional operator seeds) so we only probe scope-relevant
// names, never untargeted third-party buckets. Passive w.r.t. the target itself
// (requests go to the cloud provider endpoints, not the target).

import { mapLimit } from '../util/async'

export type BucketState = 'open' | 'locked' | 'absent'

export interface BucketHit {
  provider: 's3' | 'gcs' | 'azure'
  name: string
  url: string
  state: BucketState // open = listable/public, locked = exists but 403, absent = 404
  status: number
}

const TIMEOUT_MS = 8_000
const COMMON_SUFFIXES = ['', '-backup', '-backups', '-dev', '-prod', '-staging', '-assets', '-static', '-media', '-uploads', '-data', '-files', '-public', '-private', '-logs', '-config']

// Build scope-derived candidate names from the registrable domain.
export function bucketCandidates(domain: string, seeds: string[] = []): string[] {
  const base = domain.toLowerCase().replace(/\.[a-z]+$/, '') // strip TLD
  const label = base.split('.').pop() ?? base // last label, e.g. "example"
  const roots = new Set<string>([label, base.replace(/\./g, '-'), base.replace(/\./g, ''), ...seeds.map((s) => s.toLowerCase())])
  const names = new Set<string>()
  for (const root of roots) {
    if (!/^[a-z0-9][a-z0-9-]{1,50}[a-z0-9]$/.test(root)) continue
    for (const suf of COMMON_SUFFIXES) {
      const n = `${root}${suf}`
      if (n.length >= 3 && n.length <= 63) names.add(n)
    }
  }
  return [...names].slice(0, 120)
}

function classify(status: number): BucketState | null {
  if (status === 200) return 'open'
  if (status === 403 || status === 401) return 'locked'
  if (status === 404) return 'absent'
  return null // NoSuchBucket variants, redirects, provider errors → ignore
}

// Fetch just the status of a candidate bucket URL. Uses GET (not HEAD): the
// Azure endpoint below is a `?comp=list` container-listing, which is GET-only,
// and S3/GCS answer GET the same as HEAD for existence. The body is cancelled
// immediately, so this stays a status-only probe (no body download).
async function probeStatus(url: string): Promise<number | null> {
  const c = new AbortController()
  const t = setTimeout(() => c.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual', signal: c.signal, headers: { 'User-Agent': 'recon-dashboard/0.1' } })
    await res.body?.cancel().catch(() => {})
    return res.status
  } catch {
    return null
  } finally {
    clearTimeout(t)
  }
}

function endpoints(name: string): { provider: BucketHit['provider']; url: string }[] {
  return [
    { provider: 's3', url: `https://${name}.s3.amazonaws.com/` },
    { provider: 'gcs', url: `https://storage.googleapis.com/${name}/` },
    { provider: 'azure', url: `https://${name}.blob.core.windows.net/${name}?restype=container&comp=list` },
  ]
}

export async function enumerateBuckets(domain: string, seeds: string[] = []): Promise<BucketHit[]> {
  const names = bucketCandidates(domain, seeds)
  const targets = names.flatMap((name) => endpoints(name).map((e) => ({ name, ...e })))
  const results = await mapLimit(
    targets,
    12,
    async (t) => {
      const status = await probeStatus(t.url)
      if (status == null) return null
      const state = classify(status)
      if (!state || state === 'absent') return null
      return { provider: t.provider, name: t.name, url: t.url, state, status } as BucketHit
    },
    null,
  )
  return results.filter((r): r is BucketHit => r != null)
}
