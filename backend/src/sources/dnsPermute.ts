import { mapLimit } from '../util/async'

// DNS permutation + brute-resolve. Discovery is otherwise 100% passive (CT +
// subfinder + SANs); this generates likely names from a curated wordlist and from
// the existing inventory, then resolves them. The pure parts (candidate
// generation, wildcard detection, filtering) are unit-testable without a network;
// the resolver is injected. A MANDATORY wildcard-zone guard runs first — if a
// random label resolves, the zone is a catch-all and brute-force is worthless
// (it would "find" every name), so we skip it entirely.

export type ResolveFn = (host: string) => Promise<string[]>

// A small, high-signal set of subdomain labels (environments, infra, regions).
export const PERMUTE_WORDS: readonly string[] = [
  'dev', 'develop', 'development', 'staging', 'stage', 'test', 'testing', 'uat', 'qa', 'sandbox',
  'prod', 'production', 'preprod', 'demo', 'beta', 'alpha', 'internal', 'intranet', 'corp', 'private',
  'api', 'api-dev', 'api-staging', 'api-internal', 'app', 'apps', 'admin', 'admin2', 'portal', 'dashboard',
  'auth', 'sso', 'login', 'account', 'accounts', 'gateway', 'gw', 'vpn', 'proxy', 'edge',
  'git', 'gitlab', 'jenkins', 'ci', 'cd', 'build', 'registry', 'nexus', 'artifactory', 'sonar',
  'grafana', 'kibana', 'prometheus', 'monitor', 'monitoring', 'status', 'health', 'metrics', 'logs', 'logging',
  'mail', 'smtp', 'imap', 'webmail', 'ns1', 'ns2', 'mx', 'cdn', 'assets', 'static',
  'db', 'sql', 'mysql', 'postgres', 'redis', 'mongo', 'backup', 'backups', 'files', 'ftp',
  'us', 'eu', 'asia', 'us-east', 'us-west', 'eu-west', 'eu-central', 'ap-south', 'new', 'old',
]

const LABEL_RE = /^[a-z0-9-]{1,63}$/

// Generate candidate hostnames for a domain, excluding names already known.
// Pure + bounded (`max`). Sources: word.<domain>, and permutations of each
// existing subdomain's leftmost label (numeric increment + word-affix).
export function buildPermutationCandidates(
  domain: string,
  existingHosts: string[],
  opts: { words?: readonly string[]; max?: number } = {},
): string[] {
  const words = opts.words ?? PERMUTE_WORDS
  const max = opts.max ?? 2000
  const d = domain.toLowerCase().replace(/^\.+|\.+$/g, '')
  const existing = new Set(existingHosts.map((h) => h.toLowerCase()))
  const out = new Set<string>()
  const add = (label: string) => {
    if (out.size >= max || !LABEL_RE.test(label)) return
    const host = `${label}.${d}`
    if (!existing.has(host)) out.add(host)
  }

  // 1) word.<domain> — the highest-value candidates, added first.
  for (const w of words) add(w)

  // 2) permutations from each existing subdomain's leftmost label.
  const labels = new Set<string>()
  for (const h of existing) {
    if (h === d || !h.endsWith(`.${d}`)) continue
    const left = h.slice(0, h.length - d.length - 1).split('.')[0]
    if (left && LABEL_RE.test(left) && !words.includes(left)) labels.add(left)
  }
  for (const label of labels) {
    // numeric neighbours: admin -> admin2/3, web1 -> web2/3
    const m = label.match(/^(.*?)(\d+)$/)
    if (m) {
      const base = m[1]
      const n = Number(m[2])
      for (let i = 1; i <= 3; i++) add(`${base}${n + i}`)
    } else {
      for (let i = 1; i <= 3; i++) add(`${label}${i}`)
    }
    // word-affixed: dev-<label>, <label>-dev
    for (const w of words) {
      add(`${w}-${label}`)
      add(`${label}-${w}`)
    }
  }

  return [...out]
}

// Wildcard-zone guard: resolve a few random labels. If ANY resolves, the zone
// answers every name (catch-all) and brute-force would flood the inventory with
// non-existent hosts — the caller must skip it. Returns the observed wildcard IPs
// too, so a caller that proceeds anyway can filter catch-all answers out.
export async function isWildcardZone(
  domain: string,
  resolve: ResolveFn,
  labels: readonly string[] = ['zzq9x7-wildcard-probe', 'nope4f2a-wildcard', 'r8x1q-does-not-exist'],
): Promise<{ wildcard: boolean; ips: string[] }> {
  const d = domain.toLowerCase().replace(/^\.+|\.+$/g, '')
  const ips = new Set<string>()
  let wildcard = false
  for (const label of labels) {
    const r = await resolve(`${label}.${d}`)
    if (r.length) {
      wildcard = true
      for (const ip of r) ips.add(ip)
    }
  }
  return { wildcard, ips: [...ips] }
}

// Resolve candidates with bounded concurrency; keep those with an A/AAAA answer.
// Drops hosts that resolve ONLY to the wildcard IP set (residual catch-all noise).
export async function bruteResolve(
  candidates: string[],
  resolve: ResolveFn,
  opts: { concurrency?: number; wildcardIps?: string[] } = {},
): Promise<{ host: string; ips: string[] }[]> {
  const wildcard = new Set(opts.wildcardIps ?? [])
  const results = await mapLimit<string, { host: string; ips: string[] } | null>(
    candidates,
    opts.concurrency ?? 12,
    async (host) => {
      const ips = await resolve(host)
      if (!ips.length) return null
      if (wildcard.size && ips.every((ip) => wildcard.has(ip))) return null
      return { host, ips }
    },
    null,
  )
  return results.filter((r): r is { host: string; ips: string[] } => r != null)
}
