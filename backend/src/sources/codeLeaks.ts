import { config } from '../config'
import { getJson } from '../util/http'

// Code-leak source: search PUBLIC code (GitHub code search) for the target's
// domain and possibly-leaked keys/internal URLs. GitHub requires auth for code
// search, so this is disabled without GITHUB_TOKEN. Goes through the passive HTTP
// client (per-host governor + retry). Passive w.r.t. the TARGET — requests go to
// GitHub, not the target.

export interface CodeLeakHit {
  repo: string
  path: string
  url: string
  term: string
  fragments: string[]
  secretHint: boolean
}

export interface CodeLeakResult {
  available: boolean
  reason?: string
  searched: string[]
  hits: CodeLeakHit[]
}

// Keyword signal that a matched file may carry an actual secret (raises severity).
const SECRET_KW =
  /\b(password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|bearer|private[_-]?key|aws_secret|BEGIN [A-Z ]*PRIVATE KEY)\b/i

const MAX_TERMS = 4
const MAX_HITS = 60

export async function searchCodeLeaks(domain: string, seeds: string[] = []): Promise<CodeLeakResult> {
  const token = config.githubToken
  if (!token) {
    return { available: false, reason: 'GITHUB_TOKEN not set — GitHub requires a token for code search.', searched: [], hits: [] }
  }
  // Terms: the domain + optional operator/org seeds, sanitized to safe tokens.
  const terms = [...new Set([domain.toLowerCase(), ...seeds.map((s) => s.toLowerCase())])]
    .filter((t) => /^[a-z0-9][a-z0-9.-]{1,60}$/.test(t))
    .slice(0, MAX_TERMS)

  const headers = {
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    Accept: 'application/vnd.github.text-match+json',
  }
  const searched: string[] = []
  const seen = new Set<string>()
  const hits: CodeLeakHit[] = []

  for (const term of terms) {
    if (hits.length >= MAX_HITS) break
    searched.push(term)
    const q = encodeURIComponent(`"${term}"`)
    let doc: { items?: unknown[] }
    try {
      doc = await getJson(`https://api.github.com/search/code?q=${q}&per_page=30`, { headers, timeoutMs: 20_000 })
    } catch {
      // 403 (rate limit / scope), 422 (bad query), etc. — skip this term quietly.
      continue
    }
    for (const raw of Array.isArray(doc?.items) ? doc.items : []) {
      if (hits.length >= MAX_HITS) break
      const item = raw as any
      const repo = item?.repository?.full_name
      const path = item?.path
      if (typeof repo !== 'string' || typeof path !== 'string') continue
      const key = `${repo}:${path}`
      if (seen.has(key)) continue
      seen.add(key)
      const fragments = (Array.isArray(item?.text_matches) ? item.text_matches : [])
        .map((m: any) => String(m?.fragment ?? '').replace(/\s+/g, ' ').trim().slice(0, 300))
        .filter(Boolean)
        .slice(0, 3)
      hits.push({
        repo,
        path,
        url: typeof item?.html_url === 'string' ? item.html_url : `https://github.com/${repo}/blob/HEAD/${path}`,
        term,
        fragments,
        secretHint: fragments.some((fr: string) => SECRET_KW.test(fr)),
      })
    }
  }

  return { available: true, searched, hits }
}
