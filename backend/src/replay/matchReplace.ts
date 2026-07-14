import type { ReplayRequest } from './send'

// Session-wide request rewriting: inject an Authorization header, swap a CSRF
// token, rewrite Host, mask a value, etc. Applied ONCE up front inside
// sendRawRequest — BEFORE sanitizeHeaders and the redirect loop — so every safety
// property still holds on the rewritten request: reserved headers are still
// stripped, assertPublicHost still re-validates the (possibly rewritten) URL on
// every hop, and credential headers are still dropped on a cross-host redirect.
// applyRules is pure so it can be unit-tested and previewed with no egress.

export type RulePart = 'url' | 'header' | 'body'

export interface MatchReplaceRule {
  id: number
  domainId: number | null // null = global
  name: string
  enabled: boolean
  part: RulePart
  match: string
  replace: string
  isRegex: boolean
}

// Case-insensitive header lookup returning the actual stored key (or null).
function headerKey(headers: Record<string, string>, name: string): string | null {
  const lower = name.toLowerCase()
  for (const k of Object.keys(headers)) if (k.toLowerCase() === lower) return k
  return null
}

// Apply one rule to a string part (url/body). A bad regex is skipped, not fatal.
function rewriteString(input: string | undefined, rule: MatchReplaceRule): string | undefined {
  if (input == null) return input
  if (!rule.match) return input // no match term ⇒ nothing to do for url/body
  if (rule.isRegex) {
    try {
      return input.replace(new RegExp(rule.match, 'g'), rule.replace)
    } catch {
      return input // invalid regex — skip this rule rather than abort the request
    }
  }
  return input.split(rule.match).join(rule.replace)
}

// Header rules are set/replace/delete by NAME (the common case: inject or rewrite
// a whole header). `match` is the header name; `replace` is the value; an empty
// `replace` deletes the header.
function applyHeaderRule(headers: Record<string, string>, rule: MatchReplaceRule): Record<string, string> {
  const name = rule.match.trim()
  if (!name) return headers
  const existing = headerKey(headers, name)
  const out = { ...headers }
  if (rule.replace === '') {
    if (existing) delete out[existing]
    return out
  }
  // Overwrite the existing header (preserving its original casing) or add it.
  out[existing ?? name] = rule.replace
  return out
}

// Apply an ordered list of rules to a request, returning a new request. Callers
// pass rules already ordered (global first, then domain — so a domain rule wins).
export function applyRules(req: ReplayRequest, rules: MatchReplaceRule[]): ReplayRequest {
  let url = req.url
  let body = req.body
  let headers: Record<string, string> = { ...(req.headers ?? {}) }
  for (const rule of rules) {
    if (!rule.enabled) continue
    if (rule.part === 'url') url = rewriteString(url, rule) ?? url
    else if (rule.part === 'body') body = rewriteString(body, rule)
    else if (rule.part === 'header') headers = applyHeaderRule(headers, rule)
  }
  return { ...req, url, headers, body }
}

// Order the applicable rules: global (domainId null) before domain-specific, then
// by id — deterministic and lets a domain rule override a global one.
export function orderRules(rules: MatchReplaceRule[]): MatchReplaceRule[] {
  return [...rules].sort((a, b) => {
    const ag = a.domainId == null ? 0 : 1
    const bg = b.domainId == null ? 0 : 1
    return ag !== bg ? ag - bg : a.id - b.id
  })
}
