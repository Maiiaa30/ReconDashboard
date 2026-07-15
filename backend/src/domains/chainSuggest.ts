import { listFindings } from '../findings/store'
import type { AdviceAction } from './advisor'

// Deterministic (NOT LLM) chain-suggester. A pile of findings never becomes an
// attack path on its own; this pairs findings that already exist in the schema
// into concrete next steps — "you cracked a JWT secret AND you have an auth
// endpoint → forge an admin token and run authz_diff as identity B". Pure and
// grounded: every suggestion cites the finding ids it is built from, so it can be
// unit-tested and can never hallucinate. Any attached one-click action still runs
// through assertScanAllowed on the server.

type Finding = ReturnType<typeof listFindings>[number]

export interface ChainSuggestion {
  id: string
  title: string
  rationale: string
  severity: 'critical' | 'high' | 'medium'
  findingIds: number[]
  action?: AdviceAction // optional gated one-click; most chains are workbench guidance
}

const data = (f: Finding) => (f.data ?? {}) as Record<string, any>
const nameOf = (f: Finding) => String(data(f).name ?? '')
const hasTag = (f: Finding, t: string) => (f.tags ?? []).includes(t)

// A honored param whose name screams authorization (the highest-value IDOR seed).
const AUTHZ_PARAM_RE = /^(is_?admin|admin|role|priv|privilege|user_?id|uid|account|acct|owner|org_?id|group)$/i
// URLs/endpoints that look like an OAuth/SSO authorization endpoint.
const OAUTH_RE = /(oauth|openid|\/authorize|\/auth\/|\/sso\/|response_type=|redirect_uri=)/i
const AUTH_ENDPOINT_RE = /(login|signin|token|session|account|api\/user|graphql|admin)/i

// Pure core: turn the finding set into grounded suggestions. `findings` is
// whatever listFindings returns for a domain.
export function buildChainSuggestions(findings: Finding[], domainHost: string): ChainSuggestion[] {
  const out: ChainSuggestion[] = []

  const owasp = findings.filter((f) => f.type === 'owasp')
  const params = findings.filter((f) => f.type === 'param')
  const apis = findings.filter((f) => f.type === 'api')
  const urlOf = (f: Finding) => String(data(f).url ?? data(f).matched ?? data(f).endpoint ?? '')

  // Candidate auth/authz endpoints from api + any finding URL.
  const authEndpoints = [
    ...apis.filter((f) => AUTH_ENDPOINT_RE.test(urlOf(f)) || data(f).kind === 'graphql'),
    ...findings.filter((f) => AUTH_ENDPOINT_RE.test(urlOf(f))),
  ]

  // 1) JWT HMAC secret cracked + an auth endpoint → forge a token, run authz_diff.
  const jwtCracked = owasp.filter((f) => hasTag(f, 'cracked') || /cracked/i.test(nameOf(f)))
  if (jwtCracked.length) {
    const ep = authEndpoints[0]
    out.push({
      id: `chain:jwt-forge:${jwtCracked[0].id}`,
      title: 'Forge an admin token with the cracked JWT secret',
      rationale: `The JWT signing secret is cracked, so you can mint valid tokens with arbitrary claims. Forge one with an elevated role/claim and replay a protected request${ep ? ` (e.g. ${urlOf(ep)})` : ''} — drive it through the Authz (IDOR) diff as identity B.`,
      severity: 'critical',
      findingIds: [jwtCracked[0].id, ...(ep ? [ep.id] : [])],
    })
  }

  // 2) A honored authorization-shaped param → seed authz_diff / Intruder with it.
  const authzParams = params.filter((f) => AUTHZ_PARAM_RE.test(String(data(f).param ?? '')))
  for (const p of authzParams.slice(0, 3)) {
    out.push({
      id: `chain:authz-param:${p.id}`,
      title: `Test the honored "${data(p).param}" parameter for broken access control`,
      rationale: `${urlOf(p) || domainHost} honors "${data(p).param}", an authorization-shaped parameter the app does not document. Send it to Intruder (it is pre-marked) or seed an Authz diff to check whether toggling it escalates privilege or exposes another user's object.`,
      severity: 'high',
      findingIds: [p.id],
    })
  }

  // 3) Open redirect + an OAuth/SSO authorize endpoint → redirect_uri token theft.
  const openRedirects = owasp.filter((f) => /open redirect/i.test(nameOf(f)))
  const oauthEps = [...apis, ...findings].filter((f) => OAUTH_RE.test(urlOf(f)))
  if (openRedirects.length && oauthEps.length) {
    out.push({
      id: `chain:redirect-oauth:${openRedirects[0].id}`,
      title: 'Chain the open redirect into OAuth token theft',
      rationale: `An open redirect (${urlOf(openRedirects[0])}) plus an OAuth/SSO endpoint (${urlOf(oauthEps[0])}) is the classic redirect_uri account-takeover: if the redirect is reachable from the authorize flow, a crafted redirect_uri can leak the code/token. Verify the redirect_uri allowlist.`,
      severity: 'high',
      findingIds: [openRedirects[0].id, oauthEps[0].id],
    })
  }

  // 4) SSRF-candidate param → preload the SSRF/metadata payload set into Intruder.
  const ssrf = owasp.filter((f) => /ssrf candidate/i.test(nameOf(f)))
  for (const s of ssrf.slice(0, 2)) {
    out.push({
      id: `chain:ssrf-imds:${s.id}`,
      title: 'Probe the SSRF-candidate parameter against cloud metadata',
      rationale: `${urlOf(s)} reflects a fetched URL and its name suggests a server-side request. Load the SSRF payload set (IMDS 169.254.169.254, localhost, gopher) into Intruder for this parameter — cloud metadata credentials are the high-value target. No probe was sent automatically.`,
      severity: 'high',
      findingIds: [s.id],
    })
  }

  // 5) Dumpable .git repository → dump it and secret-scan the history.
  const gitDump = owasp.filter((f) => /dumpable \.git|\.git repository/i.test(nameOf(f)))
  if (gitDump.length) {
    out.push({
      id: `chain:git-dump:${gitDump[0].id}`,
      title: 'Dump the exposed .git repository and scan its history',
      rationale: `The full .git repository is downloadable (${urlOf(gitDump[0]) || domainHost}). Reconstruct the source with git-dumper offline, then run the secret/code-leak search over the history — committed credentials and internal URLs are common.`,
      severity: 'critical',
      findingIds: [gitDump[0].id],
    })
  }

  // 6) GraphQL introspection enabled → test the exposed mutations/authz.
  const gqlIntrospect = apis.filter((f) => data(f).kind === 'graphql' && (data(f).introspection === true || hasTag(f, 'introspection')))
  for (const g of gqlIntrospect.slice(0, 2)) {
    const host = data(g).host ?? domainHost
    out.push({
      id: `chain:graphql-authz:${g.id}`,
      title: 'Test the introspectable GraphQL schema for authz gaps',
      rationale: `Introspection is enabled at ${urlOf(g) || host}, so the full schema (including mutations) is readable. Enumerate sensitive mutations/queries and test each for missing authorization. A deep crawl surfaces the operations to target.`,
      severity: 'high',
      findingIds: [g.id],
      action: { kind: 'katana', target: String(host) },
    })
  }

  // Highest severity first, stable within a bucket by id.
  const rank = { critical: 0, high: 1, medium: 2 }
  return out.sort((a, b) => rank[a.severity] - rank[b.severity])
}

export function suggestChains(domainId: number, domainHost: string): ChainSuggestion[] {
  return buildChainSuggestions(listFindings({ domainId, limit: 5000 }), domainHost)
}
