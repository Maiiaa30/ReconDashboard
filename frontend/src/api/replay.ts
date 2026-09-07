import { del, get, post, put } from './http'
import { sitemapResponseSchema } from './schemas'

// Replay (Repeater): the full response from a server-side send.
export interface ReplayResponse {
  status: number
  statusText: string
  headers: [string, string][]
  body: string
  bodyBytes: number
  truncated: boolean
  timeMs: number
  finalUrl: string
  redirects: { status: number; location: string }[]
  // Set when a Cloudflare challenge was auto-solved and the request replayed with
  // the resulting cf_clearance cookie.
  cloudflareSolved?: boolean
}

export interface IntruderAttempt {
  payload: string
  status: number
  length: number
  words?: number
  timeMs: number
  extract?: string
  extractAll?: string[]
  matched?: boolean
  bodyExcerpt?: string
  assignment?: Record<string, string>
  error?: string
}
export interface IntruderResult {
  total: number
  sent: number
  aborted: boolean
  attempts: IntruderAttempt[]
  interesting: IntruderAttempt[]
  baseline: { status: number; length: number } | null
}

export interface MatchReplaceRule {
  id: number
  domainId: number | null
  name: string
  enabled: boolean
  part: 'url' | 'header' | 'body'
  match: string
  replace: string
  isRegex: boolean
}

// Repeater history entry (list form — no response body).
export interface ReplayHistoryItem {
  id: number
  identityId?: number | null
  method: string
  url: string
  reqHeaders: [string, string][]
  reqBody: string | null
  status: number | null
  statusText: string | null
  timeMs: number | null
  respBytes: number | null
  createdAt: string
}
// A named request identity (A / B / anon) reusable across Repeater/Intruder/authz.
export interface Identity {
  id: number
  domainId: number | null
  name: string
  headers: Record<string, string>
  isAnon: boolean
}
// Full entry (with the stored response) — fetched when a history row is opened.
export interface ReplayHistoryDetail extends ReplayHistoryItem {
  respHeaders: [string, string][]
  respBody: string | null
}

// SitemapEndpoint and SitemapHost are defined by their zod schemas and
// re-exported so call sites import them unchanged.
export type { SitemapEndpoint, SitemapHost } from './schemas'

export const replayApi = {
  // replay (Repeater): send one composed request server-side, gated to the domain's scope
  replaySend: (bodyReq: {
    domainId: number
    method: string
    url: string
    headers?: Record<string, string>
    body?: string
    followRedirects?: boolean
    identityId?: number
    confirm?: boolean
  }) => post<{ response: ReplayResponse }>('/replay/send', bodyReq),
  // repeater history (optionally scoped to one identity)
  replayHistory: (domainId: number, limit?: number, identityId?: number) =>
    get<{ history: ReplayHistoryItem[] }>(
      `/replay/history?domainId=${domainId}${limit ? `&limit=${limit}` : ''}${identityId != null ? `&identityId=${identityId}` : ''}`,
    ),
  replayHistoryDetail: (id: number) => get<{ entry: ReplayHistoryDetail }>(`/replay/history/${id}`),
  clearReplayHistory: (domainId: number) => del<{ cleared: number }>(`/replay/history?domainId=${domainId}`),
  // intruder: iterate payloads through a request template (gated LOUD job). One or
  // more {{Pn}} positions; sniper/battering-ram use one list, pitchfork/cluster-
  // bomb one list per position.
  intruder: (
    id: number,
    bodyReq: {
      template: { method: string; url: string; headers?: Record<string, string>; body?: string; followRedirects?: boolean }
      mode?: 'sniper' | 'battering-ram' | 'pitchfork' | 'cluster-bomb'
      payload?: { mode: 'list' | 'range' | 'wordlist'; list?: string; from?: number; to?: number; pad?: number; wordlist?: string }
      payloads?: { mode: 'list' | 'range' | 'wordlist'; list?: string; from?: number; to?: number; pad?: number; wordlist?: string }[]
      grep?: { extract?: string; match?: string[] }
      concurrency?: number
      throttleMs?: number
      identityId?: number
      confirm?: boolean
    },
  ) => post<{ jobId: number; count: number }>(`/domains/${id}/intruder`, bodyReq),

  // Blind-injection confirmation ({{INJ}} marker + differential payloads, gated)
  injectConfirm: (
    id: number,
    bodyReq: {
      template: { method: string; url: string; headers?: Record<string, string>; body?: string; followRedirects?: boolean }
      baseValue?: string
      truePayload?: string
      falsePayload?: string
      sleepPayload?: string
      sleepSeconds?: number
      samples?: number
      confirm?: boolean
    },
  ) => post<{ jobId: number }>(`/domains/${id}/inject-confirm`, bodyReq),

  // AI assists (suggest-only; degrade to { enabled:false, note } with no LLM)
  explainIntruderRow: (jobId: number, rowIndex: number) =>
    post<{ enabled: boolean; explanation?: string; note?: string }>(`/intruder/${jobId}/explain`, { rowIndex }),
  mutatePayload: (payload: string, status?: number) =>
    post<{ enabled: boolean; chains: string[][]; note?: string }>('/payloads/mutate', { payload, status }),
  secretTriage: (domainId: number) =>
    post<{ enabled: boolean; verdicts: { findingId: number; verdict: string; reason: string }[]; note?: string }>(`/domains/${domainId}/secret-triage`, {}),
  narrateChain: (domainId: number, chainId: string) =>
    post<{ enabled: boolean; narrative?: string; note?: string }>(`/domains/${domainId}/chains/narrate`, { chainId }),

  // Named identities (A / B / anon) reused across Repeater / Intruder / authz_diff
  identities: (domainId: number) => get<{ identities: Identity[] }>(`/identities?domainId=${domainId}`),
  saveIdentity: (bodyReq: { domainId: number; name: string; headers?: Record<string, string>; isAnon?: boolean }) =>
    post<{ identity: Identity }>('/identities', bodyReq),
  deleteIdentity: (id: number) => del<{ ok: true }>(`/identities/${id}`),

  // JWT RS256->HS256 alg-confusion confirm ({{JWT}} marker + original token, gated)
  jwtConfuse: (
    id: number,
    bodyReq: {
      template: { method: string; url: string; headers?: Record<string, string>; body?: string; followRedirects?: boolean }
      token: string
      publicKeyPem?: string
      confirm?: boolean
    },
  ) => post<{ jobId: number }>(`/domains/${id}/jwt-confuse`, bodyReq),

  // IDOR / broken-authz diff: replay one {{ID}} object request under 3 identities
  authzDiff: (
    id: number,
    bodyReq: {
      template: { method: string; url: string; headers?: Record<string, string>; body?: string; followRedirects?: boolean }
      ids: { mode: 'list' | 'range'; list?: string; from?: number; to?: number; pad?: number }
      identityB?: { headers: Record<string, string> }
      identityBId?: number
      confirm?: boolean
    },
  ) => post<{ jobId: number; count: number }>(`/domains/${id}/authz-diff`, bodyReq),

  // payload library + encoders (session-authed, not scan-gated)
  payloads: () =>
    get<{
      builtins: { id: string; name: string; category: string; payloads: string[]; notes?: string[] }[]
      grepPhrases: { id: string; name: string; phrases: string[] }[]
      custom: { id: number; name: string; category: string | null; payloads: string[] }[]
      transforms: string[]
    }>('/payloads'),
  createPayloadSet: (bodyReq: { name: string; category?: string; payloads: string[] }) =>
    post<{ set: { id: number; name: string; category: string | null; payloads: string[] } }>('/payloads', bodyReq),
  deletePayloadSet: (id: number) => del<{ ok: true }>(`/payloads/${id}`),
  encodePayload: (input: string, chain: string[]) => post<{ output: string }>('/payloads/encode', { input, chain }),

  // match/replace rules (applied inside the Repeater/Intruder send path)
  matchReplaceRules: () => get<{ rules: MatchReplaceRule[] }>('/match-replace'),
  createMatchReplace: (body: Partial<MatchReplaceRule> & { name: string; part: string }) =>
    post<{ rule: MatchReplaceRule }>('/match-replace', body),
  updateMatchReplace: (id: number, body: Partial<MatchReplaceRule>) => put<{ rule: MatchReplaceRule }>(`/match-replace/${id}`, body),
  deleteMatchReplace: (id: number) => del<{ ok: true }>(`/match-replace/${id}`),

  // Workbench sitemap (endpoint tree from captured + discovered data).
  sitemap: (domainId: number) => get(`/replay/sitemap?domainId=${domainId}`, {}, sitemapResponseSchema),
}
