import { z } from 'zod'
import { del, get, post, put } from './http'
import {
  sitemapResponseSchema, replayResponseSchema, matchReplaceRuleSchema,
  replayHistoryItemSchema, replayHistoryDetailSchema, identitySchema,
  type MatchReplaceRule,
} from './schemas'

// These types are defined by their zod schemas (single source of truth) and
// re-exported so call sites import them unchanged. IntruderAttempt/IntruderResult
// stay hand-typed below — they ride inside a job result, not a request boundary.
export type {
  ReplayResponse, MatchReplaceRule, ReplayHistoryItem, ReplayHistoryDetail, Identity,
  SitemapEndpoint, SitemapHost,
} from './schemas'

const replaySendResponse = z.object({ response: replayResponseSchema }).passthrough()
const historyResponse = z.object({ history: z.array(replayHistoryItemSchema) }).passthrough()
const historyDetailResponse = z.object({ entry: replayHistoryDetailSchema }).passthrough()
const identitiesResponse = z.object({ identities: z.array(identitySchema) }).passthrough()
const identityResponse = z.object({ identity: identitySchema }).passthrough()
const rulesResponse = z.object({ rules: z.array(matchReplaceRuleSchema) }).passthrough()

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
  }) => post('/replay/send', bodyReq, replaySendResponse),
  // repeater history (optionally scoped to one identity)
  replayHistory: (domainId: number, limit?: number, identityId?: number) =>
    get(
      `/replay/history?domainId=${domainId}${limit ? `&limit=${limit}` : ''}${identityId != null ? `&identityId=${identityId}` : ''}`,
      {}, historyResponse,
    ),
  replayHistoryDetail: (id: number) => get(`/replay/history/${id}`, {}, historyDetailResponse),
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
  identities: (domainId: number) => get(`/identities?domainId=${domainId}`, {}, identitiesResponse),
  saveIdentity: (bodyReq: { domainId: number; name: string; headers?: Record<string, string>; isAnon?: boolean }) =>
    post('/identities', bodyReq, identityResponse),
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
  matchReplaceRules: () => get('/match-replace', {}, rulesResponse),
  createMatchReplace: (body: Partial<MatchReplaceRule> & { name: string; part: string }) =>
    post<{ rule: MatchReplaceRule }>('/match-replace', body),
  updateMatchReplace: (id: number, body: Partial<MatchReplaceRule>) => put<{ rule: MatchReplaceRule }>(`/match-replace/${id}`, body),
  deleteMatchReplace: (id: number) => del<{ ok: true }>(`/match-replace/${id}`),

  // Workbench sitemap (endpoint tree from captured + discovered data).
  sitemap: (domainId: number) => get(`/replay/sitemap?domainId=${domainId}`, {}, sitemapResponseSchema),
}
