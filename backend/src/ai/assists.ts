import { getDomain } from '../domains/store'
import { getJob } from '../jobs/queue'
import { listFindings } from '../findings/store'
import { buildChainSuggestions } from '../domains/chainSuggest'
import { TRANSFORM_NAMES } from '../replay/payloads/encoders'
import { llmComplete, llmCompleteJson, llmEnabled } from '../util/llm'
import { safeJsonParse } from '../util/json'

// AI assists — SUGGEST-ONLY. Every function is read-only: it never mutates a
// finding, never enqueues a scan, and never sends traffic to a target (the model
// only ever sees data already in hand). All fail-soft: with no LLM configured, or
// on any provider/parse error, they return an empty result + a note.

const DISABLED_NOTE = 'AI is disabled. Set LLM_BASE_URL and LLM_MODEL to enable AI assists.'

// 1) Intruder response-diff explanation ---------------------------------------
export interface IntruderExplain {
  enabled: boolean
  explanation?: string
  note?: string
}

export async function explainIntruderRow(jobId: number, rowIndex: number): Promise<IntruderExplain> {
  if (!llmEnabled()) return { enabled: false, note: DISABLED_NOTE }
  const job = getJob(jobId)
  if (!job || job.type !== 'intruder') return { enabled: true, note: 'intruder job not found' }
  const result = safeJsonParse<Record<string, any>>(job.result, null as any)
  if (!result) return { enabled: true, note: 'job has no result yet' }
  const interesting: any[] = Array.isArray(result.interesting) ? result.interesting : []
  const attempts: any[] = Array.isArray(result.attempts) ? result.attempts : []
  const row = interesting[rowIndex] ?? attempts[rowIndex]
  if (!row) return { enabled: true, note: 'row not found' }
  const baseline = result.baseline ?? {}

  const system =
    'You are a web-security analyst. Given an HTTP fuzzing baseline and ONE deviating response, explain in 2-4 sentences WHY it likely deviates and whether it looks exploitable (auth bypass, injection, error leak, IDOR, rate-limit). Be concrete and cautious — never claim certainty. Plain text only.'
  const user =
    `Baseline: status=${baseline.status}, length=${baseline.length}\n` +
    `Deviating row: payload=${JSON.stringify(String(row.payload ?? '')).slice(0, 200)}, status=${row.status}, length=${row.length}, timeMs=${row.timeMs}` +
    `${row.matched ? ', grep-matched=true' : ''}${row.error ? `, error=${String(row.error).slice(0, 120)}` : ''}\n` +
    `Response excerpt:\n${String(row.bodyExcerpt ?? '(none captured)').slice(0, 800)}`

  const explanation = await llmComplete(system, user, 400)
  return explanation ? { enabled: true, explanation } : { enabled: true, note: 'The AI returned no explanation — try again.' }
}

// 2) Payload-mutation suggestion (encoder chains, not new payloads) ------------
export interface MutateResult {
  enabled: boolean
  chains: string[][]
  note?: string
}

export async function suggestPayloadMutation(payload: string, blockedStatus?: number): Promise<MutateResult> {
  if (!llmEnabled()) return { enabled: false, chains: [], note: DISABLED_NOTE }
  const system =
    `You help evade naive WAF/filtering by suggesting ENCODER CHAINS (never new payloads). ` +
    `You may ONLY use these transform names: ${TRANSFORM_NAMES.join(', ')}. Respond with JSON only.`
  const user =
    `The payload ${JSON.stringify(payload.slice(0, 300))} was blocked${blockedStatus ? ` (HTTP ${blockedStatus})` : ''}. ` +
    `Suggest up to 4 encoder chains (ordered arrays of transform names) likely to slip past a naive filter. ` +
    `Return JSON exactly: {"chains":[["url"],["base64"],["url","url"]]}. Use ONLY the allowed names.`

  const out = await llmCompleteJson<{ chains?: unknown }>(system, user, 500)
  const raw = out && Array.isArray(out.chains) ? out.chains : []
  const chains: string[][] = []
  for (const c of raw) {
    if (!Array.isArray(c)) continue
    // Reject any name not in the deterministic registry — the operator applies
    // these via applyChain, which would throw on an unknown name.
    const chain = c.map(String).filter((n) => TRANSFORM_NAMES.includes(n)).slice(0, 8)
    if (chain.length) chains.push(chain)
    if (chains.length >= 4) break
  }
  return { enabled: true, chains, note: chains.length ? undefined : 'The AI returned no valid encoder chains.' }
}

// 3) JS-secret triage: real vs placeholder for the FP-heavy jsrecon bucket -----
export interface SecretVerdict {
  findingId: number
  verdict: 'likely_real' | 'likely_placeholder'
  reason: string
}
export interface SecretTriageResult {
  enabled: boolean
  verdicts: SecretVerdict[]
  note?: string
}

const MAX_SECRETS = 60

export async function suggestSecretTriage(domainId: number): Promise<SecretTriageResult> {
  if (!llmEnabled()) return { enabled: false, verdicts: [], note: DISABLED_NOTE }
  const domain = getDomain(domainId)
  if (!domain) return { enabled: true, verdicts: [], note: 'domain not found' }
  const secrets = listFindings({ domainId, limit: 500 })
    .filter((f) => (f.tags ?? []).includes('secret') || (f.tags ?? []).includes('jsrecon'))
    .filter((f) => f.status === 'open')
    .slice(0, MAX_SECRETS)
  if (!secrets.length) return { enabled: true, verdicts: [], note: 'No open JS-secret findings to triage.' }

  const list = secrets
    .map((f) => `#${f.id} ${JSON.stringify(f.data).slice(0, 220)}`)
    .join('\n')
  const system =
    `You are a secret-scanning triage assistant for the authorized target ${domain.host}. Classify each finding's ` +
    `leaked value as 'likely_real' (a genuine live credential/token) or 'likely_placeholder' (an example, redacted, ` +
    `test, or public value). Be conservative. Respond with JSON only — you may only classify, never act.`
  const user =
    `Findings:\n${list}\n\n` +
    `Return JSON exactly: {"verdicts":[{"findingId":<number>,"verdict":"likely_real|likely_placeholder","reason":"<=140 chars"}]}. ` +
    `Only include findings you are confident about.`

  const out = await llmCompleteJson<{ verdicts?: unknown[] }>(system, user, 2000)
  if (!out || !Array.isArray(out.verdicts)) return { enabled: true, verdicts: [], note: 'The AI returned no usable verdicts.' }
  const ids = new Set(secrets.map((f) => f.id))
  const seen = new Set<number>()
  const verdicts: SecretVerdict[] = []
  for (const raw of out.verdicts) {
    const s = raw as Record<string, unknown>
    const fid = Number(s?.findingId)
    const verdict = String(s?.verdict ?? '')
    if (!ids.has(fid) || seen.has(fid)) continue
    if (verdict !== 'likely_real' && verdict !== 'likely_placeholder') continue
    seen.add(fid)
    verdicts.push({ findingId: fid, verdict, reason: String(s?.reason ?? '').slice(0, 200) })
  }
  return { enabled: true, verdicts }
}

// 4) Chain narration — deterministic structure (Task 9) + LLM prose ------------
export interface ChainNarration {
  enabled: boolean
  narrative?: string
  note?: string
}

export async function narrateChain(domainId: number, chainId: string): Promise<ChainNarration> {
  if (!llmEnabled()) return { enabled: false, note: DISABLED_NOTE }
  const domain = getDomain(domainId)
  if (!domain) return { enabled: true, note: 'domain not found' }
  const chains = buildChainSuggestions(listFindings({ domainId, limit: 500 }), domain.host)
  const chain = chains.find((c) => c.id === chainId)
  if (!chain) return { enabled: true, note: 'chain not found' }

  const system =
    'You are a red-team lead writing a short, concrete attack narrative for an authorized engagement. Given a ' +
    'deterministically-derived attack chain, narrate it in 3-5 sentences: the pivot, why it works, and the impact. ' +
    'Do not invent findings beyond what is given. Plain text only.'
  const user = `Target: ${domain.host}\nChain: ${chain.title}\nSeverity: ${chain.severity}\nRationale: ${chain.rationale}`
  const narrative = await llmComplete(system, user, 400)
  return narrative ? { enabled: true, narrative } : { enabled: true, note: 'The AI returned no narrative — try again.' }
}
