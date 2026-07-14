import { getDomain } from '../domains/store'
import { listFindings, type FindingStatus } from './store'
import { llmCompleteJson, llmEnabled } from '../util/llm'

// AI triage helper: ask the configured LLM to SUGGEST a triage disposition for a
// domain's open findings. Strictly read-only — it never changes a finding and
// never enqueues a scan. The operator applies suggestions via the normal
// bulk-triage action. Fail-soft: any LLM/parse issue returns no suggestions.

export interface TriageSuggestion {
  findingId: number
  suggestedStatus: FindingStatus
  reason: string
  nextAction: string
}

export interface TriageSuggestResult {
  enabled: boolean
  suggestions: TriageSuggestion[]
  note?: string
}

// Statuses the model may suggest — never 'open' (they already are), never a scan.
const SUGGESTABLE: FindingStatus[] = ['confirmed', 'false_positive', 'resolved', 'ignored']
const MAX_FINDINGS = 60

function compact(f: { type: string; data: unknown; score: number | null; tags: string[] }): string {
  let d = ''
  try {
    d = JSON.stringify(f.data)
  } catch {
    d = ''
  }
  return `[${f.type}] score=${f.score ?? 0} tags=${(f.tags ?? []).slice(0, 6).join(',')} — ${d.slice(0, 220)}`
}

export async function suggestTriage(domainId: number): Promise<TriageSuggestResult> {
  if (!llmEnabled()) {
    return {
      enabled: false,
      suggestions: [],
      note: 'AI is disabled. Set LLM_BASE_URL and LLM_MODEL to enable triage suggestions.',
    }
  }
  const domain = getDomain(domainId)
  if (!domain) return { enabled: true, suggestions: [], note: 'domain not found' }

  const open = listFindings({ domainId, limit: 300 }).filter((f) => f.status === 'open')
  if (!open.length) return { enabled: true, suggestions: [], note: 'No open findings to triage.' }

  const capped = open.slice(0, MAX_FINDINGS)
  const list = capped.map((f) => `#${f.id} ${compact(f)}`).join('\n')

  const system =
    `You are a senior penetration tester triaging recon findings for the authorized target ${domain.host}. ` +
    `For each finding, suggest ONE triage status from: ${SUGGESTABLE.join(', ')}. Be conservative: use 'confirmed' only ` +
    `for clearly real, high-signal issues; 'false_positive' for likely scanner noise; 'ignored' for low-value or purely ` +
    `informational items; 'resolved' only if clearly already fixed. You may only SUGGEST — never instruct running a scan. ` +
    `Respond with JSON only.`
  const user =
    `Open findings:\n${list}\n\n` +
    `Return JSON exactly: {"suggestions":[{"findingId":<number>,"suggestedStatus":"<${SUGGESTABLE.join('|')}>",` +
    `"reason":"<why, <=140 chars>","nextAction":"<suggested next step for the operator, <=140 chars>"}]}. ` +
    `Only include findings you are confident about; omit the rest.`

  const out = await llmCompleteJson<{ suggestions?: unknown[] }>(system, user, 2500)
  if (!out || !Array.isArray(out.suggestions)) {
    return { enabled: true, suggestions: [], note: 'The AI returned no usable suggestions — try again.' }
  }

  const openIds = new Set(capped.map((f) => f.id))
  const seen = new Set<number>()
  const suggestions: TriageSuggestion[] = []
  for (const raw of out.suggestions) {
    const s = raw as Record<string, unknown>
    const fid = Number(s?.findingId)
    const status = String(s?.suggestedStatus ?? '')
    if (!openIds.has(fid) || seen.has(fid)) continue // must be a real open finding, no dupes
    if (!SUGGESTABLE.includes(status as FindingStatus)) continue
    seen.add(fid)
    suggestions.push({
      findingId: fid,
      suggestedStatus: status as FindingStatus,
      reason: String(s?.reason ?? '').slice(0, 200),
      nextAction: String(s?.nextAction ?? '').slice(0, 200),
    })
  }
  return { enabled: true, suggestions }
}
