import { safeJsonParse } from '../util/json'

export type ExecutionOutcome = 'pending' | 'running' | 'completed' | 'degraded' | 'unavailable' | 'failed' | 'cancelled' | 'missing'

export interface ExecutionJob {
  status: string
  result?: string | null
  error?: string | null
}

export interface ExecutionClassification {
  outcome: ExecutionOutcome
  reason: string | null
  summary: string[]
}

// Handlers may return this contract in their result payload. The fallback
// inference below remains for older handlers, while assessment history always
// persists the normalized classification.
export interface JobExecutionContract {
  outcome: 'completed' | 'degraded' | 'unavailable'
  reason?: string | null
  summary?: string[]
}

const SUMMARY_KEYS = [
  'count', 'hits', 'found', 'tested', 'captured', 'attempted', 'hostsChecked',
  'ipsResolved', 'exposedIps', 'discovered', 'newCount', 'specs', 'graphql',
  'jsEndpoints', 'jsFilesScanned', 'newHostsFromJs', 'matched', 'upgraded',
] as const

function resultSummary(result: Record<string, unknown>): string[] {
  const out: string[] = []
  for (const key of SUMMARY_KEYS) {
    const value = result[key]
    if (typeof value === 'number' || typeof value === 'boolean') out.push(`${key}: ${value}`)
  }
  if (typeof result.target === 'string') out.unshift(`target: ${result.target}`)
  if (typeof result.domain === 'string') out.unshift(`domain: ${result.domain}`)
  return out.slice(0, 8)
}

// Collect explicit degradation markers from a result without serializing the
// whole payload (which may contain scan evidence). A bounded traversal catches
// aggregate provider results such as OSINT's nested { error } values and
// discovery's source="unavailable" markers.
function collectIssues(value: unknown, path = '', depth = 0, out: string[] = []): string[] {
  if (depth > 4 || out.length >= 8 || value == null) return out
  if (typeof value === 'string') {
    if (/^(error:|unavailable\b|failed\b)/i.test(value) || /not installed|not configured|no live web hosts/i.test(value)) {
      out.push(`${path || 'result'}: ${value}`)
    }
    return out
  }
  if (Array.isArray(value)) {
    value.slice(0, 12).forEach((item, index) => collectIssues(item, `${path}[${index}]`, depth + 1, out))
    return out
  }
  if (typeof value !== 'object') return out
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const next = path ? `${path}.${key}` : key
    if (key === 'error' && typeof item === 'string' && item.trim()) out.push(`${next}: ${item}`)
    else collectIssues(item, next, depth + 1, out)
    if (out.length >= 8) break
  }
  return out
}

export function classifyJobExecution(job: ExecutionJob | undefined): ExecutionClassification {
  if (!job) return { outcome: 'missing', reason: 'job record is missing', summary: [] }
  if (job.status === 'queued') return { outcome: 'pending', reason: null, summary: [] }
  if (job.status === 'running') return { outcome: 'running', reason: null, summary: [] }
  if (job.status === 'cancelled') return { outcome: 'cancelled', reason: job.error ?? 'cancelled', summary: [] }
  if (job.status === 'error' || job.status === 'dead') return { outcome: 'failed', reason: job.error ?? job.status, summary: [] }
  if (job.status !== 'done') return { outcome: 'failed', reason: job.error ?? `unexpected job status: ${job.status}`, summary: [] }

  const result = safeJsonParse<Record<string, unknown>>(job.result, {})
  const summary = resultSummary(result)
  const explicit = result.execution && typeof result.execution === 'object'
    ? result.execution as Partial<JobExecutionContract>
    : null
  if (explicit && ['completed', 'degraded', 'unavailable'].includes(String(explicit.outcome))) {
    return {
      outcome: explicit.outcome as JobExecutionContract['outcome'],
      reason: typeof explicit.reason === 'string' ? explicit.reason : null,
      summary: Array.isArray(explicit.summary) ? explicit.summary.filter((item): item is string => typeof item === 'string').slice(0, 8) : summary,
    }
  }
  const note = typeof result.note === 'string' ? result.note : typeof result.reason === 'string' ? result.reason : null
  if (result.available === false) return { outcome: 'unavailable', reason: note ?? 'required scanner or provider is unavailable', summary }

  const issues = collectIssues(result)
  if (result.aborted === true) issues.unshift('execution was aborted before completion')
  if (result.reachable === false) issues.unshift('target was not reachable')
  if (result.partial === true || result.degraded === true) issues.unshift('handler reported partial/degraded execution')
  if (typeof result.failed === 'number' && result.failed > 0) issues.unshift(`${result.failed} operation(s) failed`)
  if (Array.isArray(result.errors) && result.errors.length) issues.unshift(`${result.errors.length} error(s) reported`)
  if (issues.length) return { outcome: 'degraded', reason: [...new Set(issues)].slice(0, 8).join(' | '), summary }

  return { outcome: 'completed', reason: null, summary }
}
