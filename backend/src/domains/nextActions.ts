import { and, desc, eq } from 'drizzle-orm'
import { db } from '../db/index'
import { assessmentRuns, nextActionState } from '../db/schema'
import { listFindings } from '../findings/store'
import { buildMethodology, type Methodology } from '../skills/methodology'
import type { StepAction } from '../skills/registry'
import { suggestChains, type ChainSuggestion } from './chainSuggest'
import { getDomain } from './store'
import { safeJsonParse } from '../util/json'

export type NextActionStatus = 'open' | 'attempted' | 'completed' | 'dismissed'
export type NextActionRisk = 'critical' | 'high' | 'medium' | 'low'
export type NextActionMode = 'passive' | 'loud' | 'manual'
export type NextActionSource = 'assessment' | 'finding' | 'attack_chain' | 'methodology'

export interface NextAction {
  key: string
  priority: number
  risk: NextActionRisk
  mode: NextActionMode
  automation: 'automated' | 'guided'
  source: NextActionSource
  title: string
  why: string
  target: string
  page: string
  moduleLabel: string
  status: NextActionStatus
  findingIds: number[]
}

type Finding = ReturnType<typeof listFindings>[number]
type RunSummary = { id: number; name: string; status: string } | null

export interface NextActionInputs {
  domainHost: string
  findings: Finding[]
  latestRun: RunSummary
  methodology: Methodology
  chains: ChainSuggestion[]
}

const ACTIVE_FINDING_STATES = new Set(['open', 'confirmed', 'retest_pending'])
const PASSIVE_ACTIONS = new Set<StepAction['kind']>(['discover', 'exposure', 'osint', 'screenshots'])

function riskForScore(score: number | null): NextActionRisk {
  if ((score ?? 0) >= 90) return 'critical'
  if ((score ?? 0) >= 70) return 'high'
  if ((score ?? 0) >= 40) return 'medium'
  return 'low'
}

function actionPage(action: StepAction): { page: string; label: string } {
  switch (action.kind) {
    case 'discover': return { page: 'subdomains', label: 'Subdomains' }
    case 'exposure': return { page: 'exposure', label: 'Exposure' }
    case 'osint': return { page: 'osint', label: 'OSINT' }
    case 'screenshots': return { page: 'screenshots', label: 'Screenshots' }
    case 'origin': return { page: 'origin', label: 'WAF / Origin' }
    case 'owasp': return { page: 'owasp', label: 'OWASP' }
    case 'nmap': case 'nuclei': return { page: 'scans', label: 'Scans' }
    case 'ffuf': return { page: 'fuzzing', label: 'Fuzzing' }
    case 'tool': return { page: 'tools', label: action.tool ? `Tools · ${action.tool}` : 'Tools' }
  }
}

function findingTitle(finding: Finding): string {
  const data = (finding.data ?? {}) as Record<string, unknown>
  const name = data.title ?? data.name ?? data.templateId ?? data.cveId ?? data.host ?? data.target ?? data.ip ?? data.url
  return typeof name === 'string' && name.trim() ? name.trim().slice(0, 180) : finding.type.replaceAll('_', ' ')
}

function findingTarget(finding: Finding, fallback: string): string {
  const data = (finding.data ?? {}) as Record<string, unknown>
  for (const value of [finding.url, finding.host, finding.ip, data.url, data.target, data.host, data.ip]) {
    if (typeof value === 'string' && value.trim()) return value.trim().slice(0, 300)
  }
  return fallback
}

export function buildNextActions(input: NextActionInputs): NextAction[] {
  const actions: NextAction[] = []
  const base = { status: 'open' as const, findingIds: [] as number[] }

  if (!input.latestRun) {
    actions.push({ ...base, key: 'assessment:start-baseline', priority: 86, risk: 'high', mode: 'passive', automation: 'automated', source: 'assessment', title: 'Establish a passive assessment baseline', why: 'No persistent assessment run exists yet. A passive baseline maps the attack surface before louder testing decisions are made.', target: input.domainHost, page: 'profiles', moduleLabel: 'Scan Profiles' })
  } else if (input.latestRun.status === 'partial') {
    actions.push({ ...base, key: `assessment:${input.latestRun.id}:retry`, priority: 96, risk: 'critical', mode: 'manual', automation: 'guided', source: 'assessment', title: `Recover incomplete coverage in run #${input.latestRun.id}`, why: 'The latest assessment finished partial, so at least one target was degraded, unavailable, skipped or failed. Review exact evidence and retry only the affected targets.', target: input.domainHost, page: 'runs', moduleLabel: 'Assessment Runs' })
  } else if (input.latestRun.status === 'queued' || input.latestRun.status === 'running') {
    actions.push({ ...base, key: `assessment:${input.latestRun.id}:monitor`, priority: 82, risk: 'medium', mode: 'passive', automation: 'automated', source: 'assessment', title: `Monitor active assessment run #${input.latestRun.id}`, why: 'An assessment is still executing. Watch target outcomes so unavailable tooling or degraded coverage is caught before triage.', target: input.domainHost, page: 'runs', moduleLabel: 'Assessment Runs' })
  } else if (input.latestRun.status === 'cancelled') {
    actions.push({ ...base, key: `assessment:${input.latestRun.id}:review-cancelled`, priority: 72, risk: 'medium', mode: 'manual', automation: 'guided', source: 'assessment', title: `Review cancelled assessment run #${input.latestRun.id}`, why: 'Cancelled work leaves an explicit coverage gap. Decide whether the remaining targets should be retried or intentionally excluded.', target: input.domainHost, page: 'runs', moduleLabel: 'Assessment Runs' })
  }

  for (const chain of input.chains.slice(0, 6)) {
    const priority = chain.severity === 'critical' ? 99 : chain.severity === 'high' ? 91 : 76
    actions.push({ ...base, key: `chain:${chain.id}`, priority, risk: chain.severity, mode: chain.action ? 'loud' : 'manual', automation: 'guided', source: 'attack_chain', title: chain.title, why: chain.rationale, target: chain.action?.target ?? input.domainHost, page: 'intel', moduleLabel: 'Attack Paths', findingIds: chain.findingIds })
  }

  const importantFindings = input.findings
    .filter((finding) => ACTIVE_FINDING_STATES.has(finding.status) && (finding.score ?? 0) >= 40)
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, 12)
  for (const finding of importantFindings) {
    const score = finding.score ?? 40
    const confirmedBoost = finding.status === 'confirmed' ? 6 : 0
    actions.push({ ...base, key: `finding:${finding.id}:triage`, priority: Math.min(98, score + 8 + confirmedBoost), risk: riskForScore(finding.score), mode: 'manual', automation: 'guided', source: 'finding', title: `${finding.status === 'confirmed' ? 'Act on' : 'Triage'}: ${findingTitle(finding)}`, why: `${finding.status === 'confirmed' ? 'This finding is confirmed and ready for remediation evidence or exploitation-path review.' : 'This material finding is still open. Validate it, attach evidence, and either confirm or dispose it before reporting.'} Current score: ${score}.`, target: findingTarget(finding, input.domainHost), page: 'findings', moduleLabel: 'Findings', findingIds: [finding.id] })
  }

  for (const skill of input.methodology.skills.filter((item) => item.applicable)) {
    for (const step of skill.steps.filter((item) => item.status === 'todo')) {
      const destination = actionPage(step.action)
      const passive = PASSIVE_ACTIONS.has(step.action.kind)
      actions.push({ ...base, key: `methodology:${skill.id}:${step.key}`, priority: passive ? 74 : 58, risk: passive ? 'medium' : 'low', mode: passive ? 'passive' : 'loud', automation: 'automated', source: 'methodology', title: step.label, why: `${skill.name}: ${step.why}. This applicable methodology step has no completed job or finding evidence yet.`, target: input.domainHost, page: destination.page, moduleLabel: destination.label })
    }
  }

  const unique = new Map<string, NextAction>()
  for (const action of actions) if (!unique.has(action.key)) unique.set(action.key, action)
  return [...unique.values()].sort((a, b) => b.priority - a.priority || a.title.localeCompare(b.title))
}

export function listNextActions(domainId: number, includeClosed = true): NextAction[] | null {
  const domain = getDomain(domainId)
  if (!domain) return null
  const latestRun = db.select({ id: assessmentRuns.id, name: assessmentRuns.name, status: assessmentRuns.status }).from(assessmentRuns).where(eq(assessmentRuns.domainId, domainId)).orderBy(desc(assessmentRuns.id)).limit(1).all()[0] ?? null
  const generated = buildNextActions({ domainHost: domain.host, findings: listFindings({ domainId, limit: 5000 }), latestRun, methodology: buildMethodology(domainId), chains: suggestChains(domainId, domain.host) })
  const stateRows = db.select().from(nextActionState).where(eq(nextActionState.domainId, domainId)).all()
  const states = new Map(stateRows.map((row) => [row.actionKey, row.state as NextActionStatus]))
  const generatedKeys = new Set(generated.map((action) => action.key))
  const archived = stateRows.filter((row) => !generatedKeys.has(row.actionKey)).flatMap((row) => {
    const snapshot = safeJsonParse<NextAction | null>(row.snapshot, null)
    if (!snapshot) return []
    return [{ ...snapshot, status: row.state === 'attempted' ? 'completed' as const : row.state as NextActionStatus }]
  })
  const withState = [...generated.map((action) => ({ ...action, status: states.get(action.key) ?? action.status })), ...archived]
  return (includeClosed ? withState : withState.filter((action) => action.status === 'open' || action.status === 'attempted'))
    .sort((a, b) => {
      const order: Record<NextActionStatus, number> = { open: 0, attempted: 1, completed: 2, dismissed: 3 }
      return order[a.status] - order[b.status] || b.priority - a.priority
    })
}

export function setNextActionState(domainId: number, action: NextAction, state: NextActionStatus): void {
  if (state === 'open') {
    db.delete(nextActionState).where(and(eq(nextActionState.domainId, domainId), eq(nextActionState.actionKey, action.key))).run()
    return
  }
  const now = new Date()
  const snapshot = JSON.stringify({ ...action, status: state })
  db.insert(nextActionState).values({ domainId, actionKey: action.key, state, snapshot, updatedAt: now }).onConflictDoUpdate({
    target: [nextActionState.domainId, nextActionState.actionKey],
    set: { state, snapshot, updatedAt: now },
  }).run()
}
