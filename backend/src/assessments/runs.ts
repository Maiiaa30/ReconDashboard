import { asc, desc, eq, inArray } from 'drizzle-orm'
import type { FastifyBaseLogger } from 'fastify'
import { actorName, writeAudit } from '../audit/store'
import { db } from '../db/index'
import { assessmentRuns, assessmentSteps, type AssessmentRunRow, type AssessmentStepRow } from '../db/schema'
import { assertDomainActive, assertHostInScope, ScanPolicyError } from '../domains/scanPolicy'
import { getDomain } from '../domains/store'
import { cancelJob, enqueueJob, getJob, markCancelRequested, type JobType } from '../jobs/queue'
import { cancelRunningJob } from '../jobs/worker'
import { listSubdomains } from '../subdomains/store'
import { safeJsonParse } from '../util/json'
import { listFindings } from '../findings/store'
import { classifyJobExecution, type ExecutionOutcome } from './execution'

export type AssessmentProfile = 'passive' | 'monitor' | 'web' | 'full' | 'custom'
export type AssessmentAction = 'discover' | 'exposure' | 'osint' | 'screenshots' | 'api' | 'nmap' | 'nuclei' | 'ffuf' | 'owasp' | 'params'
type TargetStrategy = 'domain' | 'live_web' | 'live_hosts'
type StepStatus = 'pending' | 'queued' | 'running' | 'done' | 'degraded' | 'unavailable' | 'failed' | 'skipped' | 'cancelled'

interface StepDefinition {
  key: string
  label: string
  phase: number
  position: number
  action: AssessmentAction
  targetStrategy: TargetStrategy
}

interface StepJob {
  id: number
  target: string | null
}

const LABELS: Record<AssessmentAction, string> = {
  discover: 'Subdomain discovery',
  exposure: 'Exposure intelligence',
  osint: 'OSINT collection',
  screenshots: 'Screenshot baseline',
  api: 'API surface discovery',
  nmap: 'Network surface sweep',
  nuclei: 'Nuclei checks',
  ffuf: 'Content discovery',
  owasp: 'OWASP web checks',
  params: 'Parameter discovery',
}

const TARGETS: Record<AssessmentAction, TargetStrategy> = {
  discover: 'domain', exposure: 'domain', osint: 'domain', screenshots: 'domain', api: 'domain',
  nmap: 'live_hosts', nuclei: 'live_web', ffuf: 'live_web', owasp: 'live_web', params: 'live_web',
}

const PROFILE_ACTIONS: Record<Exclude<AssessmentProfile, 'custom'>, AssessmentAction[][]> = {
  // Phases are intentionally ordered. Discovery must finish before enrichment;
  // URL/API collection must finish before parameter and active web testing.
  passive: [['discover'], ['exposure', 'screenshots'], ['osint', 'api']],
  monitor: [['discover'], ['exposure', 'screenshots'], ['osint', 'api']],
  web: [['screenshots', 'api'], ['params'], ['ffuf', 'owasp']],
  full: [['discover'], ['exposure', 'screenshots'], ['osint', 'api'], ['nmap'], ['params'], ['nuclei', 'ffuf', 'owasp']],
}

const ACTIVE_ACTIONS = new Set<AssessmentAction>(['nmap', 'nuclei', 'ffuf', 'owasp', 'params'])
const ACTIVE_RUN_STATUSES = ['queued', 'running'] as const
const TERMINAL_STEP_STATUSES = new Set<StepStatus>(['done', 'degraded', 'unavailable', 'failed', 'skipped', 'cancelled'])
const MAX_WEB_TARGETS = 20
const MAX_HOST_TARGETS = 50

export class AssessmentRunError extends Error {
  constructor(message: string, public status = 400, public code = 'assessment_error') {
    super(message)
    this.name = 'AssessmentRunError'
  }
}

function definitions(profile: AssessmentProfile, customActions?: AssessmentAction[]): StepDefinition[] {
  let phases: AssessmentAction[][]
  if (profile === 'custom') {
    const actions = [...new Set(customActions ?? [])]
    if (!actions.length) throw new AssessmentRunError('a custom profile needs at least one step')
    // Preserve the operator's chosen set while imposing data dependencies.
    const order: AssessmentAction[][] = [['discover'], ['exposure', 'screenshots'], ['osint', 'api'], ['nmap'], ['params'], ['nuclei', 'ffuf', 'owasp']]
    phases = order.map((phase) => phase.filter((action) => actions.includes(action))).filter((phase) => phase.length)
  } else {
    phases = PROFILE_ACTIONS[profile]
  }
  return phases.flatMap((actions, phase) => actions.map((action, position) => ({
    key: action,
    label: LABELS[action],
    phase,
    position,
    action,
    targetStrategy: TARGETS[action],
  })))
}

function parseStepJobs(step: AssessmentStepRow): StepJob[] {
  return safeJsonParse<StepJob[]>(step.jobs, []).filter((item) => Number.isFinite(item?.id))
}

function stepExecution(stepJobs: StepJob[]): { status: StepStatus; error: string | null } {
  const classified = stepJobs.map((ref) => ({ ref, execution: classifyJobExecution(getJob(ref.id)) }))
  const outcomes = classified.map(({ execution }) => execution.outcome)
  if (outcomes.some((outcome) => outcome === 'running')) return { status: 'running', error: null }
  if (outcomes.some((outcome) => outcome === 'pending')) return { status: 'queued', error: null }
  if (outcomes.length && outcomes.every((outcome) => outcome === 'cancelled')) return { status: 'cancelled', error: 'all target jobs were cancelled' }
  if (outcomes.length && outcomes.every((outcome) => outcome === 'unavailable')) {
    return { status: 'unavailable', error: classified.map(({ ref, execution }) => `${ref.target ?? 'domain'}: ${execution.reason ?? 'unavailable'}`).join(' | ').slice(0, 2000) }
  }
  const successful = outcomes.filter((outcome) => outcome === 'completed').length
  const problems = classified.filter(({ execution }) => !['completed'].includes(execution.outcome)).map(({ ref, execution }) => `${ref.target ?? 'domain'}: ${execution.reason ?? execution.outcome}`)
  if (problems.length) return { status: successful > 0 ? 'degraded' : outcomes.includes('degraded') || outcomes.includes('unavailable') ? 'degraded' : 'failed', error: problems.join(' | ').slice(0, 2000) }
  if (outcomes.length) return { status: 'done', error: null }
  return { status: 'failed', error: 'step has no job records' }
}

function refreshStepStatuses(runId: number): void {
  const now = new Date()
  for (const step of db.select().from(assessmentSteps).where(eq(assessmentSteps.runId, runId)).all()) {
    if (step.status !== 'queued' && step.status !== 'running') continue
    const refs = parseStepJobs(step)
    const execution = stepExecution(refs)
    const status = execution.status
    if (status === step.status) continue
    const terminal = TERMINAL_STEP_STATUSES.has(status)
    const combinedError = [step.error, execution.error].filter(Boolean).join(' | ').slice(0, 2000) || null
    db.update(assessmentSteps).set({ status, error: combinedError, completedAt: terminal ? now : null, updatedAt: now }).where(eq(assessmentSteps.id, step.id)).run()
  }
}

function targetsFor(domainId: number, strategy: TargetStrategy): { targets: { host: string; scheme: string }[]; considered: number; capped: number } {
  const domain = getDomain(domainId)
  if (!domain) return { targets: [], considered: 0, capped: 0 }
  if (strategy === 'domain') return { targets: [{ host: domain.host, scheme: 'https' }], considered: 1, capped: 0 }
  const candidates = [{ host: domain.host, scheme: 'https', ip: null as string | null }, ...listSubdomains(domainId)
    .filter((sub) => strategy === 'live_web' ? sub.httpStatus != null : (sub.httpStatus != null || sub.ipAddress != null))
    .map((sub) => ({ host: sub.host, scheme: sub.scheme === 'http' ? 'http' : 'https', ip: sub.ipAddress }))]
  const seenHosts = new Set<string>()
  const seenIps = new Set<string>()
  const out: { host: string; scheme: string }[] = []
  for (const candidate of candidates) {
    if (seenHosts.has(candidate.host)) continue
    if (strategy === 'live_hosts' && candidate.ip && seenIps.has(candidate.ip)) continue
    seenHosts.add(candidate.host)
    if (candidate.ip) seenIps.add(candidate.ip)
    out.push({ host: candidate.host, scheme: candidate.scheme })
  }
  const limit = strategy === 'live_web' ? MAX_WEB_TARGETS : MAX_HOST_TARGETS
  return { targets: out.slice(0, limit), considered: out.length, capped: Math.max(0, out.length - limit) }
}

function jobSpec(action: AssessmentAction, domainId: number, target: string, scheme: string, runId: number, stepId: number): { type: JobType; params: Record<string, unknown> } {
  const common = { domainId, assessmentRunId: runId, assessmentStepId: stepId }
  switch (action) {
    case 'discover': return { type: 'subdomain_discovery', params: common }
    case 'exposure': return { type: 'exposure_scan', params: common }
    case 'osint': return { type: 'osint_gather', params: common }
    case 'screenshots': return { type: 'screenshot', params: common }
    case 'api': return { type: 'api_discovery', params: common }
    case 'nmap': return { type: 'nmap_scan', params: { ...common, target, deep: false } }
    case 'nuclei': return { type: 'nuclei_scan', params: { ...common, target, scheme } }
    case 'ffuf': return { type: 'ffuf_scan', params: { ...common, target, scheme, path: 'FUZZ', autoWordlist: true } }
    case 'owasp': return { type: 'owasp_active', params: { ...common, target, scheme } }
    case 'params': return { type: 'param_discovery', params: { ...common, target, scheme, path: '/' } }
  }
}

async function enqueueStep(run: AssessmentRunRow, step: AssessmentStepRow): Promise<void> {
  const domain = getDomain(run.domainId)
  if (!domain) throw new AssessmentRunError('domain not found', 404, 'not_found')
  const action = step.action as AssessmentAction
  if (ACTIVE_ACTIONS.has(action)) assertDomainActive(domain, run.confirmActive)
  const targetSet = targetsFor(run.domainId, step.targetStrategy as TargetStrategy)
  const candidates = targetSet.targets
  const valid: { host: string; scheme: string }[] = []
  const skipped: string[] = []
  for (const candidate of candidates) {
    if (!ACTIVE_ACTIONS.has(action)) {
      valid.push(candidate)
      continue
    }
    try {
      valid.push({ ...candidate, host: await assertHostInScope(domain, candidate.host) })
    } catch (error) {
      skipped.push(`${candidate.host}: ${error instanceof Error ? error.message : 'out of scope'}`)
    }
  }
  if (targetSet.capped) skipped.push(`${targetSet.capped} of ${targetSet.considered} eligible targets omitted by the ${step.targetStrategy === 'live_web' ? MAX_WEB_TARGETS : MAX_HOST_TARGETS}-target safety cap`)
  if (!valid.length) {
    db.update(assessmentSteps).set({ status: 'skipped', error: skipped.join(' | ').slice(0, 2000) || 'no eligible targets discovered', completedAt: new Date(), updatedAt: new Date() }).where(eq(assessmentSteps.id, step.id)).run()
    return
  }
  // Domain-wide handlers perform their own sweep and therefore need one job.
  const selected = step.targetStrategy === 'domain' ? valid.slice(0, 1) : valid
  const refs: StepJob[] = selected.map(({ host, scheme }) => {
    const spec = jobSpec(action, run.domainId, host, scheme, run.id, step.id)
    const id = enqueueJob(spec.type, spec.params)
    if (ACTIVE_ACTIONS.has(action)) {
      writeAudit({ actor: run.createdBy, action: `enqueue:${spec.type}`, domainId: run.domainId, target: host, mode: domain.mode, jobId: id, detail: { assessmentRunId: run.id, assessmentStep: step.key } })
    }
    return { id, target: step.targetStrategy === 'domain' ? null : host }
  })
  db.update(assessmentSteps).set({ status: 'queued', jobs: JSON.stringify(refs), error: skipped.length ? skipped.join(' | ').slice(0, 2000) : null, startedAt: new Date(), updatedAt: new Date() }).where(eq(assessmentSteps.id, step.id)).run()
}

export async function advanceAssessmentRun(runId: number): Promise<void> {
  const run = db.select().from(assessmentRuns).where(eq(assessmentRuns.id, runId)).limit(1).all()[0]
  if (!run || !ACTIVE_RUN_STATUSES.includes(run.status as typeof ACTIVE_RUN_STATUSES[number])) return
  refreshStepStatuses(runId)
  const steps = db.select().from(assessmentSteps).where(eq(assessmentSteps.runId, runId)).orderBy(asc(assessmentSteps.phase), asc(assessmentSteps.position)).all()
  if (steps.some((step) => step.status === 'queued' || step.status === 'running')) return
  const pendingPhase = steps.find((step) => step.status === 'pending')?.phase
  if (pendingPhase == null) {
    // A completed step can still carry a coverage warning (for example a
    // target omitted by the safety cap). Keep the whole run explicitly partial
    // rather than presenting a misleading clean 100%.
    const partial = steps.some((step) => ['degraded', 'unavailable', 'failed', 'skipped'].includes(step.status) || !!step.error)
    db.update(assessmentRuns).set({ status: partial ? 'partial' : 'completed', currentPhase: run.totalPhases, completedAt: new Date(), updatedAt: new Date() }).where(eq(assessmentRuns.id, runId)).run()
    writeAudit({ actor: run.createdBy, action: `assessment:${partial ? 'partial' : 'completed'}`, domainId: run.domainId, detail: { runId, completedSteps: steps.filter((step) => step.status === 'done').length, totalSteps: steps.length } })
    return
  }
  const pending = steps.filter((step) => step.phase === pendingPhase && step.status === 'pending')
  db.update(assessmentRuns).set({ status: 'running', currentPhase: pendingPhase, startedAt: run.startedAt ?? new Date(), updatedAt: new Date() }).where(eq(assessmentRuns.id, runId)).run()
  for (const step of pending) {
    try {
      await enqueueStep(run, step)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'failed to queue step'
      db.update(assessmentSteps).set({ status: 'failed', error: message.slice(0, 2000), completedAt: new Date(), updatedAt: new Date() }).where(eq(assessmentSteps.id, step.id)).run()
    }
  }
  // A phase can contain only skipped/failed steps (no jobs to wake the
  // orchestrator), so immediately continue to the next phase in that case.
  const after = db.select().from(assessmentSteps).where(eq(assessmentSteps.runId, runId)).all()
  if (!after.some((step) => step.status === 'queued' || step.status === 'running')) await advanceAssessmentRun(runId)
}

export async function createAssessmentRun(input: { domainId: number; profile: AssessmentProfile; name?: string; customActions?: AssessmentAction[]; confirm?: boolean; userId?: number }): Promise<ReturnType<typeof getAssessmentRun>> {
  const domain = getDomain(input.domainId)
  if (!domain) throw new AssessmentRunError('domain not found', 404, 'not_found')
  const active = db.select().from(assessmentRuns).where(inArray(assessmentRuns.status, [...ACTIVE_RUN_STATUSES])).all().find((run) => run.domainId === input.domainId)
  if (active) throw new AssessmentRunError(`assessment run #${active.id} is already active for ${domain.host}`, 409, 'already_running')
  const defs = definitions(input.profile, input.customActions)
  if (defs.some((step) => ACTIVE_ACTIONS.has(step.action))) {
    try { assertDomainActive(domain, input.confirm === true) } catch (error) {
      if (error instanceof ScanPolicyError) throw new AssessmentRunError(error.message, error.status, error.code)
      throw error
    }
  }
  const createdBy = actorName(input.userId)
  const totalPhases = Math.max(...defs.map((step) => step.phase)) + 1
  const runId = db.transaction((tx) => {
    const id = Number(tx.insert(assessmentRuns).values({ domainId: input.domainId, profile: input.profile, name: input.name?.trim().slice(0, 120) || `${input.profile[0].toUpperCase()}${input.profile.slice(1)} assessment`, createdBy, confirmActive: input.confirm === true, totalPhases }).run().lastInsertRowid)
    tx.insert(assessmentSteps).values(defs.map((step) => ({ runId: id, ...step }))).run()
    return id
  })
  writeAudit({ actor: createdBy, action: 'assessment:start', domainId: input.domainId, mode: domain.mode, detail: { runId, profile: input.profile, steps: defs.map((step) => step.action) } })
  await advanceAssessmentRun(runId)
  return getAssessmentRun(runId)
}

export function getAssessmentRun(runId: number) {
  const run = db.select().from(assessmentRuns).where(eq(assessmentRuns.id, runId)).limit(1).all()[0]
  if (!run) return null
  const domainFindings = listFindings({ domainId: run.domainId, limit: 5000 })
  const steps = db.select().from(assessmentSteps).where(eq(assessmentSteps.runId, runId)).orderBy(asc(assessmentSteps.phase), asc(assessmentSteps.position)).all().map((step) => {
    const stepJobs = parseStepJobs(step).map((ref) => {
      const job = getJob(ref.id)
      const execution = classifyJobExecution(job)
      const findingsProduced = domainFindings.filter((finding) => finding.jobId === ref.id)
      return {
        ...ref,
        status: job?.status ?? 'missing',
        outcome: execution.outcome,
        reason: execution.reason,
        summary: execution.summary,
        progress: job?.progress ?? null,
        error: job?.error ?? null,
        findingsProduced: findingsProduced.length,
        highFindings: findingsProduced.filter((finding) => (finding.score ?? 0) >= 70).length,
      }
    })
    const counts = (outcome: ExecutionOutcome) => stepJobs.filter((job) => job.outcome === outcome).length
    return {
      ...step,
      jobs: stepJobs,
      evidence: {
        targets: stepJobs.length,
        completed: counts('completed'),
        degraded: counts('degraded'),
        unavailable: counts('unavailable'),
        failed: counts('failed') + counts('missing'),
        cancelled: counts('cancelled'),
        findingsProduced: stepJobs.reduce((sum, job) => sum + job.findingsProduced, 0),
        highFindings: stepJobs.reduce((sum, job) => sum + job.highFindings, 0),
      },
    }
  })
  const done = steps.filter((step) => step.status === 'done').length
  const concreteJobs = steps.flatMap((step) => step.jobs)
  const completedJobs = concreteJobs.filter((job) => job.outcome === 'completed').length
  return {
    ...run,
    steps,
    coverage: steps.length ? Math.round((done / steps.length) * 100) : 0,
    completedSteps: done,
    totalSteps: steps.length,
    targetCoverage: concreteJobs.length ? Math.round((completedJobs / concreteJobs.length) * 100) : 0,
    completedTargetJobs: completedJobs,
    totalTargetJobs: concreteJobs.length,
  }
}

export function listAssessmentRuns(domainId: number, limit = 20) {
  return db.select().from(assessmentRuns).where(eq(assessmentRuns.domainId, domainId)).orderBy(desc(assessmentRuns.id)).limit(Math.min(Math.max(limit, 1), 100)).all().map((run) => getAssessmentRun(run.id)!)
}

export async function retryAssessmentRun(runId: number): Promise<ReturnType<typeof getAssessmentRun>> {
  const run = db.select().from(assessmentRuns).where(eq(assessmentRuns.id, runId)).limit(1).all()[0]
  if (!run) throw new AssessmentRunError('assessment run not found', 404, 'not_found')
  const retryable = db.select().from(assessmentSteps).where(eq(assessmentSteps.runId, runId)).all().filter((step) => ['degraded', 'unavailable', 'failed', 'skipped'].includes(step.status) || !!step.error)
  if (!retryable.length) throw new AssessmentRunError('this run has no failed or skipped steps to retry', 409, 'nothing_to_retry')
  const firstPhase = Math.min(...retryable.map((step) => step.phase))
  for (const step of retryable) db.update(assessmentSteps).set({ status: 'pending', jobs: '[]', error: null, startedAt: null, completedAt: null, updatedAt: new Date() }).where(eq(assessmentSteps.id, step.id)).run()
  db.update(assessmentRuns).set({ status: 'running', currentPhase: firstPhase, completedAt: null, updatedAt: new Date() }).where(eq(assessmentRuns.id, runId)).run()
  writeAudit({ actor: run.createdBy, action: 'assessment:retry', domainId: run.domainId, detail: { runId, steps: retryable.map((step) => step.key) } })
  await advanceAssessmentRun(runId)
  return getAssessmentRun(runId)
}

export function cancelAssessmentRun(runId: number): ReturnType<typeof getAssessmentRun> {
  const run = db.select().from(assessmentRuns).where(eq(assessmentRuns.id, runId)).limit(1).all()[0]
  if (!run) throw new AssessmentRunError('assessment run not found', 404, 'not_found')
  if (!ACTIVE_RUN_STATUSES.includes(run.status as typeof ACTIVE_RUN_STATUSES[number])) throw new AssessmentRunError(`assessment run is already ${run.status}`, 409, 'not_running')
  for (const step of db.select().from(assessmentSteps).where(eq(assessmentSteps.runId, runId)).all()) {
    for (const { id } of parseStepJobs(step)) {
      if (!cancelJob(id)) {
        markCancelRequested(id)
        cancelRunningJob(id)
      }
    }
    if (!TERMINAL_STEP_STATUSES.has(step.status as StepStatus)) db.update(assessmentSteps).set({ status: 'cancelled', completedAt: new Date(), updatedAt: new Date() }).where(eq(assessmentSteps.id, step.id)).run()
  }
  db.update(assessmentRuns).set({ status: 'cancelled', completedAt: new Date(), updatedAt: new Date() }).where(eq(assessmentRuns.id, runId)).run()
  writeAudit({ actor: run.createdBy, action: 'assessment:cancelled', domainId: run.domainId, detail: { runId } })
  return getAssessmentRun(runId)
}

let reconciling = false
let timer: NodeJS.Timeout | null = null

export async function reconcileAssessmentRuns(log?: FastifyBaseLogger): Promise<void> {
  if (reconciling) return
  reconciling = true
  try {
    const active = db.select({ id: assessmentRuns.id }).from(assessmentRuns).where(inArray(assessmentRuns.status, [...ACTIVE_RUN_STATUSES])).all()
    for (const { id } of active) await advanceAssessmentRun(id)
  } catch (error) {
    log?.warn({ err: error }, 'assessment orchestrator reconciliation failed')
  } finally {
    reconciling = false
  }
}

export function startAssessmentOrchestrator(log: FastifyBaseLogger, intervalMs = 2_000): void {
  void reconcileAssessmentRuns(log)
  timer = setInterval(() => void reconcileAssessmentRuns(log), intervalMs)
  timer.unref()
  log.info('assessment orchestrator started')
}

export function stopAssessmentOrchestrator(): void {
  if (timer) clearInterval(timer)
  timer = null
}
