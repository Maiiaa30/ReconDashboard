import { get, patch, post, type RequestOptions } from './http'
import type { ReportSnapshot } from './findings'

export interface AttackPath {
  ip: string
  cdn: string | null
  asn: string | null
  asnName: string | null
  hosts: string[]
  ports: number[]
  cveCount: number
  worstCvss: number | null
  kev: boolean
  score: number
}

// Hosts sharing a TLS cert / favicon hash — same asset across different IPs.
export interface SignatureCluster {
  key: string
  kind: 'cert' | 'favicon'
  signature: string
  hosts: string[]
  ips: string[]
}

export type AdviceActionKind = 'nmap' | 'naabu' | 'nuclei' | 'ffuf' | 'dalfox' | 'sslscan' | 'katana' | 'owasp'
export interface AdviceAction {
  kind: AdviceActionKind
  target: string
}
export interface IntelAdvice {
  summary: string
  priorities: { target: string; risk: 'high' | 'medium' | 'low'; why: string; tests: string[]; action?: AdviceAction }[]
  injection: { target: string; param?: string; type: string; why: string; action?: AdviceAction }[]
  quickWins: { item: string; why: string }[]
  deeperDigs: { item: string; why: string }[]
}
export interface ChainSuggestion {
  id: string
  title: string
  rationale: string
  severity: 'critical' | 'high' | 'medium'
  findingIds: number[]
  action?: AdviceAction
}

export type StepStatus = 'found' | 'done' | 'running' | 'todo' | 'skipped'
export interface StepAction {
  kind: 'discover' | 'exposure' | 'osint' | 'screenshots' | 'origin' | 'owasp' | 'nmap' | 'nuclei' | 'ffuf' | 'tool'
  tool?: string
  tags?: string
}
export interface MethodologyStep {
  key: string
  label: string
  why: string
  action: StepAction
  status: StepStatus
  manual: boolean
}
export interface MethodologySkill {
  id: string
  name: string
  description: string
  applicable: boolean
  reason: string
  coverage: number
  steps: MethodologyStep[]
}
export interface Methodology {
  tech: string[]
  ports: number[]
  skills: MethodologySkill[]
}

export type NextActionStatus = 'open' | 'attempted' | 'completed' | 'dismissed'
export interface NextAction {
  key: string
  priority: number
  risk: 'critical' | 'high' | 'medium' | 'low'
  mode: 'passive' | 'loud' | 'manual'
  automation: 'automated' | 'guided'
  source: 'assessment' | 'finding' | 'attack_chain' | 'methodology'
  title: string
  why: string
  target: string
  page: string
  moduleLabel: string
  status: NextActionStatus
  findingIds: number[]
}

export type AssessmentProfile = 'passive' | 'monitor' | 'web' | 'full' | 'custom'
export type AssessmentAction = 'discover' | 'exposure' | 'osint' | 'screenshots' | 'api' | 'nmap' | 'nuclei' | 'ffuf' | 'owasp' | 'params'
export type AssessmentRunStatus = 'queued' | 'running' | 'completed' | 'partial' | 'cancelled'
export type AssessmentStepStatus = 'pending' | 'queued' | 'running' | 'done' | 'degraded' | 'unavailable' | 'failed' | 'skipped' | 'cancelled'
export type AssessmentExecutionOutcome = 'pending' | 'running' | 'completed' | 'degraded' | 'unavailable' | 'failed' | 'cancelled' | 'missing'
export interface AssessmentStepJob {
  id: number
  target: string | null
  attempt: number
  current: boolean
  status: string
  outcome: AssessmentExecutionOutcome
  reason: string | null
  summary: string[]
  progress: string | null
  error: string | null
  findingsProduced: number
  highFindings: number
}
export interface AssessmentStep {
  id: number
  runId: number
  key: string
  label: string
  phase: number
  position: number
  action: AssessmentAction
  targetStrategy: 'domain' | 'live_web' | 'live_hosts'
  status: AssessmentStepStatus
  jobs: AssessmentStepJob[]
  error: string | null
  startedAt: string | null
  completedAt: string | null
  evidence: {
    targets: number
    completed: number
    degraded: number
    unavailable: number
    failed: number
    cancelled: number
    findingsProduced: number
    highFindings: number
  }
}
export interface AssessmentRun {
  id: number
  domainId: number
  profile: AssessmentProfile
  name: string
  status: AssessmentRunStatus
  createdBy: string
  confirmActive: boolean
  currentPhase: number
  totalPhases: number
  coverage: number
  completedSteps: number
  totalSteps: number
  targetCoverage: number
  completedTargetJobs: number
  totalTargetJobs: number
  steps: AssessmentStep[]
  startedAt: string | null
  completedAt: string | null
  createdAt: string
  updatedAt: string
  reportSnapshot: ReportSnapshot | null
}

export interface AssessmentFindingSnapshot {
  findingKey: string
  findingId: number | null
  type: string
  title: string
  target: string | null
  score: number | null
  severity: string | null
  status: string
}

export interface AssessmentComparison {
  previousRunId: number | null
  counts: { new: number; unchanged: number; resolved: number; regressed: number }
  new: AssessmentFindingSnapshot[]
  unchanged: AssessmentFindingSnapshot[]
  resolved: AssessmentFindingSnapshot[]
  regressed: AssessmentFindingSnapshot[]
}

export const intelApi = {
  // attack-path correlation
  correlate: (id: number) => get<{ paths: AttackPath[]; signatureClusters: SignatureCluster[] }>(`/domains/${id}/correlate`),

  // recon methodology / coverage
  methodology: (id: number, options?: RequestOptions) => get<Methodology>(`/domains/${id}/methodology`, options),
  setMethodologyStep: (id: number, skillId: string, stepKey: string, state: 'done' | 'skipped' | 'clear') =>
    patch<Methodology>(`/domains/${id}/methodology/step`, { skillId, stepKey, state }),
  nextActions: (id: number, includeClosed = true, options?: RequestOptions) => get<{ actions: NextAction[] }>(`/domains/${id}/next-actions?includeClosed=${includeClosed}`, options),
  updateNextAction: (id: number, actionKey: string, state: NextActionStatus) =>
    patch<{ actions: NextAction[] }>(`/domains/${id}/next-actions`, { actionKey, state }),

  // Persistent, dependency-aware assessment workflows.
  assessmentRuns: (id: number, options?: RequestOptions) => get<{ runs: AssessmentRun[] }>(`/domains/${id}/assessment-runs`, options),
  assessmentRun: (id: number, options?: RequestOptions) => get<{ run: AssessmentRun }>(`/assessment-runs/${id}`, options),
  createAssessmentRun: (id: number, body: { profile: AssessmentProfile; name?: string; steps?: AssessmentAction[]; confirm?: boolean }) =>
    post<{ run: AssessmentRun }>(`/domains/${id}/assessment-runs`, body),
  retryAssessmentRun: (id: number) => post<{ run: AssessmentRun }>(`/assessment-runs/${id}/retry`),
  cancelAssessmentRun: (id: number) => post<{ run: AssessmentRun }>(`/assessment-runs/${id}/cancel`),
  assessmentComparison: (id: number, options?: RequestOptions) => get<{ comparison: AssessmentComparison }>(`/assessment-runs/${id}/comparison`, options),
  retryAssessmentTarget: (runId: number, stepId: number, jobId: number) => post<{ run: AssessmentRun }>(`/assessment-runs/${runId}/steps/${stepId}/jobs/${jobId}/retry`),
  cancelAssessmentTarget: (runId: number, stepId: number, jobId: number) => post<{ run: AssessmentRun }>(`/assessment-runs/${runId}/steps/${stepId}/jobs/${jobId}/cancel`),
  createAssessmentReport: (id: number) => post<{ snapshot: ReportSnapshot }>(`/assessment-runs/${id}/report-snapshot`),

  // AI-drafted report narrative (optional; only when llm.enabled)
  generateNarrative: (id: number) => post<{ narrative: string; model: string; note: string }>(`/domains/${id}/report/narrative`),

  // AI intel advisor: structured, prioritized testing plan (optional; llm.enabled)
  adviseIntel: (id: number) => post<{ advice: IntelAdvice; model: string; note: string }>(`/domains/${id}/intel/advise`),
  chainSuggestions: (id: number) => get<{ chains: ChainSuggestion[] }>(`/domains/${id}/chains`),
}
