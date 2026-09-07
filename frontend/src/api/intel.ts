import { z } from 'zod'
import { get, patch, post, type RequestOptions } from './http'
import {
  correlateResponseSchema, nextActionsResponseSchema, chainsResponseSchema,
  methodologySchema, assessmentRunSchema, assessmentComparisonSchema, reportSnapshotSchema,
  type NextActionStatus, type AssessmentProfile, type AssessmentAction,
} from './schemas'

// These types are defined by their zod schemas (single source of truth) and
// re-exported so call sites import them from the api facade unchanged.
export type {
  AttackPath, SignatureCluster, NextAction, NextActionStatus, ChainSuggestion,
  StepStatus, StepAction, MethodologyStep, MethodologySkill, Methodology,
  AssessmentProfile, AssessmentAction, AssessmentRunStatus, AssessmentStepStatus,
  AssessmentExecutionOutcome, AssessmentStepJob, AssessmentStep, AssessmentRun,
  AssessmentFindingSnapshot, AssessmentComparison,
} from './schemas'

const runsResponse = z.object({ runs: z.array(assessmentRunSchema) }).passthrough()
const runResponse = z.object({ run: assessmentRunSchema }).passthrough()
const comparisonResponse = z.object({ comparison: assessmentComparisonSchema }).passthrough()
const reportSnapshotResponse = z.object({ snapshot: reportSnapshotSchema }).passthrough()

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
export const intelApi = {
  // attack-path correlation
  correlate: (id: number) => get(`/domains/${id}/correlate`, {}, correlateResponseSchema),

  // recon methodology / coverage
  methodology: (id: number, options?: RequestOptions) => get(`/domains/${id}/methodology`, options, methodologySchema),
  setMethodologyStep: (id: number, skillId: string, stepKey: string, state: 'done' | 'skipped' | 'clear') =>
    patch(`/domains/${id}/methodology/step`, { skillId, stepKey, state }, methodologySchema),
  nextActions: (id: number, includeClosed = true, options?: RequestOptions) => get(`/domains/${id}/next-actions?includeClosed=${includeClosed}`, options, nextActionsResponseSchema),
  updateNextAction: (id: number, actionKey: string, state: NextActionStatus) =>
    patch(`/domains/${id}/next-actions`, { actionKey, state }, nextActionsResponseSchema),

  // Persistent, dependency-aware assessment workflows.
  assessmentRuns: (id: number, options?: RequestOptions) => get(`/domains/${id}/assessment-runs`, options, runsResponse),
  assessmentRun: (id: number, options?: RequestOptions) => get(`/assessment-runs/${id}`, options, runResponse),
  createAssessmentRun: (id: number, body: { profile: AssessmentProfile; name?: string; steps?: AssessmentAction[]; confirm?: boolean }) =>
    post(`/domains/${id}/assessment-runs`, body, runResponse),
  retryAssessmentRun: (id: number) => post(`/assessment-runs/${id}/retry`, undefined, runResponse),
  cancelAssessmentRun: (id: number) => post(`/assessment-runs/${id}/cancel`, undefined, runResponse),
  assessmentComparison: (id: number, options?: RequestOptions) => get(`/assessment-runs/${id}/comparison`, options, comparisonResponse),
  retryAssessmentTarget: (runId: number, stepId: number, jobId: number) => post(`/assessment-runs/${runId}/steps/${stepId}/jobs/${jobId}/retry`, undefined, runResponse),
  cancelAssessmentTarget: (runId: number, stepId: number, jobId: number) => post(`/assessment-runs/${runId}/steps/${stepId}/jobs/${jobId}/cancel`, undefined, runResponse),
  createAssessmentReport: (id: number) => post(`/assessment-runs/${id}/report-snapshot`, undefined, reportSnapshotResponse),

  // AI-drafted report narrative (optional; only when llm.enabled)
  generateNarrative: (id: number) => post<{ narrative: string; model: string; note: string }>(`/domains/${id}/report/narrative`),

  // AI intel advisor: structured, prioritized testing plan (optional; llm.enabled)
  adviseIntel: (id: number) => post<{ advice: IntelAdvice; model: string; note: string }>(`/domains/${id}/intel/advise`),
  chainSuggestions: (id: number) => get(`/domains/${id}/chains`, {}, chainsResponseSchema),
}
