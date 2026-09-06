// Typed facade over focused, per-domain API clients. Every client is composed
// into the single `api` object below, and its types are re-exported here, so
// existing `import { api, type Finding } from './api'` call sites stay stable
// while the implementation lives in cohesive `./api/*` modules.
export { ApiError } from './api/http'
export type { RequestOptions } from './api/http'

import { authApi } from './api/auth'
import { capturesApi } from './api/captures'
import { contentApi } from './api/content'
import { domainsApi } from './api/domains'
import { findingsApi } from './api/findings'
import { homeApi } from './api/home'
import { intelApi } from './api/intel'
import { jobsApi } from './api/jobs'
import { reconApi } from './api/recon'
import { replayApi } from './api/replay'
import { scansApi } from './api/scans'
import { systemApi } from './api/system'
import { toolsApi } from './api/tools'

export type { Me } from './api/auth'
export type { Capture, CapturePage, CaptureQuery, CaptureSummary } from './api/captures'
export type { AuditEntry, AuditPage, AuditQuery, AuditSummary, Drawing, DrawingMeta, Note } from './api/content'
export type { Domain, DomainMode, DomainOverview, DomainProfile, OwaspConfig, ScopeConfig } from './api/domains'
export type {
  Finding,
  FindingLink,
  FindingPage,
  FindingQuery,
  FindingStatus,
  FindingStatusFilter,
  FindingSummary,
  ReportSnapshot,
  SnapshotMeta,
  TriageSuggestion,
} from './api/findings'
export type { HomeFinding, RecentChange, TodayData } from './api/home'
export type {
  AdviceAction,
  AdviceActionKind,
  AssessmentAction,
  AssessmentComparison,
  AssessmentExecutionOutcome,
  AssessmentFindingSnapshot,
  AssessmentProfile,
  AssessmentRun,
  AssessmentRunStatus,
  AssessmentStep,
  AssessmentStepJob,
  AssessmentStepStatus,
  AttackPath,
  ChainSuggestion,
  IntelAdvice,
  Methodology,
  MethodologySkill,
  MethodologyStep,
  NextAction,
  NextActionStatus,
  SignatureCluster,
  StepAction,
  StepStatus,
} from './api/intel'
export type { Job, JobStatus } from './api/jobs'
export type { Asset, FreeEmailResult, LeaksResponse, ScreenshotEntry, Subdomain, SubdomainPage, SubdomainQuery, SubdomainSort, SubdomainSummary } from './api/recon'
export type {
  Identity,
  IntruderAttempt,
  IntruderResult,
  MatchReplaceRule,
  ReplayHistoryDetail,
  ReplayHistoryItem,
  ReplayResponse,
  SitemapEndpoint,
  SitemapHost,
} from './api/replay'
export type { OwaspCategory, OwaspProfileKey } from './api/scans'
export type { BackupCheckResult, MetaStatus, Wordlist } from './api/system'
export type { CheckHostResult, PingResult, TcpResult, WhoisResult } from './api/tools'

// --- API surface -------------------------------------------------------------
// Method names are unique across clients, so the spread composition preserves
// the exact shape of the previous single-object facade.
export const api = {
  ...authApi,
  ...homeApi,
  ...systemApi,
  ...domainsApi,
  ...reconApi,
  ...scansApi,
  ...intelApi,
  ...replayApi,
  ...capturesApi,
  ...jobsApi,
  ...findingsApi,
  ...toolsApi,
  ...contentApi,
}
