import { del, get, patch, post, type RequestOptions } from './http'

export type FindingStatus = 'open' | 'confirmed' | 'retest_pending' | 'retest_passed' | 'false_positive' | 'resolved' | 'ignored'

export interface Finding {
  id: number
  domainId: number | null
  type: string
  data: any
  score: number | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null
  host: string | null
  ip: string | null
  url: string | null
  jobId: number | null
  tags: string[]
  status: FindingStatus
  note: string | null
  createdAt: string
  lastSeenAt: string | null
  // When the operator marked this finding for retest (null unless retest_pending).
  retestRequestedAt: string | null
}

export interface FindingLink {
  finding: Finding
  kind: 'confirms' | 'evidence_for' | 'same_asset' | 'chained_from'
  direction: 'outgoing' | 'incoming'
}

export interface TriageSuggestion {
  findingId: number
  suggestedStatus: FindingStatus
  reason: string
  nextAction: string
}

export interface SnapshotMeta {
  findings: number
  high: number
  medium: number
  low: number
  cves: number
}

export interface ReportSnapshot {
  id: number
  assessmentRunId: number | null
  host: string
  label: string | null
  meta: SnapshotMeta | null
  createdAt: string
}

// 'active' hides triaged-away statuses; 'all' shows every status.
export type FindingStatusFilter = FindingStatus | 'active' | 'all'

export interface FindingQuery {
  domainId?: number
  type?: string
  status?: FindingStatusFilter
  severity?: string
  asset?: string
  tag?: string
  since?: number
  limit?: number
  cursor?: string
}

// One page of findings plus the cursor for the next page (null on the last page).
export interface FindingPage {
  findings: Finding[]
  nextCursor: string | null
}

// Outcome of the auto-rescan the retest action tries to enqueue: none for a type
// with no clean re-detection, queued when a scan was launched, or blocked (e.g. a
// passive domain needs `confirm`, or a cooldown/scope rule stopped it).
export type RetestRescan =
  | { kind: 'none' }
  | { kind: 'queued'; jobId: number; jobType: string }
  | { kind: 'blocked'; jobType: string; code: string; message: string; retryAfterSec?: number }

// Counts for a filter set: total plus per-status and per-severity breakdowns.
export interface FindingSummary {
  total: number
  byStatus: Record<string, number>
  bySeverity: Record<string, number>
}

// Facets shared by the list and summary endpoints (everything except pagination
// and the status/severity facets the summary intentionally ignores).
function findingFilterParams(q: FindingQuery): URLSearchParams {
  const params = new URLSearchParams()
  if (q.domainId != null) params.set('domainId', String(q.domainId))
  if (q.type) params.set('type', q.type)
  if (q.asset) params.set('asset', q.asset)
  if (q.tag) params.set('tag', q.tag)
  if (q.since) params.set('since', String(q.since))
  return params
}

export const findingsApi = {
  findings: (q: FindingQuery = {}, options?: RequestOptions) => {
    const params = findingFilterParams(q)
    if (q.status) params.set('status', q.status)
    if (q.severity) params.set('severity', q.severity)
    if (q.limit) params.set('limit', String(q.limit))
    if (q.cursor) params.set('cursor', q.cursor)
    const qs = params.toString()
    return get<FindingPage>(`/findings${qs ? `?${qs}` : ''}`, options)
  },
  // Total plus per-status/per-severity counts for a filter set (status/severity
  // facets excluded server-side), for header stats without loading every row.
  findingsSummary: (
    q: Pick<FindingQuery, 'domainId' | 'type' | 'asset' | 'tag' | 'since'> = {},
    options?: RequestOptions,
  ) => {
    const qs = findingFilterParams(q).toString()
    return get<FindingSummary>(`/findings/summary${qs ? `?${qs}` : ''}`, options)
  },
  updateFinding: (id: number, patchBody: { status?: FindingStatus; note?: string | null }) =>
    patch<{ finding: Finding }>(`/findings/${id}`, patchBody),
  // Mark a finding for retest (→ retest_pending, stamped) and, when the type has
  // a clean re-detection, enqueue that scan. `confirm` passes the passive-domain
  // gate for the loud re-scans. It auto-reopens to confirmed if re-detected.
  retestFinding: (id: number, confirm?: boolean) =>
    post<{ finding: Finding; rescan: RetestRescan }>(`/findings/${id}/retest`, confirm ? { confirm: true } : {}),
  // Attach evidence (request/response/screenshot/note) to a finding (merged).
  attachEvidence: (id: number, body: { request?: string; response?: string; screenshotPath?: string; note?: string }) =>
    post<{ finding: Finding; evidenceCount: number }>(`/findings/${id}/evidence`, body),
  findingLinks: (id: number) => get<{ links: FindingLink[] }>(`/findings/${id}/links`),

  // immutable report snapshots (frozen deliverables)
  snapshots: (domainId: number, options?: RequestOptions) => get<{ snapshots: ReportSnapshot[] }>(`/domains/${domainId}/report/snapshots`, options),
  createSnapshot: (domainId: number, label?: string) =>
    post<{ snapshot: ReportSnapshot }>(`/domains/${domainId}/report/snapshot`, label ? { label } : {}),
  deleteSnapshot: (id: number) => del<{ ok: true }>(`/report/snapshots/${id}`),
  snapshotUrl: (id: number, format: 'html' | 'md') => `/api/report/snapshots/${id}?format=${format}`,
  // Chromium-rendered PDF of a frozen snapshot.
  reportPdfUrl: (id: number) => `/api/export/report/${id}.pdf`,
  // Passive code-leak search (public code, GitHub) → 'secret' findings.
  codeLeaks: (domainId: number, seeds?: string[]) =>
    post<{ jobId: number }>(`/domains/${domainId}/code-leaks`, seeds && seeds.length ? { seeds } : {}),
  bulkUpdateFindings: (ids: number[], patchBody: { status?: FindingStatus; note?: string | null }) =>
    patch<{ changed: number }>('/findings/bulk', { ids, ...patchBody }),
  // AI triage suggestions (suggest-only; nothing is applied server-side).
  triageSuggest: (domainId: number) =>
    post<{ enabled: boolean; suggestions: TriageSuggestion[]; note?: string }>('/findings/triage-suggest', { domainId }),
}
