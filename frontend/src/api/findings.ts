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

export const findingsApi = {
  findings: (q: { domainId?: number; type?: string; limit?: number; since?: number } = {}, options?: RequestOptions) => {
    const params = new URLSearchParams()
    if (q.domainId != null) params.set('domainId', String(q.domainId))
    if (q.type) params.set('type', q.type)
    if (q.limit) params.set('limit', String(q.limit))
    if (q.since) params.set('since', String(q.since))
    const qs = params.toString()
    return get<{ findings: Finding[] }>(`/findings${qs ? `?${qs}` : ''}`, options)
  },
  updateFinding: (id: number, patchBody: { status?: FindingStatus; note?: string | null }) =>
    patch<{ finding: Finding }>(`/findings/${id}`, patchBody),
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
