import { del, get, post, put } from './http'

export interface Note {
  id: number
  domainId: number | null
  title: string | null
  body: string | null
  createdAt: string
  updatedAt: string
}

export interface DrawingMeta {
  id: number
  domainId: number | null
  name: string | null
  createdAt: string
  updatedAt: string
}

export interface Drawing extends DrawingMeta {
  data: any
}

export interface AuditEntry {
  id: number
  ts: string
  actor: string
  action: string
  domainId: number | null
  target: string | null
  mode: string | null
  jobId: number | null
  detail: string | null
}

export interface AuditQuery {
  domainId?: number
  actor?: string
  action?: string
  mode?: string
  target?: string
  since?: number
  limit?: number
  cursor?: string
}

// One page of audit entries plus the cursor for the next page (null on the last).
export interface AuditPage {
  entries: AuditEntry[]
  nextCursor: string | null
}

// Counts for a filter set: total plus a per-action breakdown.
export interface AuditSummary {
  total: number
  byAction: Record<string, number>
}

// Facets shared by the list and summary endpoints (everything except pagination
// and the action facet the summary intentionally ignores).
function auditFilterParams(q: AuditQuery): URLSearchParams {
  const params = new URLSearchParams()
  if (q.domainId != null) params.set('domainId', String(q.domainId))
  if (q.actor) params.set('actor', q.actor)
  if (q.mode) params.set('mode', q.mode)
  if (q.target) params.set('target', q.target)
  if (q.since) params.set('since', String(q.since))
  return params
}

export const contentApi = {
  // notes
  notes: (domainId: number | 'global') =>
    get<{ notes: Note[] }>(`/notes?domainId=${domainId === 'global' ? 'global' : domainId}`),
  createNote: (domainId: number | null, title: string, body: string) =>
    post<{ note: Note }>('/notes', { domainId, title, body }),
  updateNote: (id: number, title: string, body: string) => put<{ note: Note }>(`/notes/${id}`, { title, body }),
  deleteNote: (id: number) => del<{ ok: true }>(`/notes/${id}`),
  sendNoteToDiscord: (id: number) => post<{ ok: true }>(`/notes/${id}/discord`),

  // drawings
  drawings: () => get<{ drawings: DrawingMeta[] }>('/drawings'),
  drawing: (id: number) => get<{ drawing: Drawing }>(`/drawings/${id}`),
  createDrawing: (name: string, data: unknown) => post<{ drawing: Drawing }>('/drawings', { name, data }),
  updateDrawing: (id: number, data: unknown, name?: string) =>
    put<{ drawing: Drawing }>(`/drawings/${id}`, { data, name }),
  deleteDrawing: (id: number) => del<{ ok: true }>(`/drawings/${id}`),

  // audit ledger (read-only), paged with a keyset cursor and server-side filters
  audit: (q: AuditQuery = {}) => {
    const params = auditFilterParams(q)
    if (q.action) params.set('action', q.action)
    if (q.limit) params.set('limit', String(q.limit))
    if (q.cursor) params.set('cursor', q.cursor)
    const qs = params.toString()
    return get<AuditPage>(`/audit${qs ? `?${qs}` : ''}`)
  },
  // Total plus per-action counts for a filter set (action facet excluded
  // server-side), for header stats without loading every row.
  auditSummary: (q: Pick<AuditQuery, 'domainId' | 'actor' | 'mode' | 'target' | 'since'> = {}) => {
    const qs = auditFilterParams(q).toString()
    return get<AuditSummary>(`/audit/summary${qs ? `?${qs}` : ''}`)
  },
}
