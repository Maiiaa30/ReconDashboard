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

  // audit ledger (read-only)
  audit: (q: { domainId?: number; limit?: number } = {}) => {
    const params = new URLSearchParams()
    if (q.domainId != null) params.set('domainId', String(q.domainId))
    if (q.limit) params.set('limit', String(q.limit))
    const qs = params.toString()
    return get<{ entries: AuditEntry[] }>(`/audit${qs ? `?${qs}` : ''}`)
  },
}
