import { del, get, type RequestOptions } from './http'

// A request captured by the browser extension, awaiting replay/review.
export interface Capture {
  id: number
  domainId: number | null
  method: string
  url: string
  host: string
  headers: [string, string][]
  body: string | null // null in list responses — lazy-loaded via api.capture(id)
  hasBody?: boolean // present in list responses; whether a body exists to fetch
  source: string
  createdAt: string
}

export interface CaptureQuery {
  method?: string
  // Free-text search over host/URL/method.
  q?: string
  limit?: number
  cursor?: string
}

// One page of captures plus the cursor for the next page (null on the last).
export interface CapturePage {
  captures: Capture[]
  nextCursor: string | null
}

export interface CaptureSummary {
  total: number
  byMethod: Record<string, number>
}

export const capturesApi = {
  // captured traffic (from the browser extension), paged with a keyset cursor
  captures: (domainId?: number, q: CaptureQuery = {}, options?: RequestOptions) => {
    const p = new URLSearchParams()
    if (domainId != null) p.set('domainId', String(domainId))
    if (q.method) p.set('method', q.method)
    if (q.q) p.set('q', q.q)
    if (q.limit) p.set('limit', String(q.limit))
    if (q.cursor) p.set('cursor', q.cursor)
    const qs = p.toString()
    return get<CapturePage>(`/capture${qs ? `?${qs}` : ''}`, options)
  },
  // total + per-method counts for a filter set (method facet excluded), for
  // header stats without loading every row.
  capturesSummary: (domainId?: number, q: Pick<CaptureQuery, 'q'> = {}, options?: RequestOptions) => {
    const p = new URLSearchParams()
    if (domainId != null) p.set('domainId', String(domainId))
    if (q.q) p.set('q', q.q)
    const qs = p.toString()
    return get<CaptureSummary>(`/capture/summary${qs ? `?${qs}` : ''}`, options)
  },
  captureStatus: () => get<{ enabled: boolean; extensionSeenAt: number | null }>('/capture/status'),
  capture: (id: number) => get<{ capture: Capture }>(`/capture/${id}`),
  deleteCapture: (id: number) => del<{ deleted: number }>(`/capture/${id}`),
  clearCaptures: (domainId: number) => del<{ cleared: number }>(`/capture?domainId=${domainId}`),
}
