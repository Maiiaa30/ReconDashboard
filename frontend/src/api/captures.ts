import { del, get, type RequestOptions } from './http'
import { capturePageSchema, captureSummarySchema, type Capture } from './schemas'

// Capture, CapturePage and CaptureSummary are defined by their zod schemas
// (single source of truth) and re-exported so call sites import them unchanged.
export type { Capture, CapturePage, CaptureSummary } from './schemas'

export interface CaptureQuery {
  method?: string
  // Free-text search over host/URL/method.
  q?: string
  limit?: number
  cursor?: string
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
    return get(`/capture${qs ? `?${qs}` : ''}`, options, capturePageSchema)
  },
  // total + per-method counts for a filter set (method facet excluded), for
  // header stats without loading every row.
  capturesSummary: (domainId?: number, q: Pick<CaptureQuery, 'q'> = {}, options?: RequestOptions) => {
    const p = new URLSearchParams()
    if (domainId != null) p.set('domainId', String(domainId))
    if (q.q) p.set('q', q.q)
    const qs = p.toString()
    return get(`/capture/summary${qs ? `?${qs}` : ''}`, options, captureSummarySchema)
  },
  captureStatus: () => get<{ enabled: boolean; extensionSeenAt: number | null }>('/capture/status'),
  capture: (id: number) => get<{ capture: Capture }>(`/capture/${id}`),
  deleteCapture: (id: number) => del<{ deleted: number }>(`/capture/${id}`),
  clearCaptures: (domainId: number) => del<{ cleared: number }>(`/capture?domainId=${domainId}`),
}
