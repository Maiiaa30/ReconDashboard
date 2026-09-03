import { del, get } from './http'

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

export const capturesApi = {
  // captured traffic (from the browser extension)
  captures: (domainId?: number, limit?: number) => {
    const p = new URLSearchParams()
    if (domainId != null) p.set('domainId', String(domainId))
    if (limit) p.set('limit', String(limit))
    const qs = p.toString()
    return get<{ captures: Capture[] }>(`/capture${qs ? `?${qs}` : ''}`)
  },
  captureStatus: () => get<{ enabled: boolean; extensionSeenAt: number | null }>('/capture/status'),
  capture: (id: number) => get<{ capture: Capture }>(`/capture/${id}`),
  deleteCapture: (id: number) => del<{ deleted: number }>(`/capture/${id}`),
  clearCaptures: (domainId: number) => del<{ cleared: number }>(`/capture?domainId=${domainId}`),
}
