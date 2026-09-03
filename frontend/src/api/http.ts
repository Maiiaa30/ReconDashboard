import { markOffline, markOnline, markSessionExpired } from './connection'

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export type RequestOptions = Pick<RequestInit, 'signal'>

export async function readResponseBody(response: Response): Promise<unknown> {
  const text = await response.text()
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

export function apiError(response: Response, body: unknown): ApiError {
  const message = body && typeof body === 'object' && 'error' in body
    ? String((body as { error: unknown }).error)
    : `HTTP ${response.status}`
  return new ApiError(response.status, message)
}

function isAbort(err: unknown): boolean {
  // A caller-initiated cancellation (unmount, obsolete poll, job cancel) rejects
  // with an AbortError — that is not a connectivity problem.
  return err instanceof DOMException ? err.name === 'AbortError' : (err as { name?: string })?.name === 'AbortError'
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      // Only send a JSON content-type when there is a body. GET/DELETE requests
      // stay simple and do not trigger needless preflights or strict rejections.
      headers: options.body ? { 'Content-Type': 'application/json' } : {},
      ...options,
    })
  } catch (err) {
    // fetch only rejects on a network-level failure (backend/tailnet down),
    // never on an HTTP error status. Ignore intentional cancellations.
    if (!isAbort(err)) markOffline()
    throw err
  }
  // A response of any status means the backend is reachable again.
  markOnline()
  const body = await readResponseBody(response)
  if (!response.ok) {
    if (response.status === 401) markSessionExpired()
    throw apiError(response, body)
  }
  return body as T
}

export const get = <T>(path: string, options: RequestOptions = {}) => request<T>(path, options)
export const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body == null ? undefined : JSON.stringify(body) })
export const patch = <T>(path: string, body: unknown) => request<T>(path, { method: 'PATCH', body: JSON.stringify(body) })
export const put = <T>(path: string, body: unknown) => request<T>(path, { method: 'PUT', body: JSON.stringify(body) })
export const del = <T>(path: string) => request<T>(path, { method: 'DELETE' })
