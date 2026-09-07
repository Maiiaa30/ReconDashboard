import type { ZodType } from 'zod'
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

// Raised when a response fails its runtime contract — the backend returned a
// shape the frontend does not expect (a removed or retyped field). Extends
// ApiError so page-level error handling surfaces it like any request failure
// instead of the UI silently rendering `undefined`.
export class ContractError extends ApiError {
  constructor(
    public path: string,
    public issues: string,
  ) {
    super(0, `Response contract mismatch for ${path}: ${issues}`)
    this.name = 'ContractError'
  }
}

/**
 * Validate a decoded response against its schema and return the typed value.
 * Schemas use `.passthrough()`, so a backend that ADDS fields still validates —
 * only a missing/wrong-typed KNOWN field fails, which is the drift worth
 * catching. Throws ContractError on failure instead of casting blindly.
 */
export function validate<T>(schema: ZodType<T>, body: unknown, path: string): T {
  const result = schema.safeParse(body)
  if (result.success) return result.data
  const issues = result.error.issues
    .slice(0, 5)
    .map((i) => `${i.path.join('.') || '<root>'}: ${i.message}`)
    .join('; ')
  console.error(`[api-contract] ${path} failed validation: ${issues}`, body)
  throw new ContractError(path, issues)
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

export async function request<T>(path: string, options: RequestInit = {}, schema?: ZodType<T>): Promise<T> {
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
  return schema ? validate(schema, body, path) : (body as T)
}

// Each verb takes an optional zod schema. When present the response is validated
// at the boundary and the inferred type flows out; when omitted it stays a plain
// cast, so un-migrated call sites are unaffected and migration is incremental.
export const get = <T>(path: string, options: RequestOptions = {}, schema?: ZodType<T>) => request<T>(path, options, schema)
export const post = <T>(path: string, body?: unknown, schema?: ZodType<T>) =>
  request<T>(path, { method: 'POST', body: body == null ? undefined : JSON.stringify(body) }, schema)
export const patch = <T>(path: string, body: unknown, schema?: ZodType<T>) =>
  request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }, schema)
export const put = <T>(path: string, body: unknown, schema?: ZodType<T>) =>
  request<T>(path, { method: 'PUT', body: JSON.stringify(body) }, schema)
export const del = <T>(path: string, schema?: ZodType<T>) => request<T>(path, { method: 'DELETE' }, schema)
