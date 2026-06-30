// Parse JSON that *should* be valid (it was written by us) but guard against a
// corrupted row taking down an entire list endpoint.
export function safeJsonParse<T>(text: string | null | undefined, fallback: T): T {
  if (text == null) return fallback
  try {
    return JSON.parse(text) as T
  } catch {
    return fallback
  }
}
