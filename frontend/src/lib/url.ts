// Return `u` only if it is a plain http(s) URL, otherwise undefined.
//
// Recon data (scanned pages, wayback/urlscan results, tool output) can carry
// attacker-influenced strings. Rendering one straight into an <a href> would let
// a `javascript:` / `data:` URL become a clickable script/redirect vector. None
// of today's sources is a confirmed sink, but this makes the frontend robust to a
// backend source ever loosening. When it returns undefined, callers render the
// value as plain text (href={safeHttpUrl(u)} simply drops the attribute).
export function safeHttpUrl(u: unknown): string | undefined {
  if (typeof u !== 'string' || !u) return undefined
  try {
    const { protocol } = new URL(u)
    return protocol === 'http:' || protocol === 'https:' ? u : undefined
  } catch {
    return undefined // not an absolute URL we can vet — don't make it clickable
  }
}
