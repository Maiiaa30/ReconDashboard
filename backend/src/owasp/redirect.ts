// Open-redirect / SSRF-candidate helpers — pure, so the tricky bypass-confirmation
// logic is unit-testable. The core idea: don't trust that a payload was reflected;
// resolve the server's actual Location header the way a BROWSER would (WHATWG URL,
// which turns `\` into `/` and honors protocol-relative `//`) and only flag when
// the resolved host is the attacker's. That kills the false positives from a
// param that's echoed but doesn't actually change the redirect target.

export const REDIRECT_EVIL_HOST = 'evil.example.org'

// Bypass payload forms a naive allowlist misses: absolute, protocol-relative,
// backslash, scheme-with-one-slash, URL-encoded slashes, @-userinfo (the host
// after `@` is the real target), fullwidth slashes, and null-byte truncation.
// redirectsToAttacker resolves the server's ACTUAL Location, so whichever the
// server honors is attributed correctly.
export const REDIRECT_PAYLOADS: readonly string[] = [
  `https://${REDIRECT_EVIL_HOST}/`,
  `//${REDIRECT_EVIL_HOST}/`,
  `/\\${REDIRECT_EVIL_HOST}/`,
  `https:/${REDIRECT_EVIL_HOST}`,
  `%2f%2f${REDIRECT_EVIL_HOST}`,
  `https://legit.test@${REDIRECT_EVIL_HOST}/`, // @-userinfo: real host is after the @
  `/%2f@${REDIRECT_EVIL_HOST}/`, // encoded-slash + @, defeats servers that decode %2f
  `／／${REDIRECT_EVIL_HOST}/`, // fullwidth slashes some parsers normalize to //
  `https://${REDIRECT_EVIL_HOST}%00.legit.test/`, // null-byte truncation
]

// Params whose name suggests the server may FETCH the URL (SSRF) rather than just
// 30x-redirect to it. Used only to classify a candidate for out-of-band review —
// never to fire a probe at an internal host.
const SSRF_PARAM_RE = /^(url|uri|dest|destination|target|link|src|source|image|img|fetch|load|proxy|feed|host|domain|site|data|reference|callback|webhook|remote)$/i

export function isSsrfParam(name: string): boolean {
  return SSRF_PARAM_RE.test(name)
}

// Would a browser following `location` (relative to the request URL) end up on the
// attacker's host? Resolves via WHATWG URL so protocol-relative / backslash forms
// are handled exactly as a browser would, and an encoded slash that the server
// echoed verbatim (staying same-origin) is correctly NOT flagged.
export function redirectsToAttacker(location: string, requestUrl: string, evilHost = REDIRECT_EVIL_HOST): boolean {
  if (!location) return false
  try {
    const resolved = new URL(location, requestUrl)
    const host = resolved.hostname.toLowerCase()
    return host === evilHost || host.endsWith(`.${evilHost}`)
  } catch {
    return false
  }
}
