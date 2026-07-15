// Payload encoders / decoders — pure string transforms, chainable. Used to build
// evasion payloads (double-url, unicode, mixed) before they go into the Repeater
// or Intruder. Encoding is baked into the payload STRING up front so the fuzzer
// stays dumb and the abort path clean. Every function is total (never throws): a
// malformed decode input returns the string unchanged rather than aborting a run.

export type Transform = (s: string) => string

const htmlEntityEncode = (s: string): string =>
  s.replace(/[&<>"'`/]/g, (c) => `&#${c.charCodeAt(0)};`)

const htmlEntityDecode = (s: string): string =>
  s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => safeFromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => safeFromCodePoint(parseInt(d, 10)))
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")

function safeFromCodePoint(n: number): string {
  try {
    return Number.isFinite(n) && n >= 0 && n <= 0x10ffff ? String.fromCodePoint(n) : ''
  } catch {
    return ''
  }
}

const tryDecode = (fn: (s: string) => string) => (s: string): string => {
  try {
    return fn(s)
  } catch {
    return s
  }
}

// The registry — names are the stable API used by the /encode route and the UI.
export const TRANSFORMS: Record<string, Transform> = {
  base64: (s) => Buffer.from(s, 'utf8').toString('base64'),
  'base64-decode': tryDecode((s) => Buffer.from(s, 'base64').toString('utf8')),
  base64url: (s) => Buffer.from(s, 'utf8').toString('base64url'),
  'base64url-decode': tryDecode((s) => Buffer.from(s, 'base64url').toString('utf8')),
  // JS-string evasion: wrap the payload as String.fromCharCode(...) (encode-only).
  'from-char-code': (s) => `String.fromCharCode(${[...s].map((c) => c.charCodeAt(0)).join(',')})`,
  url: (s) => encodeURIComponent(s),
  'url-decode': tryDecode((s) => decodeURIComponent(s)),
  'double-url': (s) => encodeURIComponent(encodeURIComponent(s)),
  'double-url-decode': tryDecode((s) => decodeURIComponent(decodeURIComponent(s))),
  hex: (s) => Buffer.from(s, 'utf8').toString('hex'),
  'hex-decode': tryDecode((s) => Buffer.from(s, 'hex').toString('utf8')),
  unicode: (s) => [...s].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
  'unicode-decode': (s) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => safeFromCodePoint(parseInt(h, 16))),
  'html-entity': htmlEntityEncode,
  'html-entity-decode': htmlEntityDecode,
}

export const TRANSFORM_NAMES = Object.keys(TRANSFORMS)

const MAX_CHAIN = 8

// Apply a sequence of named transforms left-to-right. Unknown names are rejected
// (so a typo can't silently no-op); the chain is length-capped.
export function applyChain(input: string, chain: string[]): string {
  if (chain.length > MAX_CHAIN) throw new Error(`encoder chain too long (max ${MAX_CHAIN})`)
  let out = input
  for (const name of chain) {
    const fn = TRANSFORMS[name]
    if (!fn) throw new Error(`unknown transform: ${name}`)
    out = fn(out)
  }
  return out
}
