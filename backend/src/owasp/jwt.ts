import { createHmac, timingSafeEqual } from 'node:crypto'

// JWT analysis + offline HMAC-secret crack. Entirely LOCAL — zero network — so it
// is passive, silent, and self-verifying: a cracked secret is proof (it forges a
// valid signature), not a guess. Tokens come from what the tool already holds
// (owaspConfig.authHeader, JS-mined secrets, captured requests), so this squeezes
// signal out of data already on hand.

export type JwtSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface JwtFinding {
  name: string
  severity: JwtSeverity
  evidence: string
  source: string
}

// A small, curated set of secrets that show up constantly in tutorials, framework
// defaults, and copy-pasted examples. Bundled in-repo (auditable, offline) rather
// than fetched. The operator can extend it via owaspConfig.jwtSecrets.
export const BUILTIN_JWT_SECRETS: readonly string[] = [
  'secret', 'secretkey', 'secret_key', 'password', 'changeme', 'change-me', 'admin', 'test',
  'jwt', 'jwtsecret', 'jwt_secret', 'token', 'mysecret', 'supersecret', 'super-secret',
  '123456', '12345678', 'qwerty', 'root', 'default', 'example', 'private', 'key', 'signature',
  'your-256-bit-secret', 'your_jwt_secret', 'yoursecret', 'secretpassword', 'p@ssw0rd',
  'my-secret-key', 'mysecretkey', 'HS256', 'jwtkey', 'apikey', 'api_key', 'sekret',
  'devsecret', 'dev', 'staging', 'production', 'prod', 's3cr3t', 'secret123', 'letmein',
]

// Extract JWT-shaped strings from an arbitrary blob (header.payload.signature,
// each base64url). Matches the tighter three-segment form so random dotted tokens
// don't slip in; the analyze step still validates it decodes.
const JWT_RE = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}/g

export function findJwts(text: string): string[] {
  if (!text) return []
  return [...new Set(text.match(JWT_RE) ?? [])]
}

function b64urlToBuf(seg: string): Buffer {
  const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4))
  return Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64')
}

interface DecodedJwt {
  header: Record<string, any>
  payload: Record<string, any>
  signingInput: string
  signature: string
}

export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const header = JSON.parse(b64urlToBuf(parts[0]).toString('utf8'))
    const payload = JSON.parse(b64urlToBuf(parts[1]).toString('utf8'))
    if (typeof header !== 'object' || header == null) return null
    return { header, payload: typeof payload === 'object' && payload ? payload : {}, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] }
  } catch {
    return null
  }
}

const HMAC_ALG: Record<string, string> = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }

// Try each candidate secret against an HMAC-signed token. Returns the secret on a
// match (the token's own signature is the oracle — recompute and compare), else
// null. Constant-time compare avoids leaking timing, though it's moot offline.
export function crackHmacSecret(token: string, secrets: Iterable<string>): string | null {
  const decoded = decodeJwt(token)
  if (!decoded) return null
  const alg = String(decoded.header.alg ?? '').toUpperCase()
  const nodeAlg = HMAC_ALG[alg]
  if (!nodeAlg) return null // only HMAC tokens are crackable this way
  const want = b64urlToBuf(decoded.signature)
  if (want.length === 0) return null
  for (const secret of secrets) {
    const got = createHmac(nodeAlg, secret).update(decoded.signingInput).digest()
    if (got.length === want.length && timingSafeEqual(got, want)) return secret
  }
  return null
}

// Analyze one token: structural/claim weaknesses + an HMAC crack attempt. Returns
// [] for anything that isn't a decodable JWT. `now` is injectable for tests.
export function analyzeJwtToken(
  token: string,
  source: string,
  extraSecrets: readonly string[] = [],
  now: number = Date.now(),
): JwtFinding[] {
  const decoded = decodeJwt(token)
  if (!decoded) return []
  const out: JwtFinding[] = []
  const alg = String(decoded.header.alg ?? '').toUpperCase()
  const claims = decoded.payload

  if (alg === 'NONE' || alg === '') {
    out.push({ name: 'JWT accepts alg:none (unsigned)', severity: 'critical', evidence: `header alg=${decoded.header.alg ?? '(empty)'} — the signature is not verified; tokens can be forged`, source })
  }
  if (decoded.header.jku || decoded.header.x5u) {
    out.push({ name: 'JWT header references an external key URL (jku/x5u)', severity: 'high', evidence: `jku/x5u=${decoded.header.jku ?? decoded.header.x5u} — key-injection / SSRF if the URL is attacker-influenced`, source })
  }
  if (typeof decoded.header.kid === 'string' && /[\/'";`|]|\.\./.test(decoded.header.kid)) {
    out.push({ name: 'JWT kid may be injectable', severity: 'medium', evidence: `kid=${decoded.header.kid} contains path/quote characters — test for path-traversal / SQLi in key lookup`, source })
  }
  if (claims.exp == null) {
    out.push({ name: 'JWT has no expiry (exp)', severity: 'low', evidence: 'token never expires — a leaked token is valid forever', source })
  } else if (typeof claims.exp === 'number') {
    const iat = typeof claims.iat === 'number' ? claims.iat : now / 1000
    if (claims.exp - iat > 365 * 24 * 3600) {
      out.push({ name: 'JWT lifetime exceeds one year', severity: 'low', evidence: `exp is ${Math.round((claims.exp - iat) / 86400)} days after iat — excessive token lifetime`, source })
    }
  }

  // The headline: crack the HMAC secret offline. A hit is self-verifying proof.
  if (HMAC_ALG[alg]) {
    const secret = crackHmacSecret(token, [...BUILTIN_JWT_SECRETS, ...extraSecrets])
    if (secret) {
      out.push({ name: 'JWT HMAC secret cracked', severity: 'critical', evidence: `${alg} signing secret is "${secret}" — tokens (and any claims, e.g. role/admin) can be forged at will`, source })
    }
  }

  return out
}
