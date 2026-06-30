// OWASP Top 10 (2021) test catalog.
//
// The actual test engine is nuclei (installed in the image), driven by template
// tags — production-grade and safe, rather than a hand-rolled payload injector.
// Each category maps to nuclei tags and a `requires` set of app-profile flags:
// a category is APPLICABLE if `requires` is empty OR the domain's profile has at
// least one of those flags true. This implements "don't test IDOR if there's no
// login", etc. `payloads` is a small manual-testing reference shown in the UI.

export interface ProfileFlags {
  hasLogin?: boolean
  hasParams?: boolean
  hasUpload?: boolean
  hasApi?: boolean
  hasRedirects?: boolean
}

export const PROFILE_KEYS: { key: keyof ProfileFlags; label: string; hint: string }[] = [
  { key: 'hasLogin', label: 'Has login / auth', hint: 'Authentication, accounts, sessions' },
  { key: 'hasParams', label: 'Takes user input', hint: 'Search, query params, forms' },
  { key: 'hasUpload', label: 'File upload', hint: 'Avatar, document, import' },
  { key: 'hasApi', label: 'Has an API', hint: 'JSON/REST/GraphQL endpoints' },
  { key: 'hasRedirects', label: 'Redirects by param', hint: '?next=, ?url=, ?return=' },
]

export interface OwaspCategory {
  id: string
  name: string
  description: string
  tags: string[] // nuclei -tags
  requires: (keyof ProfileFlags)[] // applicable if empty or any is true
  payloads: string[] // manual-testing reference
}

export const OWASP_CATALOG: OwaspCategory[] = [
  {
    id: 'A01',
    name: 'A01 Broken Access Control',
    description: 'IDOR, missing authz, forced browsing, privilege escalation.',
    tags: ['idor', 'auth-bypass', 'access', 'unauth'],
    requires: ['hasLogin', 'hasApi'],
    payloads: ['/admin', '/api/users/1 → /api/users/2', '/../', '?id=1 → ?id=2', 'X-Original-URL: /admin'],
  },
  {
    id: 'A02',
    name: 'A02 Cryptographic Failures',
    description: 'Weak TLS, sensitive data exposure, secrets in responses.',
    tags: ['ssl', 'tls', 'exposure', 'disclosure'],
    requires: [],
    payloads: ['/.env', '/.git/config', '/config.json', 'Look for http:// on auth pages'],
  },
  {
    id: 'A03',
    name: 'A03 Injection',
    description: 'SQLi, XSS, SSTI, command/template injection via inputs.',
    tags: ['sqli', 'xss', 'injection', 'ssti', 'cmdi'],
    requires: ['hasParams', 'hasApi'],
    payloads: ["' OR '1'='1", '" onmouseover=alert(1) x="', '{{7*7}}', '${7*7}', '`id`', ';cat /etc/passwd'],
  },
  {
    id: 'A04',
    name: 'A04 Insecure Design',
    description: 'Logic flaws (limited automated coverage).',
    tags: ['misconfig', 'logic'],
    requires: [],
    payloads: ['Rate-limit bypass', 'Race conditions on checkout/coupon', 'Mass assignment'],
  },
  {
    id: 'A05',
    name: 'A05 Security Misconfiguration',
    description: 'Default creds, debug endpoints, verbose errors, open dirs.',
    tags: ['misconfig', 'default-login', 'exposure', 'debug'],
    requires: [],
    payloads: ['admin:admin', '/server-status', '/actuator', '/phpinfo.php', 'TRACE method'],
  },
  {
    id: 'A06',
    name: 'A06 Vulnerable & Outdated Components',
    description: 'Known CVEs in detected technologies/versions.',
    tags: ['cve', 'tech', 'wordpress', 'wp-plugin'],
    requires: [],
    payloads: ['Fingerprint versions, match to CVE feeds', 'Check Exposure tab CVEs'],
  },
  {
    id: 'A07',
    name: 'A07 Identification & Auth Failures',
    description: 'Default/weak credentials, missing brute-force protection.',
    tags: ['default-login', 'weak-credentials', 'auth'],
    requires: ['hasLogin'],
    payloads: ['admin:admin', 'admin:password', 'No lockout after N tries', 'Predictable session tokens'],
  },
  {
    id: 'A08',
    name: 'A08 Software & Data Integrity',
    description: 'Insecure deserialization, unsigned updates, CI/CD exposure.',
    tags: ['deserialization', 'exposure'],
    requires: ['hasUpload', 'hasApi'],
    payloads: ['/.github/workflows/', 'java serialized objects', 'unsafe pickle/yaml'],
  },
  {
    id: 'A10',
    name: 'A10 Server-Side Request Forgery',
    description: 'SSRF via URL/redirect/import params.',
    tags: ['ssrf', 'redirect'],
    requires: ['hasParams', 'hasApi', 'hasRedirects'],
    payloads: ['?url=http://169.254.169.254/latest/meta-data/', '?next=//evil.com', 'gopher://', 'file:///etc/passwd'],
  },
]

export function applicableCategories(profile: ProfileFlags): OwaspCategory[] {
  return OWASP_CATALOG.filter(
    (c) => c.requires.length === 0 || c.requires.some((k) => profile[k] === true),
  )
}

export function tagsForCategories(ids: string[]): string[] {
  const set = new Set<string>()
  for (const c of OWASP_CATALOG) {
    if (ids.includes(c.id)) for (const t of c.tags) set.add(t)
  }
  return [...set]
}
