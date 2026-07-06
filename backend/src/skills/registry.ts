import type { FindingType } from '../findings/store'
import type { JobType } from '../jobs/queue'

// "Recon skills" = packaged methodologies. Each skill applies to a target under
// certain conditions (tech fingerprint / open ports / always) and lists the
// steps of that methodology. A step is covered when the matching job has run
// and/or produced a finding — coverage is derived from data we already store.
// Each step also carries a runnable `action` (mapped to an existing endpoint)
// and a detector.

export interface StepDetect {
  jobTypes?: JobType[]
  jobTool?: string
  findingType?: FindingType
  findingTool?: string
  owaspCategory?: string
}

// Which existing endpoint a step's one-click run maps to. Passive kinds
// (discover/exposure/osint/screenshots/origin) run without confirmation; the
// rest are active and go through the gated tool/scan routes.
export type ActionKind =
  | 'discover'
  | 'exposure'
  | 'osint'
  | 'screenshots'
  | 'origin'
  | 'owasp'
  | 'nmap'
  | 'nuclei'
  | 'ffuf'
  | 'tool'
export interface StepAction {
  kind: ActionKind
  tool?: string // for kind:'tool'
  tags?: string // for kind:'nuclei'
}

export interface SkillStep {
  key: string
  label: string
  why: string
  detect: StepDetect
  action: StepAction
}

export interface Skill {
  id: string
  name: string
  description: string
  appliesWhen: { always?: boolean; tech?: string[]; ports?: number[] }
  steps: SkillStep[]
}

export const SKILLS: Skill[] = [
  {
    id: 'web-baseline',
    name: 'Web app baseline',
    description: 'The passive-first sweep every web target should get.',
    appliesWhen: { always: true },
    steps: [
      { key: 'subs', label: 'Subdomain discovery', why: 'map the attack surface', action: { kind: 'discover' }, detect: { jobTypes: ['subdomain_discovery'], findingType: 'new_subdomain' } },
      { key: 'exposure', label: 'Exposure / CVE sweep', why: 'known-vuln + open services per IP', action: { kind: 'exposure' }, detect: { jobTypes: ['exposure_scan'], findingType: 'exposure' } },
      { key: 'osint', label: 'OSINT', why: 'DNS / WHOIS / CT / archived URLs', action: { kind: 'osint' }, detect: { jobTypes: ['osint_gather'], findingType: 'osint' } },
      { key: 'screens', label: 'Screenshots', why: 'eyeball live hosts', action: { kind: 'screenshots' }, detect: { jobTypes: ['screenshot'] } },
      { key: 'content', label: 'Content discovery', why: 'find hidden paths / params', action: { kind: 'tool', tool: 'katana' }, detect: { jobTool: 'katana', jobTypes: ['ffuf_scan'], findingType: 'ffuf' } },
      { key: 'owasp', label: 'OWASP active checks', why: 'headers, exposed files, XSS, redirect, CORS', action: { kind: 'owasp' }, detect: { jobTypes: ['owasp_active'], findingType: 'owasp' } },
      { key: 'tls', label: 'TLS audit', why: 'weak protocols / ciphers', action: { kind: 'tool', tool: 'sslscan' }, detect: { jobTool: 'sslscan', findingTool: 'sslscan' } },
      { key: 'methods', label: 'HTTP methods', why: 'writable verbs (PUT/DELETE/PATCH)', action: { kind: 'tool', tool: 'methods' }, detect: { jobTool: 'methods', findingTool: 'methods' } },
    ],
  },
  {
    id: 'wordpress',
    name: 'WordPress',
    description: 'WordPress-specific enumeration + common weaknesses.',
    appliesWhen: { tech: ['wordpress'] },
    steps: [
      { key: 'wpenum', label: 'WordPress enum', why: 'users, plugins, version, xmlrpc', action: { kind: 'tool', tool: 'wpenum' }, detect: { jobTool: 'wpenum', findingTool: 'wpenum' } },
      { key: 'wpcve', label: 'Core / plugin CVEs', why: 'known WordPress + plugin vulns', action: { kind: 'nuclei', tags: 'wordpress,cve' }, detect: { jobTypes: ['nuclei_scan'], findingType: 'nuclei' } },
      { key: 'wpxss', label: 'Reflected XSS on params', why: 'WP params commonly reflect input', action: { kind: 'tool', tool: 'dalfox' }, detect: { jobTool: 'dalfox', findingTool: 'dalfox', owaspCategory: 'A03' } },
      { key: 'wpadmin', label: 'Reach /wp-admin (403 bypass)', why: 'admin is often behind 401/403', action: { kind: 'tool', tool: 'bypass403' }, detect: { jobTool: 'bypass403', findingTool: 'bypass403' } },
    ],
  },
  {
    id: 'injection',
    name: 'Injection testing',
    description: 'Active injection probes once params/endpoints are known.',
    appliesWhen: { always: true },
    steps: [
      { key: 'sqli', label: 'SQL injection', why: 'test discovered params for SQLi', action: { kind: 'tool', tool: 'sqlmap' }, detect: { jobTool: 'sqlmap', findingTool: 'sqlmap' } },
      { key: 'xss', label: 'Reflected XSS', why: 'reflected XSS on params', action: { kind: 'tool', tool: 'dalfox' }, detect: { jobTool: 'dalfox', findingTool: 'dalfox', owaspCategory: 'A03' } },
      { key: 'accessctl', label: 'Open redirect / CORS / access-control', why: 'covered by the OWASP active engine', action: { kind: 'owasp' }, detect: { jobTypes: ['owasp_active'], owaspCategory: 'A01' } },
    ],
  },
  {
    id: 'infra',
    name: 'Infrastructure exposure',
    description: 'Non-web services + exposed datastores.',
    appliesWhen: { ports: [22, 3306, 5432, 6379, 9200, 27017, 5984, 2375, 3389, 11211] },
    steps: [
      { key: 'ports', label: 'Port scan', why: 'enumerate open services', action: { kind: 'tool', tool: 'naabu' }, detect: { jobTool: 'naabu', jobTypes: ['nmap_scan'] } },
      { key: 'versions', label: 'Service versions', why: 'version → known CVEs', action: { kind: 'nmap' }, detect: { jobTypes: ['nmap_scan'], findingType: 'nmap' } },
      { key: 'datastores', label: 'Exposed datastores', why: 'no-auth DBs / DB admin panels', action: { kind: 'tool', tool: 'datastores' }, detect: { jobTool: 'datastores', findingTool: 'datastores' } },
    ],
  },
  {
    id: 'origin',
    name: 'WAF / origin',
    description: 'Find the real origin behind a CDN/WAF.',
    appliesWhen: { tech: ['cloudflare', 'cloudfront'] },
    steps: [
      { key: 'origin', label: 'Origin discovery', why: 'hit the origin IP directly, bypassing the WAF', action: { kind: 'origin' }, detect: { jobTypes: ['origin_scan'], findingType: 'origin' } },
    ],
  },
]
