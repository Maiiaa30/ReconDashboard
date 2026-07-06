import type { FindingType } from '../findings/store'
import type { JobType } from '../jobs/queue'

// "Recon skills" = packaged methodologies. Each skill applies to a target under
// certain conditions (tech fingerprint / open ports / always) and lists the
// steps of that methodology. A step is considered covered when the matching job
// has run and/or produced a finding — so coverage is derived from data we
// already store (no new schema). Steps map to tools/scans the app already has.

export interface StepDetect {
  // A completed/pending job of any of these types (scoped to the domain).
  jobTypes?: JobType[]
  // A tool_scan job whose params.tool === this.
  jobTool?: string
  // A finding of this type exists.
  findingType?: FindingType
  // A 'tool' finding whose data.tool === this.
  findingTool?: string
  // An 'owasp' finding whose data.category starts with this (e.g. 'A03').
  owaspCategory?: string
}

export interface SkillStep {
  key: string
  label: string
  why: string
  detect: StepDetect
  // Human hint for where to run it (a one-click runner comes in a later slice).
  run: string
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
      { key: 'subs', label: 'Subdomain discovery', why: 'map the attack surface', run: 'Domains → Discover', detect: { jobTypes: ['subdomain_discovery'], findingType: 'new_subdomain' } },
      { key: 'exposure', label: 'Exposure / CVE sweep', why: 'known-vuln + open services per IP', run: 'Domains → Exposure', detect: { jobTypes: ['exposure_scan'], findingType: 'exposure' } },
      { key: 'osint', label: 'OSINT', why: 'DNS / WHOIS / CT / archived URLs', run: 'Domains → OSINT', detect: { jobTypes: ['osint_gather'], findingType: 'osint' } },
      { key: 'screens', label: 'Screenshots', why: 'eyeball live hosts', run: 'Screenshots', detect: { jobTypes: ['screenshot'] } },
      { key: 'content', label: 'Content discovery', why: 'find hidden paths / params', run: 'Tools → katana or Fuzzing', detect: { jobTool: 'katana', jobTypes: ['ffuf_scan'], findingType: 'ffuf' } },
      { key: 'owasp', label: 'OWASP active checks', why: 'headers, exposed files, XSS, redirect, CORS', run: 'OWASP → Run all applicable', detect: { jobTypes: ['owasp_active'], findingType: 'owasp' } },
      { key: 'tls', label: 'TLS audit', why: 'weak protocols / ciphers', run: 'Tools → sslscan', detect: { jobTool: 'sslscan', findingTool: 'sslscan' } },
      { key: 'methods', label: 'HTTP methods', why: 'writable verbs (PUT/DELETE/PATCH)', run: 'Tools → HTTP methods', detect: { jobTool: 'methods', findingTool: 'methods' } },
    ],
  },
  {
    id: 'wordpress',
    name: 'WordPress',
    description: 'WordPress-specific enumeration + common weaknesses.',
    appliesWhen: { tech: ['wordpress'] },
    steps: [
      { key: 'wpenum', label: 'WordPress enum', why: 'users, plugins, version, xmlrpc', run: 'Tools → WordPress enum', detect: { jobTool: 'wpenum', findingTool: 'wpenum' } },
      { key: 'wpcve', label: 'Core / plugin CVEs', why: 'known WordPress + plugin vulns', run: 'Scans → nuclei (tags: wordpress,cve)', detect: { jobTypes: ['nuclei_scan'], findingType: 'nuclei' } },
      { key: 'wpxss', label: 'Reflected XSS on params', why: 'WP params commonly reflect input', run: 'Tools → dalfox or OWASP', detect: { jobTool: 'dalfox', findingTool: 'dalfox', owaspCategory: 'A03' } },
      { key: 'wpadmin', label: 'Reach /wp-admin (403 bypass)', why: 'admin is often behind 401/403', run: 'Tools → 403 bypass', detect: { jobTool: 'bypass403', findingTool: 'bypass403' } },
    ],
  },
  {
    id: 'injection',
    name: 'Injection testing',
    description: 'Active injection probes once params/endpoints are known.',
    appliesWhen: { always: true },
    steps: [
      { key: 'sqli', label: 'SQL injection', why: 'test discovered params for SQLi', run: 'Tools → sqlmap', detect: { jobTool: 'sqlmap', findingTool: 'sqlmap' } },
      { key: 'xss', label: 'Reflected XSS', why: 'reflected XSS on params', run: 'Tools → dalfox', detect: { jobTool: 'dalfox', findingTool: 'dalfox', owaspCategory: 'A03' } },
      { key: 'accessctl', label: 'Open redirect / CORS / access-control', why: 'covered by the OWASP active engine', run: 'OWASP', detect: { jobTypes: ['owasp_active'], owaspCategory: 'A01' } },
    ],
  },
  {
    id: 'infra',
    name: 'Infrastructure exposure',
    description: 'Non-web services + exposed datastores.',
    appliesWhen: { ports: [22, 3306, 5432, 6379, 9200, 27017, 5984, 2375, 3389, 11211] },
    steps: [
      { key: 'ports', label: 'Port scan', why: 'enumerate open services', run: 'Tools → naabu or Scans → nmap', detect: { jobTool: 'naabu', jobTypes: ['nmap_scan'] } },
      { key: 'versions', label: 'Service versions', why: 'version → known CVEs', run: 'Scans → nmap', detect: { jobTypes: ['nmap_scan'], findingType: 'nmap' } },
      { key: 'datastores', label: 'Exposed datastores', why: 'no-auth DBs / DB admin panels', run: 'Tools → Exposed datastores', detect: { jobTool: 'datastores', findingTool: 'datastores' } },
    ],
  },
  {
    id: 'origin',
    name: 'WAF / origin',
    description: 'Find the real origin behind a CDN/WAF.',
    appliesWhen: { tech: ['cloudflare', 'cloudfront'] },
    steps: [
      { key: 'origin', label: 'Origin discovery', why: 'hit the origin IP directly, bypassing the WAF', run: 'WAF / Origin → Find origin', detect: { jobTypes: ['origin_scan'], findingType: 'origin' } },
    ],
  },
]
