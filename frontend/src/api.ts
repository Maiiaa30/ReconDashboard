// Thin typed wrapper around the backend REST API. Cookies (the session) are
// sent automatically (same origin via the Vite proxy in dev, same origin in prod).

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    // Only send a JSON content-type when there's actually a body, so GET/DELETE
    // don't trigger needless CORS preflights or strict-server rejections.
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
  })
  let body: unknown = null
  const text = await res.text()
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }
  if (!res.ok) {
    const message =
      body && typeof body === 'object' && 'error' in body
        ? String((body as { error: unknown }).error)
        : `HTTP ${res.status}`
    throw new ApiError(res.status, message)
  }
  return body as T
}

const get = <T>(p: string) => request<T>(p)
const post = <T>(p: string, body?: unknown) =>
  request<T>(p, { method: 'POST', body: body == null ? undefined : JSON.stringify(body) })
const patch = <T>(p: string, body: unknown) => request<T>(p, { method: 'PATCH', body: JSON.stringify(body) })
const put = <T>(p: string, body: unknown) => request<T>(p, { method: 'PUT', body: JSON.stringify(body) })
const del = <T>(p: string) => request<T>(p, { method: 'DELETE' })

// --- Types -------------------------------------------------------------------

export type DomainMode = 'passive_only' | 'active_authorized'

export interface DomainProfile {
  hasLogin?: boolean
  hasParams?: boolean
  hasUpload?: boolean
  hasApi?: boolean
  hasRedirects?: boolean
}

export interface OwaspConfig {
  xssParams?: string[]
  xssPayloads?: string[]
  redirectParams?: string[]
  sensitivePaths?: string[]
  authHeader?: string
}

export interface ScopeConfig {
  allow?: string[]
  deny?: string[]
}

export interface Domain {
  id: number
  host: string
  label: string | null
  mode: DomainMode
  profile?: DomainProfile
  owaspConfig?: OwaspConfig
  scopeConfig?: ScopeConfig
  authorizedFrom?: string | null
  authorizedUntil?: string | null
  monitorIntervalHours?: number
  createdAt: string
  updatedAt: string
}

export interface AuditEntry {
  id: number
  ts: string
  actor: string
  action: string
  domainId: number | null
  target: string | null
  mode: string | null
  jobId: number | null
  detail: string | null
}

export interface Subdomain {
  id: number
  domainId: number
  host: string
  source: string | null
  isNew: boolean
  ipAddress: string | null
  httpStatus: number | null
  title: string | null
  server: string | null
  scheme: string | null
  probedAt: string | null
  screenshotPath: string | null
  screenshotAt: string | null
  firstSeen: string
  lastSeen: string
}

export interface ScreenshotEntry {
  host: string
  status: number | null
  title: string | null
  scheme: string | null
  capturedAt: string | null
}

export interface OwaspCategory {
  id: string
  name: string
  description: string
  tags: string[]
  requires: string[]
  payloads: string[]
}

export interface OwaspProfileKey {
  key: keyof DomainProfile
  label: string
  hint: string
}

export type JobStatus = 'queued' | 'running' | 'done' | 'error' | 'cancelled' | 'dead'

export interface Job {
  id: number
  type: string
  status: JobStatus
  params: unknown
  result: unknown
  error: string | null
  progress: string | null
  createdAt: string
  startedAt: string | null
  finishedAt: string | null
  updatedAt: string
}

// Replay (Repeater): the full response from a server-side send.
export interface ReplayResponse {
  status: number
  statusText: string
  headers: [string, string][]
  body: string
  bodyBytes: number
  truncated: boolean
  timeMs: number
  finalUrl: string
  redirects: { status: number; location: string }[]
}

export interface IntruderAttempt {
  payload: string
  status: number
  length: number
  timeMs: number
  error?: string
}
export interface IntruderResult {
  total: number
  sent: number
  aborted: boolean
  attempts: IntruderAttempt[]
  interesting: IntruderAttempt[]
  baseline: { status: number; length: number } | null
}

// A request captured by the browser extension, awaiting replay/review.
export interface Capture {
  id: number
  domainId: number | null
  method: string
  url: string
  host: string
  headers: [string, string][]
  body: string | null
  source: string
  createdAt: string
}

// Repeater history entry (list form — no response body).
export interface ReplayHistoryItem {
  id: number
  method: string
  url: string
  reqHeaders: [string, string][]
  reqBody: string | null
  status: number | null
  statusText: string | null
  timeMs: number | null
  respBytes: number | null
  createdAt: string
}
// Full entry (with the stored response) — fetched when a history row is opened.
export interface ReplayHistoryDetail extends ReplayHistoryItem {
  respHeaders: [string, string][]
  respBody: string | null
}

export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'resolved' | 'ignored'

export interface Finding {
  id: number
  domainId: number | null
  type: string
  data: any
  score: number | null
  tags: string[]
  status: FindingStatus
  note: string | null
  createdAt: string
  lastSeenAt: string | null
}

export interface Note {
  id: number
  domainId: number | null
  title: string | null
  body: string | null
  createdAt: string
  updatedAt: string
}

export interface DrawingMeta {
  id: number
  domainId: number | null
  name: string | null
  createdAt: string
  updatedAt: string
}

export interface Drawing extends DrawingMeta {
  data: any
}

export interface Wordlist {
  path: string
  name: string
  sizeKb: number
  category?: 'payload' | 'content'
}

export interface AttackPath {
  ip: string
  cdn: string | null
  asn: string | null
  asnName: string | null
  hosts: string[]
  ports: number[]
  cveCount: number
  worstCvss: number | null
  kev: boolean
  score: number
}

export type AdviceActionKind = 'nmap' | 'naabu' | 'nuclei' | 'ffuf' | 'dalfox' | 'sslscan' | 'katana' | 'owasp'
export interface AdviceAction {
  kind: AdviceActionKind
  target: string
}
export interface IntelAdvice {
  summary: string
  priorities: { target: string; risk: 'high' | 'medium' | 'low'; why: string; tests: string[]; action?: AdviceAction }[]
  injection: { target: string; param?: string; type: string; why: string; action?: AdviceAction }[]
  quickWins: { item: string; why: string }[]
  deeperDigs: { item: string; why: string }[]
}

export type StepStatus = 'found' | 'done' | 'running' | 'todo' | 'skipped'
export interface StepAction {
  kind: 'discover' | 'exposure' | 'osint' | 'screenshots' | 'origin' | 'owasp' | 'nmap' | 'nuclei' | 'ffuf' | 'tool'
  tool?: string
  tags?: string
}
export interface MethodologyStep {
  key: string
  label: string
  why: string
  action: StepAction
  status: StepStatus
  manual: boolean
}
export interface MethodologySkill {
  id: string
  name: string
  description: string
  applicable: boolean
  reason: string
  coverage: number
  steps: MethodologyStep[]
}
export interface Methodology {
  tech: string[]
  ports: number[]
  skills: MethodologySkill[]
}

export interface MetaStatus {
  scorer: string
  aiProvider: string
  scheduler: { enabled: boolean; intervalMinutes: number }
  discordConfigured: boolean
  llm?: { enabled: boolean; model: string | null }
  leaks?: { enabled: boolean; provider: string | null }
  tools: {
    subfinder: boolean
    nmap: boolean
    nuclei: boolean
    ffuf: boolean
    chromium: boolean
    dig: boolean
    katana?: boolean
    naabu?: boolean
    dalfox?: boolean
    sslscan?: boolean
    sqlmap?: boolean
    wpenum?: boolean
    bypass403?: boolean
    methods?: boolean
    datastores?: boolean
  }
  wordlists: Wordlist[]
}

export interface LeaksResponse {
  enabled: boolean
  provider: string | null
  autoDaily: boolean
  pending: boolean
  lastCheckedAt: string | null
  findings: Finding[]
}

export interface FreeEmailResult {
  email: string
  found: number
  fields: string[]
  sources: { name: string; date: string | null }[]
  provider: string
}

export interface SnapshotMeta {
  findings: number
  high: number
  medium: number
  low: number
  cves: number
}

export interface ReportSnapshot {
  id: number
  host: string
  label: string | null
  meta: SnapshotMeta | null
  createdAt: string
}

export interface Me {
  user: { username: string; totpEnabled: boolean; selectedDomainId?: number | null }
}

export interface WhoisResult {
  query: string
  kind: 'domain' | 'ip'
  server: string
  raw: string
}

export interface TcpResult {
  port: number
  open: boolean
  latencyMs: number | null
}

export interface PingResult {
  available: boolean
  alive: boolean
  transmitted: number | null
  received: number | null
  lossPct: number | null
  rttMs: { min: number; avg: number; max: number } | null
  error: string | null
}

export interface CheckHostResult {
  target: string
  resolvedIp: string | null
  dns: { a: string[]; aaaa: string[]; cname: string[]; ns: string[] } | { error: string }
  ping: PingResult
  tcp: TcpResult[]
  http: { scheme: string | null; status: number | null; title: string | null; server: string | null; url: string | null } | null
}

export interface DomainOverview {
  id: number
  host: string
  label: string | null
  mode: DomainMode
  createdAt: number | null
  subdomains: { total: number; new: number }
  findings: { total: number; maxScore: number | null }
  exposure: { ips: number; openPorts: number; cves: number }
  lastActivity: number | null
  monitorIntervalHours: number
}

export interface HomeFinding {
  id: number
  domainId: number | null
  type: string
  data: any
  score: number | null
  tags: string[]
}

export interface RecentChange {
  id: number
  domainId: number | null
  data: { ip?: string; host?: string; cveId?: string; cvss?: number | null; kev?: boolean }
  score: number | null
  createdAt: string
}

// --- API surface -------------------------------------------------------------

export const api = {
  // auth
  me: () => get<Me>('/auth/me'),
  setSelectedDomain: (domainId: number | null) =>
    post<{ ok: boolean; selectedDomainId: number | null }>('/auth/selected-domain', { domainId }),
  login: (username: string, password: string, token?: string) =>
    post<{ user: { username: string } }>('/auth/login', { username, password, ...(token ? { token } : {}) }),
  logout: () => post<{ ok: true }>('/auth/logout'),
  enroll: () => get<{ totpEnabled: boolean; otpauthUrl: string }>('/auth/enroll'),
  enableTotp: (token: string) => post<{ totpEnabled: boolean }>('/auth/totp/enable', { token }),
  disableTotp: (token: string) => post<{ totpEnabled: boolean }>('/auth/totp/disable', { token }),
  changePassword: (currentPassword: string, newPassword: string) =>
    post<{ ok: true }>('/auth/password', { currentPassword, newPassword }),
  changeUsername: (password: string, newUsername: string) =>
    post<{ ok: true; username: string }>('/auth/username', { password, newUsername }),

  // engagement home (cross-target overview + top open findings + recent changes)
  home: () => get<{ overview: DomainOverview[]; topFindings: HomeFinding[]; recentChanges: RecentChange[] }>('/home'),

  // meta
  meta: () => get<MetaStatus>('/meta/status'),

  // domains
  domains: () => get<{ domains: Domain[] }>('/domains'),
  domainsOverview: () => get<{ overview: DomainOverview[] }>('/domains/overview'),
  createDomain: (host: string, mode: DomainMode, label?: string) =>
    post<{ domain: Domain }>('/domains', { host, mode, label }),
  setDomainMode: (id: number, mode: DomainMode) => patch<{ domain: Domain }>(`/domains/${id}`, { mode }),
  updateDomain: (
    id: number,
    patchBody: {
      mode?: DomainMode
      label?: string | null
      profile?: DomainProfile
      monitorIntervalHours?: number
      owaspConfig?: OwaspConfig
      scopeConfig?: ScopeConfig
      authorizedFrom?: number | null
      authorizedUntil?: number | null
    },
  ) => patch<{ domain: Domain }>(`/domains/${id}`, patchBody),
  deleteDomain: (id: number) => del<{ ok: true }>(`/domains/${id}`),

  // OWASP testing
  owaspCatalog: () => get<{ catalog: OwaspCategory[]; profileKeys: OwaspProfileKey[] }>('/owasp/catalog'),
  runOwasp: (id: number, categoryIds?: string[], scheme?: string, confirm?: boolean) =>
    post<{ jobId: number; categories: string[]; tags: string[] }>(`/domains/${id}/owasp`, { categoryIds, scheme, confirm }),

  // attack-path correlation
  correlate: (id: number) => get<{ paths: AttackPath[] }>(`/domains/${id}/correlate`),

  // recon methodology / coverage
  methodology: (id: number) => get<Methodology>(`/domains/${id}/methodology`),
  setMethodologyStep: (id: number, skillId: string, stepKey: string, state: 'done' | 'skipped' | 'clear') =>
    patch<Methodology>(`/domains/${id}/methodology/step`, { skillId, stepKey, state }),

  // AI-drafted report narrative (optional; only when llm.enabled)
  generateNarrative: (id: number) => post<{ narrative: string; model: string; note: string }>(`/domains/${id}/report/narrative`),

  // AI intel advisor: structured, prioritized testing plan (optional; llm.enabled)
  adviseIntel: (id: number) => post<{ advice: IntelAdvice; model: string; note: string }>(`/domains/${id}/intel/advise`),

  // subdomains
  subdomains: (id: number) => get<{ subdomains: Subdomain[] }>(`/domains/${id}/subdomains`),
  discover: (id: number) => post<{ jobId: number }>(`/domains/${id}/discover`),
  acknowledgeNew: (id: number) => post<{ cleared: number }>(`/domains/${id}/subdomains/acknowledge`),

  // passive recon
  exposure: (id: number) => post<{ jobId: number }>(`/domains/${id}/exposure`),
  osint: (id: number) => post<{ jobId: number }>(`/domains/${id}/osint`),

  // origin discovery (WAF/CDN bypass)
  findOrigin: (id: number) => post<{ jobId: number }>(`/domains/${id}/origin`),

  // passive API-surface discovery (OpenAPI/Swagger + GraphQL)
  apiDiscovery: (id: number) => post<{ jobId: number }>(`/domains/${id}/api-discovery`),

  // domain breach/leak exposure (needs a configured provider; passive lookup)
  leaks: (id: number) => get<LeaksResponse>(`/domains/${id}/leaks`),
  checkLeaks: (id: number) => post<{ jobId: number }>(`/domains/${id}/leaks/check`),
  // free, keyless per-email breach-metadata check (no provider needed)
  checkEmailLeak: (id: number, email: string) =>
    post<{ result: FreeEmailResult }>(`/domains/${id}/leaks/email`, { email }),

  // ad-hoc lookup tools (not scoped to a tracked domain)
  whois: (query: string) => post<{ result: WhoisResult }>('/tools/whois', { query }),
  checkHost: (host: string, ports?: number[]) =>
    post<{ result: CheckHostResult }>('/tools/check-host', { host, ...(ports ? { ports } : {}) }),

  // screenshots
  captureScreenshots: (id: number) => post<{ jobId: number }>(`/domains/${id}/screenshots`),
  screenshots: (id: number) => get<{ screenshots: ScreenshotEntry[] }>(`/domains/${id}/screenshots`),
  screenshotUrl: (id: number, host: string) => `/api/domains/${id}/screenshot?host=${encodeURIComponent(host)}`,

  // extra active tools (katana/naabu/dalfox/sslscan/wpenum), gated like scans
  runTool: (id: number, opts: { tool: string; target?: string; scheme?: string; confirm?: boolean; path?: string }) =>
    post<{ jobId: number; tool: string; target: string }>(`/domains/${id}/tool`, opts),

  // active scans (gated server-side; passive domains require confirm:true)
  nmap: (id: number, opts: { target?: string; ports?: string; deep?: boolean; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/scan/nmap`, opts),
  // Attack-surface sweep: one nmap job per live host of the domain (deduped by IP).
  nmapSweep: (id: number, opts: { deep?: boolean; confirm?: boolean } = {}) =>
    post<{
      queued: number
      jobs: { host: string; jobId: number }[]
      skipped: { host: string; reason: string }[]
      capped: boolean
      considered: number
    }>(`/domains/${id}/scan/nmap-sweep`, opts),
  nuclei: (id: number, opts: { target?: string; severity?: string; tags?: string; scheme?: string; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/scan/nuclei`, opts),
  ffuf: (id: number, opts: { target?: string; path?: string; wordlist?: string; scheme?: string; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/scan/ffuf`, opts),

  // replay (Repeater): send one composed request server-side, gated to the domain's scope
  replaySend: (bodyReq: {
    domainId: number
    method: string
    url: string
    headers?: Record<string, string>
    body?: string
    followRedirects?: boolean
    confirm?: boolean
  }) => post<{ response: ReplayResponse }>('/replay/send', bodyReq),
  // repeater history
  replayHistory: (domainId: number, limit?: number) =>
    get<{ history: ReplayHistoryItem[] }>(`/replay/history?domainId=${domainId}${limit ? `&limit=${limit}` : ''}`),
  replayHistoryDetail: (id: number) => get<{ entry: ReplayHistoryDetail }>(`/replay/history/${id}`),
  clearReplayHistory: (domainId: number) => del<{ cleared: number }>(`/replay/history?domainId=${domainId}`),
  // intruder: iterate a payload set through a request template (gated LOUD job)
  intruder: (
    id: number,
    bodyReq: {
      template: { method: string; url: string; headers?: Record<string, string>; body?: string; followRedirects?: boolean }
      payload: { mode: 'list' | 'range' | 'wordlist'; list?: string; from?: number; to?: number; pad?: number; wordlist?: string }
      throttleMs?: number
      confirm?: boolean
    },
  ) => post<{ jobId: number; count: number }>(`/domains/${id}/intruder`, bodyReq),

  // captured traffic (from the browser extension)
  captures: (domainId?: number, limit?: number) => {
    const p = new URLSearchParams()
    if (domainId != null) p.set('domainId', String(domainId))
    if (limit) p.set('limit', String(limit))
    const qs = p.toString()
    return get<{ captures: Capture[] }>(`/capture${qs ? `?${qs}` : ''}`)
  },
  captureStatus: () => get<{ enabled: boolean; extensionSeenAt: number | null }>('/capture/status'),
  deleteCapture: (id: number) => del<{ deleted: number }>(`/capture/${id}`),
  clearCaptures: (domainId: number) => del<{ cleared: number }>(`/capture?domainId=${domainId}`),

  // jobs
  jobs: () => get<{ jobs: Job[] }>('/jobs'),
  job: (id: number) => get<{ job: Job }>(`/jobs/${id}`),
  cancelJob: (id: number) => post<{ job: Job }>(`/jobs/${id}/cancel`),

  // findings
  findings: (q: { domainId?: number; type?: string; limit?: number; since?: number } = {}) => {
    const params = new URLSearchParams()
    if (q.domainId != null) params.set('domainId', String(q.domainId))
    if (q.type) params.set('type', q.type)
    if (q.limit) params.set('limit', String(q.limit))
    if (q.since) params.set('since', String(q.since))
    const qs = params.toString()
    return get<{ findings: Finding[] }>(`/findings${qs ? `?${qs}` : ''}`)
  },
  updateFinding: (id: number, patchBody: { status?: FindingStatus; note?: string | null }) =>
    patch<{ finding: Finding }>(`/findings/${id}`, patchBody),

  // immutable report snapshots (frozen deliverables)
  snapshots: (domainId: number) => get<{ snapshots: ReportSnapshot[] }>(`/domains/${domainId}/report/snapshots`),
  createSnapshot: (domainId: number, label?: string) =>
    post<{ snapshot: ReportSnapshot }>(`/domains/${domainId}/report/snapshot`, label ? { label } : {}),
  deleteSnapshot: (id: number) => del<{ ok: true }>(`/report/snapshots/${id}`),
  snapshotUrl: (id: number, format: 'html' | 'md') => `/api/report/snapshots/${id}?format=${format}`,
  bulkUpdateFindings: (ids: number[], patchBody: { status?: FindingStatus; note?: string | null }) =>
    patch<{ changed: number }>('/findings/bulk', { ids, ...patchBody }),

  // notes
  notes: (domainId: number | 'global') =>
    get<{ notes: Note[] }>(`/notes?domainId=${domainId === 'global' ? 'global' : domainId}`),
  createNote: (domainId: number | null, title: string, body: string) =>
    post<{ note: Note }>('/notes', { domainId, title, body }),
  updateNote: (id: number, title: string, body: string) => put<{ note: Note }>(`/notes/${id}`, { title, body }),
  deleteNote: (id: number) => del<{ ok: true }>(`/notes/${id}`),
  sendNoteToDiscord: (id: number) => post<{ ok: true }>(`/notes/${id}/discord`),

  // drawings
  drawings: () => get<{ drawings: DrawingMeta[] }>('/drawings'),
  drawing: (id: number) => get<{ drawing: Drawing }>(`/drawings/${id}`),
  createDrawing: (name: string, data: unknown) => post<{ drawing: Drawing }>('/drawings', { name, data }),
  updateDrawing: (id: number, data: unknown, name?: string) =>
    put<{ drawing: Drawing }>(`/drawings/${id}`, { data, name }),
  deleteDrawing: (id: number) => del<{ ok: true }>(`/drawings/${id}`),

  // audit ledger (read-only)
  audit: (q: { domainId?: number; limit?: number } = {}) => {
    const params = new URLSearchParams()
    if (q.domainId != null) params.set('domainId', String(q.domainId))
    if (q.limit) params.set('limit', String(q.limit))
    const qs = params.toString()
    return get<{ entries: AuditEntry[] }>(`/audit${qs ? `?${qs}` : ''}`)
  },

  // backup
  backupStatus: () => get<{ serverPassphraseConfigured: boolean }>('/backup/status'),
  // backup download is handled directly in the component (binary response).
  // Upload an encrypted .rdb (verify = safe check; restore = stage for restart).
  backupVerify: (blob: Blob, passphrase?: string) => uploadBackup('/backup/verify', blob, passphrase),
  backupRestore: (blob: Blob, passphrase?: string) => uploadBackup('/backup/restore', blob, passphrase),
}

export interface BackupCheckResult {
  ok: boolean
  error?: string
  bytes?: number
  staged?: boolean
  restartRequired?: boolean
  message?: string
}

async function uploadBackup(path: string, blob: Blob, passphrase?: string): Promise<BackupCheckResult> {
  const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' }
  if (passphrase) headers['X-Backup-Passphrase'] = passphrase
  const res = await fetch(`/api${path}`, { method: 'POST', headers, body: blob })
  const text = await res.text()
  let body: unknown = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }
  if (!res.ok && res.status !== 422) {
    const message =
      body && typeof body === 'object' && 'error' in body ? String((body as { error: unknown }).error) : `HTTP ${res.status}`
    throw new ApiError(res.status, message)
  }
  return body as BackupCheckResult
}
