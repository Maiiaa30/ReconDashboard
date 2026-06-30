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

export interface Domain {
  id: number
  host: string
  label: string | null
  mode: DomainMode
  profile?: DomainProfile
  createdAt: string
  updatedAt: string
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

export type JobStatus = 'queued' | 'running' | 'done' | 'error'

export interface Job {
  id: number
  type: string
  status: JobStatus
  params: unknown
  result: unknown
  error: string | null
  createdAt: string
  startedAt: string | null
  finishedAt: string | null
}

export interface Finding {
  id: number
  domainId: number | null
  type: string
  data: any
  score: number | null
  tags: string[]
  createdAt: string
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
}

export interface MetaStatus {
  scorer: string
  aiProvider: string
  scheduler: { enabled: boolean; intervalMinutes: number }
  discordConfigured: boolean
  tools: { subfinder: boolean; nmap: boolean; nuclei: boolean; ffuf: boolean; chromium: boolean; dig: boolean }
  wordlists: Wordlist[]
}

export interface Me {
  user: { username: string; totpEnabled: boolean }
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
}

// --- API surface -------------------------------------------------------------

export const api = {
  // auth
  me: () => get<Me>('/auth/me'),
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

  // meta
  meta: () => get<MetaStatus>('/meta/status'),

  // domains
  domains: () => get<{ domains: Domain[] }>('/domains'),
  domainsOverview: () => get<{ overview: DomainOverview[] }>('/domains/overview'),
  createDomain: (host: string, mode: DomainMode, label?: string) =>
    post<{ domain: Domain }>('/domains', { host, mode, label }),
  setDomainMode: (id: number, mode: DomainMode) => patch<{ domain: Domain }>(`/domains/${id}`, { mode }),
  updateDomain: (id: number, patchBody: { mode?: DomainMode; label?: string | null; profile?: DomainProfile }) =>
    patch<{ domain: Domain }>(`/domains/${id}`, patchBody),
  deleteDomain: (id: number) => del<{ ok: true }>(`/domains/${id}`),

  // OWASP testing
  owaspCatalog: () => get<{ catalog: OwaspCategory[]; profileKeys: OwaspProfileKey[] }>('/owasp/catalog'),
  runOwasp: (id: number, categoryIds?: string[], scheme?: string) =>
    post<{ jobId: number; categories: string[]; tags: string[] }>(`/domains/${id}/owasp`, { categoryIds, scheme }),

  // subdomains
  subdomains: (id: number) => get<{ subdomains: Subdomain[] }>(`/domains/${id}/subdomains`),
  discover: (id: number) => post<{ jobId: number }>(`/domains/${id}/discover`),
  acknowledgeNew: (id: number) => post<{ cleared: number }>(`/domains/${id}/subdomains/acknowledge`),

  // passive recon
  exposure: (id: number) => post<{ jobId: number }>(`/domains/${id}/exposure`),
  osint: (id: number) => post<{ jobId: number }>(`/domains/${id}/osint`),

  // origin discovery (WAF/CDN bypass)
  findOrigin: (id: number) => post<{ jobId: number }>(`/domains/${id}/origin`),

  // screenshots
  captureScreenshots: (id: number) => post<{ jobId: number }>(`/domains/${id}/screenshots`),
  screenshots: (id: number) => get<{ screenshots: ScreenshotEntry[] }>(`/domains/${id}/screenshots`),
  screenshotUrl: (id: number, host: string) => `/api/domains/${id}/screenshot?host=${encodeURIComponent(host)}`,

  // active scans (gated server-side; passive domains require confirm:true)
  nmap: (id: number, opts: { target?: string; ports?: string; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/scan/nmap`, opts),
  nuclei: (id: number, opts: { target?: string; severity?: string; scheme?: string; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/scan/nuclei`, opts),
  ffuf: (id: number, opts: { target?: string; path?: string; wordlist?: string; scheme?: string; confirm?: boolean } = {}) =>
    post<{ jobId: number }>(`/domains/${id}/scan/ffuf`, opts),

  // jobs
  jobs: () => get<{ jobs: Job[] }>('/jobs'),
  job: (id: number) => get<{ job: Job }>(`/jobs/${id}`),

  // findings
  findings: (q: { domainId?: number; type?: string; limit?: number } = {}) => {
    const params = new URLSearchParams()
    if (q.domainId != null) params.set('domainId', String(q.domainId))
    if (q.type) params.set('type', q.type)
    if (q.limit) params.set('limit', String(q.limit))
    const qs = params.toString()
    return get<{ findings: Finding[] }>(`/findings${qs ? `?${qs}` : ''}`)
  },

  // notes
  notes: (domainId: number | 'global') =>
    get<{ notes: Note[] }>(`/notes?domainId=${domainId === 'global' ? 'global' : domainId}`),
  createNote: (domainId: number | null, title: string, body: string) =>
    post<{ note: Note }>('/notes', { domainId, title, body }),
  updateNote: (id: number, title: string, body: string) => put<{ note: Note }>(`/notes/${id}`, { title, body }),
  deleteNote: (id: number) => del<{ ok: true }>(`/notes/${id}`),

  // drawings
  drawings: () => get<{ drawings: DrawingMeta[] }>('/drawings'),
  drawing: (id: number) => get<{ drawing: Drawing }>(`/drawings/${id}`),
  createDrawing: (name: string, data: unknown) => post<{ drawing: Drawing }>('/drawings', { name, data }),
  updateDrawing: (id: number, data: unknown, name?: string) =>
    put<{ drawing: Drawing }>(`/drawings/${id}`, { data, name }),
  deleteDrawing: (id: number) => del<{ ok: true }>(`/drawings/${id}`),

  // backup
  backupStatus: () => get<{ serverPassphraseConfigured: boolean }>('/backup/status'),
  // backup download is handled directly in the component (binary response).
}
