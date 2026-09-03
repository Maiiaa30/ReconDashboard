import { post } from './http'

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

export const toolsApi = {
  // ad-hoc lookup tools (not scoped to a tracked domain)
  whois: (query: string) => post<{ result: WhoisResult }>('/tools/whois', { query }),
  checkHost: (host: string, ports?: number[]) =>
    post<{ result: CheckHostResult }>('/tools/check-host', { host, ...(ports ? { ports } : {}) }),
}
