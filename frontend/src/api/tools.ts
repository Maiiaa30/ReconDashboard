import { z } from 'zod'
import { post } from './http'
import { whoisResultSchema, checkHostResultSchema } from './schemas'

// Types now live with their zod schemas (single source of truth).
export type { WhoisResult, CheckHostResult, PingResult, TcpResult } from './schemas'

const whoisResponse = z.object({ result: whoisResultSchema }).passthrough()
const checkHostResponse = z.object({ result: checkHostResultSchema }).passthrough()

export const toolsApi = {
  // ad-hoc lookup tools (not scoped to a tracked domain)
  whois: (query: string) => post('/tools/whois', { query }, whoisResponse),
  checkHost: (host: string, ports?: number[]) =>
    post('/tools/check-host', { host, ...(ports ? { ports } : {}) }, checkHostResponse),
}
