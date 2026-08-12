import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { run, toolExists, ToolNotFoundError } from '../util/exec'
import { isValidDomain, isValidHostname, normalizeHost } from '../util/validate'

export interface DnsxRecord {
  host: string
  a: string[]
  aaaa: string[]
  cname: string[]
}

export interface DnsxResult {
  available: boolean
  records: Map<string, DnsxRecord>
}

const strings = (value: unknown): string[] => {
  if (typeof value === 'string') return value ? [value] : []
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && !!item) : []
}

// Exported for fixture tests: dnsx has added fields over time, so the parser is
// intentionally tolerant and only consumes the stable host/address record set.
export function parseDnsxJsonl(output: string): Map<string, DnsxRecord> {
  const records = new Map<string, DnsxRecord>()
  for (const line of output.split('\n')) {
    if (!line.trim()) continue
    try {
      const row = JSON.parse(line) as Record<string, unknown>
      const host = normalizeHost(String(row.host ?? row.input ?? ''))
      if (!host || (!isValidDomain(host) && !isValidHostname(host))) continue
      const current = records.get(host) ?? { host, a: [], aaaa: [], cname: [] }
      current.a.push(...strings(row.a))
      current.aaaa.push(...strings(row.aaaa))
      current.cname.push(...strings(row.cname).map((value) => value.replace(/\.$/, '').toLowerCase()))
      current.a = [...new Set(current.a)]
      current.aaaa = [...new Set(current.aaaa)]
      current.cname = [...new Set(current.cname)]
      records.set(host, current)
    } catch {
      // Ignore progress/noise and malformed lines without losing valid records.
    }
  }
  return records
}

// Batch DNS validation and CNAME collection. The caller still has the built-in
// resolver as a fallback, so a missing binary or failed release download never
// disables discovery.
export async function dnsxResolveHosts(hosts: string[], signal?: AbortSignal): Promise<DnsxResult> {
  const valid = [...new Set(hosts.map(normalizeHost).filter((host): host is string => !!host && (isValidDomain(host) || isValidHostname(host))))]
  if (!valid.length || !(await toolExists('dnsx'))) return { available: false, records: new Map() }

  const dir = await mkdtemp(join(tmpdir(), 'recon-dnsx-'))
  const input = join(dir, 'hosts.txt')
  try {
    await writeFile(input, valid.join('\n'), 'utf8')
    const { stdout } = await run(
      'dnsx',
      ['-l', input, '-json', '-silent', '-a', '-aaaa', '-cname', '-resp', '-retry', '2'],
      { timeoutMs: 180_000, signal },
    )
    return { available: true, records: parseDnsxJsonl(stdout) }
  } catch (error) {
    if (signal?.aborted) throw error
    if (error instanceof ToolNotFoundError) return { available: false, records: new Map() }
    return { available: false, records: new Map() }
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {})
  }
}
