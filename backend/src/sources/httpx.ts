import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mapLimit } from '../util/async'
import { run, toolExists, ToolNotFoundError } from '../util/exec'
import { isInternalIp, isValidDomain, isValidHostname, normalizeHost } from '../util/validate'
import { assertPublicHost } from './guard'
import { probeHost, type ProbeResult } from './httpProbe'

type Json = Record<string, unknown>

const strings = (value: unknown): string[] => {
  if (typeof value === 'string') return value ? [value] : []
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && !!item) : []
}

const number = (value: unknown): number | null => {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

export function parseHttpxJsonl(output: string): Map<string, ProbeResult> {
  const probes = new Map<string, ProbeResult>()
  for (const line of output.split('\n')) {
    if (!line.trim()) continue
    try {
      const row = JSON.parse(line) as Json
      let host = normalizeHost(String(row.input ?? row.host ?? ''))
      if (!host && typeof row.url === 'string') host = normalizeHost(new URL(row.url).hostname)
      if (!host || (!isValidDomain(host) && !isValidHostname(host))) continue
      const url = typeof row.url === 'string' ? row.url : null
      const scheme = url?.startsWith('https://') ? 'https' : url?.startsWith('http://') ? 'http' : null
      const hash = row.hash && typeof row.hash === 'object' ? row.hash as Json : {}
      const ips = [...strings(row.a), ...strings(row.ip)]
      probes.set(host, {
        host,
        scheme,
        status: number(row.status_code ?? row.status),
        title: typeof row.title === 'string' ? row.title.slice(0, 200) : null,
        server: typeof row.webserver === 'string' ? row.webserver : typeof row.server === 'string' ? row.server : null,
        ip: ips.find((ip) => !isInternalIp(ip)) ?? null,
        url,
        cnames: strings(row.cname).map((value) => value.replace(/\.$/, '').toLowerCase()),
        loginHint: /\b(sign[\s-]?in|log[\s-]?in)\b/i.test(String(row.title ?? '')),
        apiHint: /^api[.-]/i.test(host) || /\b(api|graphql|swagger)\b/i.test(`${row.title ?? ''} ${strings(row.tech).join(' ')}`),
        technologies: strings(row.tech),
        redirect: typeof row.location === 'string' ? row.location.slice(0, 1000) : null,
        contentHash: typeof hash.body_sha256 === 'string' ? hash.body_sha256 : null,
        contentLength: number(row.content_length),
      })
    } catch {
      // Ignore non-JSON diagnostics and retain the rest of the batch.
    }
  }
  return probes
}

export interface HttpxBatchResult {
  available: boolean
  probes: ProbeResult[]
}

// Batch-probe public hosts with httpx, then use the guarded built-in probe for
// anything httpx did not return. Hosts are resolved and SSRF-checked before the
// external process is allowed to connect; redirects are not followed by httpx.
export async function httpxProbeHosts(hosts: string[], signal?: AbortSignal): Promise<HttpxBatchResult> {
  const valid = [...new Set(hosts.map(normalizeHost).filter((host): host is string => !!host && (isValidDomain(host) || isValidHostname(host))))]
  const allowed = (await mapLimit(valid, 12, async (host) => {
    try { await assertPublicHost(host); return host } catch { return null }
  }, null)).filter((host): host is string => !!host)

  let available = false
  let parsed = new Map<string, ProbeResult>()
  if (allowed.length && await toolExists('httpx')) {
    const dir = await mkdtemp(join(tmpdir(), 'recon-httpx-'))
    const input = join(dir, 'hosts.txt')
    try {
      await writeFile(input, allowed.join('\n'), 'utf8')
      const { stdout } = await run(
        'httpx',
        ['-l', input, '-no-stdin', '-json', '-silent', '-no-color', '-status-code', '-title', '-web-server', '-tech-detect', '-ip', '-cname', '-location', '-content-length', '-hash', 'sha256', '-timeout', '8', '-retries', '1', '-threads', '25'],
        { timeoutMs: 240_000, signal },
      )
      available = true
      parsed = parseHttpxJsonl(stdout)
    } catch (error) {
      if (signal?.aborted) throw error
      if (!(error instanceof ToolNotFoundError)) {
        const partial = (error as { stdout?: string }).stdout ?? ''
        parsed = parseHttpxJsonl(partial)
      }
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => {})
    }
  }

  const missing = allowed.filter((host) => !parsed.has(host))
  const fallback = await mapLimit(missing, 8, (host) => probeHost(host, signal), null)
  for (let i = 0; i < missing.length; i++) if (fallback[i]) parsed.set(missing[i], fallback[i]!)
  return { available, probes: valid.map((host) => parsed.get(host) ?? {
    host, scheme: null, status: null, title: null, server: null, ip: null, url: null,
    cnames: [], loginHint: false, apiHint: /^api[.-]/i.test(host), technologies: [],
    redirect: null, contentHash: null, contentLength: null,
  }) }
}
