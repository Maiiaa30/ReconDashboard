import { run, toolExists, ToolNotFoundError } from '../util/exec'
import { hostBelongsToDomain, normalizeHost } from '../util/validate'

export interface SubfinderResult {
  available: boolean
  hosts: string[]
}

// Passive subdomain discovery via subfinder (ProjectDiscovery). Passive sources
// only; safe to run against any domain. subfinder may not be installed (e.g.
// local Windows dev) — in that case we report unavailable rather than crash.
//
// `-oJ` emits one JSON object per line: {"host":"...","input":"...","source":"..."}.
export async function subfinderSubdomains(domain: string): Promise<SubfinderResult> {
  if (!(await toolExists('subfinder'))) {
    return { available: false, hosts: [] }
  }

  try {
    const { stdout } = await run(
      'subfinder',
      ['-d', domain, '-oJ', '-silent', '-all'],
      { timeoutMs: 180_000 },
    )
    const hosts = new Set<string>()
    for (const line of stdout.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed) continue
      try {
        const obj = JSON.parse(trimmed) as { host?: string }
        const host = obj.host ? normalizeHost(obj.host) : null
        if (host && hostBelongsToDomain(host, domain)) hosts.add(host)
      } catch {
        // ignore non-JSON noise
      }
    }
    return { available: true, hosts: [...hosts] }
  } catch (err) {
    if (err instanceof ToolNotFoundError) return { available: false, hosts: [] }
    throw err
  }
}
