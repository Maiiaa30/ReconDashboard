import { run, toolExists } from '../util/exec'
import { isValidDomain, isValidHostname } from '../util/validate'
import { mapLimit } from '../util/async'

export interface ZoneTransferResult {
  available: boolean // whether the `dig` tool exists
  vulnerable: boolean
  servers: { ns: string; records: number }[]
  sample?: string
}

// Attempt an AXFR (full DNS zone transfer) against each nameserver. A successful
// transfer is a real misconfiguration (leaks the whole zone). Passive-ish: it's
// a standard DNS query, no exploitation. Uses `dig` (graceful if absent).
export async function zoneTransfer(domain: string, nameservers: string[], signal?: AbortSignal): Promise<ZoneTransferResult> {
  if (!isValidDomain(domain)) throw new Error(`invalid domain: ${domain}`)
  if (!(await toolExists('dig'))) {
    return { available: false, vulnerable: false, servers: [] }
  }

  const attempts = await mapLimit(nameservers.slice(0, 8), 4, async (nsRaw) => {
    if (signal?.aborted) return null
    const ns = nsRaw.replace(/\.$/, '')
    if (!isValidHostname(ns) && !isValidDomain(ns)) return null
    try {
      const { stdout } = await run('dig', ['AXFR', domain, `@${ns}`, '+noidnout', '+time=8', '+tries=1'], { timeoutMs: 20_000, signal })
      if (/;\s*Transfer failed|communications error|connection timed out|; Transfer/i.test(stdout)) return null
      const m = stdout.match(/XFR size:\s*(\d+)/i)
      const records = m ? Number(m[1]) : stdout.split('\n').filter((l) => /\bIN\b/.test(l)).length
      return records > 1 ? { ns, records, sample: stdout.split('\n').slice(0, 40).join('\n') } : null
    } catch {
      return null
    }
  }, null)
  const successful = attempts.filter((x): x is { ns: string; records: number; sample: string } => x != null)
  const servers = successful.map(({ ns, records }) => ({ ns, records }))
  const sample = successful[0]?.sample

  return { available: true, vulnerable: servers.length > 0, servers, sample }
}
