import { config } from '../../config'
import { getDomain } from '../../domains/store'
import { addFinding } from '../../findings/store'
import { searchDomainLeaks } from '../../sources/leaks'
import type { JobContext } from '../worker'

// Query the configured breach-data provider for accounts on this domain and
// store each exposed record as a 'leak' finding. Passive (a third-party API
// lookup keyed on the domain — never touches the target), so it runs on any
// domain mode; active domains just get it automatically once a day (scheduler).
export async function leakCheckHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  if (!config.leaks.enabled) {
    throw new Error('leak provider not configured (set LEAK_PROVIDER + LEAK_API_KEY in .env)')
  }

  progress(`querying ${config.leaks.provider} for ${domain.host}`)
  const result = await searchDomainLeaks(domain.host, signal)

  let stored = 0
  for (const e of result.entries) {
    const hasPassword = Boolean(e.password || e.hashedPassword)
    // Credentials with a password are the highest exposure; account-only hits
    // (e.g. HIBP, which never returns passwords) are still notable.
    const score = hasPassword ? 85 : 55
    addFinding({
      domainId,
      type: 'leak',
      data: {
        email: e.email,
        username: e.username,
        password: e.password,
        hashedPassword: e.hashedPassword,
        name: e.name,
        phone: e.phone,
        ip: e.ip,
        source: e.source,
        breachDate: e.breachDate,
        provider: result.provider,
        domain: domain.host,
      },
      score,
      tags: [
        'leak',
        `provider:${result.provider}`,
        ...(e.source ? [`breach:${e.source}`] : []),
        ...(hasPassword ? ['has-password'] : []),
      ],
    })
    stored++
  }

  progress(`stored ${stored} exposed record(s)`)
  log.info({ domain: domain.host, provider: result.provider, total: result.total, stored }, 'leak check complete')
  return {
    domain: domain.host,
    provider: result.provider,
    total: result.total,
    stored,
    truncated: result.truncated,
  }
}
