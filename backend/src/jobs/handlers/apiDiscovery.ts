import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { discoverApiSurface } from '../../sources/apiSurface'
import { listSubdomains } from '../../subdomains/store'
import type { JobContext } from '../worker'

// Passive API-surface discovery: probe the apex + likely API subdomains for
// published OpenAPI/Swagger specs and GraphQL endpoints, and record each as a
// scored 'api' finding.
const MAX_HOSTS = 6

export async function apiDiscoveryHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  // Apex + live subdomains that look like API hosts (bounded).
  const hosts: string[] = [domain.host]
  for (const s of listSubdomains(domainId)) {
    if (s.httpStatus != null && /(^|\.)(api|graphql|gateway|rest)\b/i.test(s.host) && !hosts.includes(s.host)) {
      hosts.push(s.host)
    }
    if (hosts.length >= MAX_HOSTS) break
  }

  let specCount = 0
  let graphqlCount = 0
  for (const host of hosts) {
    if (signal.aborted) break
    progress(`probing API surface of ${host}`)
    let result
    try {
      result = await discoverApiSurface(host)
    } catch (err) {
      log.warn({ host, err }, 'api-surface probe failed')
      continue
    }
    if (signal.aborted) break

    for (const spec of result.specs) {
      await addScoredFinding({
        domainId,
        type: 'api',
        data: { kind: 'openapi', host, ...spec },
        tags: ['api', spec.format],
      })
      specCount++
    }
    for (const gql of result.graphql) {
      await addScoredFinding({
        domainId,
        type: 'api',
        data: { kind: 'graphql', host, ...gql },
        tags: ['api', 'graphql'],
      })
      graphqlCount++
    }
  }

  log.info({ domain: domain.host, hosts: hosts.length, specCount, graphqlCount }, 'api discovery complete')
  return { domain: domain.host, hostsChecked: hosts.length, specs: specCount, graphql: graphqlCount }
}
