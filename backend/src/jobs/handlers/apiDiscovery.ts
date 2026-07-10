import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { discoverApiSurface } from '../../sources/apiSurface'
import { knownUrlsFor } from './owaspActive'
import { listSubdomains } from '../../subdomains/store'
import { mapLimit } from '../../util/async'
import type { JobContext } from '../worker'

// Passive API-surface discovery: probe the apex + discovered subdomains for
// published OpenAPI/Swagger specs, GraphQL endpoints, and endpoints/secrets mined
// from their JS — recording each as a scored 'api' finding.
const MAX_HOSTS = 12
const HOST_CONCURRENCY = 3
// Subdomain names that commonly front an API / backend, scanned first.
const API_HOSTISH =
  /(^|\.)(api|apis|graphql|gql|gateway|gw|rest|backend|bff|services?|svc|data|app|apps|mobile|admin|portal|auth|sso|account|accounts|dev|staging|stage|test|qa|internal|edge)\b/i

export async function apiDiscoveryHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  // Apex + LIVE subdomains: API-ish names first, then any other live host, up to
  // the cap. (Only hosts already discovered by a subdomain scan are visible —
  // run Discovery first for full subdomain coverage.)
  const hosts: string[] = [domain.host]
  const live = listSubdomains(domainId).filter((s) => s.httpStatus != null && s.host !== domain.host)
  const ordered = [...live.filter((s) => API_HOSTISH.test(s.host)), ...live.filter((s) => !API_HOSTISH.test(s.host))]
  for (const s of ordered) {
    if (hosts.length >= MAX_HOSTS) break
    if (!hosts.includes(s.host)) hosts.push(s.host)
  }

  // Known .js URLs from prior recon (wayback/commoncrawl/katana) broaden the JS
  // corpus beyond just the homepage bundles.
  const knownJs = knownUrlsFor(domainId).filter((u) => /^https?:\/\/[^\s"']+\.m?js(\?|$)/i.test(u))

  const counts = { spec: 0, graphql: 0, jsEndpoints: 0, jsFiles: 0 }
  await mapLimit(
    hosts,
    HOST_CONCURRENCY,
    async (host) => {
      if (signal.aborted) return null
      progress(`probing API surface of ${host}`)
      let result
      try {
        result = await discoverApiSurface(host, knownJs)
      } catch (err) {
        log.warn({ host, err }, 'api-surface probe failed')
        return null
      }
      if (signal.aborted) return null
      counts.jsFiles += result.js.filesScanned

      for (const spec of result.specs) {
        await addScoredFinding({ domainId, type: 'api', data: { kind: 'openapi', host, ...spec }, tags: ['api', spec.format] })
        counts.spec++
      }
      for (const gql of result.graphql) {
        await addScoredFinding({ domainId, type: 'api', data: { kind: 'graphql', host, ...gql }, tags: ['api', 'graphql'] })
        counts.graphql++
      }
      const js = result.js
      if (js.endpoints.length || js.secrets.length || js.params.length) {
        await addScoredFinding({
          domainId,
          type: 'api',
          data: { kind: 'js', host, ...js },
          tags: ['api', 'js-endpoints', ...(js.secrets.length ? ['secret-in-js'] : [])],
        })
        counts.jsEndpoints += js.endpoints.length
      }
      return null
    },
    null,
  )

  log.info({ domain: domain.host, hosts: hosts.length, ...counts }, 'api discovery complete')
  return {
    domain: domain.host,
    hostsChecked: hosts.length,
    jsFilesScanned: counts.jsFiles,
    specs: counts.spec,
    graphql: counts.graphql,
    jsEndpoints: counts.jsEndpoints,
  }
}
