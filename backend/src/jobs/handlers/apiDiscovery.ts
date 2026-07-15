import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { discoverApiSurface } from '../../sources/apiSurface'
import { knownUrlsFor } from './owaspActive'
import { diffAndStore, listSubdomains } from '../../subdomains/store'
import { mapLimit } from '../../util/async'
import { hostBelongsToDomain } from '../../util/validate'
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

  // A specific host was requested (validated in the route as belonging to this
  // domain): scan just that one. Otherwise sweep the apex + LIVE subdomains,
  // API-ish names first, then any other live host, up to the cap. (Only hosts
  // already discovered by a subdomain scan are visible — run Discovery first for
  // full subdomain coverage.)
  const only = typeof params.host === 'string' && params.host ? params.host : null
  const hosts: string[] = only ? [only] : [domain.host]
  if (!only) {
    const live = listSubdomains(domainId).filter((s) => s.httpStatus != null && s.host !== domain.host)
    const ordered = [...live.filter((s) => API_HOSTISH.test(s.host)), ...live.filter((s) => !API_HOSTISH.test(s.host))]
    for (const s of ordered) {
      if (hosts.length >= MAX_HOSTS) break
      if (!hosts.includes(s.host)) hosts.push(s.host)
    }
  }

  // The full passive URL corpus from prior recon (wayback/commoncrawl/urlscan/
  // katana). `.js` URLs broaden the JS corpus beyond the homepage bundles; the
  // rest is mined per-host for API-looking paths (no new request to the target).
  const knownUrls = knownUrlsFor(domainId)
  const knownJs = knownUrls.filter((u) => /^https?:\/\/[^\s"']+\.m?js(\?|$)/i.test(u))

  const counts = { spec: 0, graphql: 0, jsEndpoints: 0, jsFiles: 0 }
  const jsHosts = new Set<string>() // in-scope sibling hostnames mined from JS
  await mapLimit(
    hosts,
    HOST_CONCURRENCY,
    async (host) => {
      if (signal.aborted) return null
      progress(`probing API surface of ${host}`)
      let result
      try {
        result = await discoverApiSurface(host, knownJs, knownUrls)
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
      // Hostnames the bundle referenced (already scoped by mineJs); re-check
      // belongs-to-domain here for defense in depth.
      for (const h of js.hosts ?? []) if (h === domain.host || hostBelongsToDomain(h, domain.host)) jsHosts.add(h)
      if (js.endpoints.length || js.secrets.length || js.params.length || js.frameworks?.length || js.env?.length) {
        await addScoredFinding({
          domainId,
          type: 'api',
          data: { kind: 'js', host, ...js },
          tags: [
            'api',
            'js-endpoints',
            ...(js.secrets.length ? ['secret-in-js'] : []),
            ...(js.frameworks?.length ? ['spa'] : []),
            ...(js.env?.length ? ['env-config'] : []),
          ],
        })
        counts.jsEndpoints += js.endpoints.length
      }
      return null
    },
    null,
  )

  // Register in-scope hostnames the JS referenced (api.target.com, a staging
  // sibling, …) as subdomains, so new-host diffing/alerting picks them up for
  // free — the same feedback loop the cert-SAN fold uses in exposure.
  let newHostsFromJs = 0
  if (jsHosts.size) {
    try {
      const res = diffAndStore(domainId, [...jsHosts].map((host) => ({ host, source: 'js-recon' })))
      newHostsFromJs = res.newHosts.length
      if (newHostsFromJs) log.info({ domain: domain.host, newHostsFromJs }, 'api discovery: new subdomains from JS')
    } catch (err) {
      log.warn({ err }, 'js-recon host fold failed')
    }
  }

  log.info({ domain: domain.host, hosts: hosts.length, jsHosts: jsHosts.size, newHostsFromJs, ...counts }, 'api discovery complete')
  return {
    domain: domain.host,
    hostsChecked: hosts.length,
    newHostsFromJs,
    jsFilesScanned: counts.jsFiles,
    specs: counts.spec,
    graphql: counts.graphql,
    jsEndpoints: counts.jsEndpoints,
  }
}
