import { registerHandler } from './worker'
import { subdomainDiscoveryHandler } from './handlers/subdomainDiscovery'
import { exposureHandler } from './handlers/exposure'
import { osintHandler } from './handlers/osint'
import { ffufHandler, nmapHandler, nucleiHandler } from './handlers/activeScans'

// Wire every job type to its handler. Called once at startup.
export function registerJobHandlers(): void {
  registerHandler('subdomain_discovery', subdomainDiscoveryHandler)
  registerHandler('exposure_scan', exposureHandler)
  registerHandler('osint_gather', osintHandler)
  registerHandler('nmap_scan', nmapHandler)
  registerHandler('nuclei_scan', nucleiHandler)
  registerHandler('ffuf_scan', ffufHandler)
}
