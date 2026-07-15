import { registerHandler } from './worker'
import { subdomainDiscoveryHandler } from './handlers/subdomainDiscovery'
import { exposureHandler } from './handlers/exposure'
import { osintHandler } from './handlers/osint'
import { ffufHandler, nmapHandler, nucleiHandler } from './handlers/activeScans'
import { owaspActiveHandler } from './handlers/owaspActive'
import { toolScanHandler } from './handlers/toolScan'
import { screenshotHandler } from './handlers/screenshot'
import { originHandler } from './handlers/origin'
import { leakCheckHandler } from './handlers/leakCheck'
import { apiDiscoveryHandler } from './handlers/apiDiscovery'
import { intruderHandler } from './handlers/intruder'
import { codeLeakHandler } from './handlers/codeLeak'
import { cveVerifyHandler } from './handlers/cveVerify'
import { authzDiffHandler } from './handlers/authzDiff'
import { paramDiscoveryHandler } from './handlers/paramDiscovery'
import { injectConfirmHandler } from './handlers/injectConfirm'
import { jwtConfuseHandler } from './handlers/jwtConfuse'

// Wire every job type to its handler. Called once at startup.
export function registerJobHandlers(): void {
  registerHandler('subdomain_discovery', subdomainDiscoveryHandler)
  registerHandler('exposure_scan', exposureHandler)
  registerHandler('osint_gather', osintHandler)
  registerHandler('nmap_scan', nmapHandler)
  registerHandler('nuclei_scan', nucleiHandler)
  registerHandler('ffuf_scan', ffufHandler)
  registerHandler('owasp_active', owaspActiveHandler)
  registerHandler('tool_scan', toolScanHandler)
  registerHandler('screenshot', screenshotHandler)
  registerHandler('origin_scan', originHandler)
  registerHandler('leak_check', leakCheckHandler)
  registerHandler('api_discovery', apiDiscoveryHandler)
  registerHandler('intruder', intruderHandler)
  registerHandler('code_leak', codeLeakHandler)
  registerHandler('cve_verify', cveVerifyHandler)
  registerHandler('authz_diff', authzDiffHandler)
  registerHandler('param_discovery', paramDiscoveryHandler)
  registerHandler('inject_confirm', injectConfirmHandler)
  registerHandler('jwt_confuse', jwtConfuseHandler)
}
