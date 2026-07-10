import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { runBypass403, runDalfox, runDatastores, runHttpMethods, runKatana, runNaabu, runSqlmap, runSslscan, runWpEnum, type ToolFinding } from '../../sources/binTools'
import { assertPublicHost } from '../../sources/guard'
import { ToolNotFoundError } from '../../util/exec'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

export const TOOL_IDS = ['katana', 'naabu', 'dalfox', 'sslscan', 'sqlmap', 'wpenum', 'bypass403', 'methods', 'datastores'] as const
export type ToolId = (typeof TOOL_IDS)[number]

// One active tool against a target. Authorization (active_authorized OR confirm)
// is enforced at the route; here we re-check the target belongs to the domain.
export async function toolScanHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const target = String(params.target ?? domain.host)
  if (!isValidHostname(target) && !isValidDomain(target)) throw new Error(`invalid target: ${target}`)
  if (target !== domain.host && !hostBelongsToDomain(target, domain.host)) {
    throw new Error(`target ${target} does not belong to authorized domain ${domain.host}`)
  }
  const scheme = params.scheme === 'http' ? 'http' : 'https'
  const tool = String(params.tool) as ToolId

  // SSRF: katana/naabu/dalfox/sslscan/sqlmap connect to whatever the host
  // resolves to. Refuse a target that resolves to an internal/Tailscale address
  // before any binary runs (throws SsrfBlockedError -> job fails with a reason).
  await assertPublicHost(target)
  progress(`running ${tool} against ${target}`)

  try {
    let finding: ToolFinding | null
    switch (tool) {
      case 'katana':
        finding = await runKatana(scheme, target, signal)
        break
      case 'naabu':
        finding = await runNaabu(target, signal)
        break
      case 'dalfox':
        finding = await runDalfox(scheme, target, signal)
        break
      case 'sslscan':
        finding = await runSslscan(target, signal)
        break
      case 'sqlmap':
        finding = await runSqlmap(scheme, target, signal)
        break
      case 'wpenum':
        finding = await runWpEnum(scheme, target, signal)
        break
      case 'bypass403': {
        // Optional specific path(s) to bypass (e.g. a 403 hit sent from Fuzzing).
        const raw = params.paths ?? params.path
        const paths = Array.isArray(raw)
          ? raw.map(String)
          : typeof raw === 'string' && raw
            ? [raw]
            : undefined
        finding = await runBypass403(scheme, target, paths, signal)
        break
      }
      case 'methods':
        finding = await runHttpMethods(scheme, target, signal)
        break
      case 'datastores':
        finding = await runDatastores(scheme, target, signal)
        break
      default:
        throw new Error(`unknown tool: ${tool}`)
    }

    if (finding) {
      await addScoredFinding({
        domainId,
        type: 'tool',
        data: {
          tool: finding.tool,
          target: finding.target,
          severity: finding.severity,
          title: finding.title,
          detail: finding.detail,
          items: finding.items,
        },
        tags: ['tool', finding.tool, `sev:${finding.severity}`],
      })
      log.info({ tool, target, items: finding.items.length }, 'tool scan complete')
      return { available: true, tool, target, found: true, count: finding.items.length }
    }
    return { available: true, tool, target, found: false }
  } catch (err) {
    if (err instanceof ToolNotFoundError) {
      return { available: false, tool, note: `${tool} binary not installed in this image` }
    }
    throw err
  }
}
