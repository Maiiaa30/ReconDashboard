import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { runBypass403, runDalfox, runDatastores, runHttpMethods, runKatana, runNaabu, runSqlmap, runSslscan, runWpEnum, type SqlmapOpts, type ToolFinding } from '../../sources/binTools'
import { assertPublicHost } from '../../sources/guard'
import { fingerprintWaf } from '../../sources/wafFingerprint'
import { tamperForBrand } from '../../sources/sqlmapTamper'
import { throttleForBrand } from '../../sources/wafThrottle'
import { getHostWaf } from '../../subdomains/store'
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
    // Set by the sqlmap evasion path so the identified WAF is preserved on the
    // finding (operators asked to SEE the brand/version, not just in the logs).
    let wafNote: string | null = null
    switch (tool) {
      case 'katana':
        finding = await runKatana(scheme, target, signal)
        break
      case 'naabu':
        finding = await runNaabu(target, signal)
        break
      case 'dalfox': {
        // WAF throttle: known WAF-fronted host → fewer workers + inter-request
        // delay so dalfox's XSS probes don't trip rate-based rules.
        const throttle = throttleForBrand(getHostWaf(domainId, target))
        if (throttle) progress(`dalfox: ${throttle.reason} for ${target}`)
        finding = await runDalfox(scheme, target, signal, throttle ? { worker: throttle.dalfoxWorker, delayMs: throttle.dalfoxDelayMs } : {})
        break
      }
      case 'sslscan':
        finding = await runSslscan(target, signal)
        break
      case 'sqlmap': {
        // WAF evasion (opt-in). Identify the WAF, pick a stock sqlmap tamper
        // chain for that vendor, and raise depth so evasion has vectors to try.
        // An explicit `tamper` param overrides the auto-picked chain.
        const opts: SqlmapOpts = {}
        if (params.evade) {
          const fp = await fingerprintWaf(scheme, target, signal)
          const preset = tamperForBrand(fp.brand)
          const tamper = typeof params.tamper === 'string' && params.tamper.trim()
            ? params.tamper.trim()
            : preset?.tamper
          if (tamper) {
            opts.tamper = tamper
            opts.level = 2
            opts.risk = 2
            opts.delay = typeof params.delay === 'number' ? params.delay : (preset?.delay ?? 0)
          }
          if (fp.detected) {
            wafNote = `WAF: ${fp.brand}${fp.version ? ` ${fp.version}` : ''}`
              + `${fp.manufacturer ? ` — ${fp.manufacturer}` : ''} (via ${fp.source})`
          }
          progress(
            wafNote
              ? `${wafNote} — tamper: ${opts.tamper ?? 'none'}`
              : 'no WAF identified — running sqlmap without tamper',
          )
        }
        finding = await runSqlmap(scheme, target, signal, opts)
        break
      }
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

    // Preserve the identified WAF on the finding even when sqlmap slipped it.
    if (finding && wafNote) finding.items = [wafNote, ...finding.items]

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
