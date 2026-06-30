import { randomUUID } from 'node:crypto'
import { readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { XMLParser } from 'fast-xml-parser'
import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { run, toolExists } from '../../util/exec'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

// Phase 5: ACTIVE / LOUD scanners. Authorization (domain.mode ===
// active_authorized) is enforced at the route layer before enqueue; handlers
// re-check that the target belongs to the domain and that the binary exists.
//
// SECURITY: every invocation uses execFile with an explicit argv array (see
// util/exec.ts). No value is ever interpolated into a shell string.

const PORT_SPEC_RE = /^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$/
const FFUF_PATH_RE = /^[A-Za-z0-9._~/-]*FUZZ[A-Za-z0-9._~/-]*$/

function assertTargetInDomain(target: string, domainHost: string): void {
  if (!isValidHostname(target) && !isValidDomain(target)) {
    throw new Error(`invalid scan target: ${target}`)
  }
  if (!hostBelongsToDomain(target, domainHost) && target !== domainHost) {
    throw new Error(`target ${target} does not belong to authorized domain ${domainHost}`)
  }
}

// --- nmap --------------------------------------------------------------------

export async function nmapHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const target = String(params.target ?? domain.host)
  assertTargetInDomain(target, domain.host)

  if (!(await toolExists('nmap'))) {
    return { available: false, note: 'nmap binary not installed' }
  }

  const args = ['-Pn', '-T3', '-oX', '-']
  const portSpec = params.ports ? String(params.ports) : ''
  if (portSpec) {
    if (!PORT_SPEC_RE.test(portSpec)) throw new Error(`invalid port spec: ${portSpec}`)
    args.push('-p', portSpec)
  } else {
    args.push('--top-ports', '100')
  }
  args.push(target)

  let xml = ''
  try {
    const res = await run('nmap', args, { timeoutMs: 300_000 })
    xml = res.stdout
  } catch (err) {
    const e = err as Error & { stdout?: string }
    xml = e.stdout ?? ''
    if (!xml) throw err
  }

  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' })
  const parsed = parser.parse(xml) as any
  const hostNode = parsed?.nmaprun?.host
  const portsNode = hostNode?.ports?.port
  const portArray = Array.isArray(portsNode) ? portsNode : portsNode ? [portsNode] : []

  const openPorts = portArray
    .filter((p: any) => p?.state?.['@_state'] === 'open')
    .map((p: any) => ({
      port: Number(p['@_portid']),
      protocol: String(p['@_protocol'] ?? 'tcp'),
      service: p?.service?.['@_name'] ?? null,
      product: p?.service?.['@_product'] ?? null,
      version: p?.service?.['@_version'] ?? null,
    }))

  const finding = { target, openPorts }
  await addScoredFinding({ domainId, type: 'nmap', data: finding, tags: ['nmap', 'active'] })
  log.info({ target, open: openPorts.length }, 'nmap scan complete')
  return { available: true, ...finding }
}

// --- nuclei ------------------------------------------------------------------

export async function nucleiHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const target = String(params.target ?? domain.host)
  assertTargetInDomain(target, domain.host)

  if (!(await toolExists('nuclei'))) {
    return { available: false, note: 'nuclei binary not installed' }
  }

  const scheme = params.scheme === 'http' ? 'http' : 'https'
  const url = `${scheme}://${target}`
  const args = ['-u', url, '-jsonl', '-silent', '-no-color']
  if (params.severity && /^[a-z,]+$/.test(String(params.severity))) {
    args.push('-severity', String(params.severity))
  }

  let stdout = ''
  try {
    const res = await run('nuclei', args, { timeoutMs: 600_000 })
    stdout = res.stdout
  } catch (err) {
    const e = err as Error & { stdout?: string }
    stdout = e.stdout ?? ''
    if (!stdout) throw err
  }

  const results: any[] = []
  for (const line of stdout.split('\n')) {
    const t = line.trim()
    if (!t) continue
    try {
      results.push(JSON.parse(t))
    } catch {
      /* ignore */
    }
  }

  for (const r of results) {
    await addScoredFinding({
      domainId,
      type: 'nuclei',
      data: {
        target,
        templateId: r['template-id'] ?? r.templateID,
        name: r.info?.name,
        severity: r.info?.severity,
        matched: r['matched-at'] ?? r.matched,
        info: r.info,
      },
      tags: ['nuclei', 'active'],
    })
  }

  log.info({ target, findings: results.length }, 'nuclei scan complete')
  return { available: true, target, count: results.length }
}

// --- ffuf --------------------------------------------------------------------

export async function ffufHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const target = String(params.target ?? domain.host)
  assertTargetInDomain(target, domain.host)

  if (!(await toolExists('ffuf'))) {
    return { available: false, note: 'ffuf binary not installed' }
  }

  const scheme = params.scheme === 'http' ? 'http' : 'https'
  const path = String(params.path ?? 'FUZZ')
  if (!FFUF_PATH_RE.test(path)) throw new Error(`invalid ffuf path (must match safe charset and contain FUZZ): ${path}`)
  const url = `${scheme}://${target}/${path}`

  const wordlist = String(params.wordlist ?? '/usr/share/wordlists/common.txt')
  // Constrain to the wordlists dir and forbid traversal — prevents using ffuf as
  // an arbitrary-file-read primitive (e.g. /etc/../etc/shadow).
  if (
    !/^\/[A-Za-z0-9._/-]+$/.test(wordlist) ||
    wordlist.includes('..') ||
    !wordlist.startsWith('/usr/share/wordlists/')
  ) {
    throw new Error('wordlist must be an absolute path under /usr/share/wordlists/ with no ".."')
  }

  const outFile = join(tmpdir(), `ffuf-${randomUUID()}.json`)
  const args = ['-u', url, '-w', wordlist, '-of', 'json', '-o', outFile, '-mc', '200,204,301,302,307,401,403', '-s']

  try {
    try {
      await run('ffuf', args, { timeoutMs: 600_000 })
    } catch (err) {
      // ffuf can exit non-zero; still try to read the output file.
      log.warn({ err }, 'ffuf exited non-zero; attempting to read output')
    }

    let parsed: any = { results: [] }
    try {
      parsed = JSON.parse(await readFile(outFile, 'utf8'))
    } catch {
      parsed = { results: [] }
    }

    const results = Array.isArray(parsed.results) ? parsed.results : []
    for (const r of results.slice(0, 500)) {
      await addScoredFinding({
        domainId,
        type: 'ffuf',
        data: { target, url: r.url, status: r.status, length: r.length, words: r.words },
        tags: ['ffuf', 'active'],
      })
    }
    log.info({ target, hits: results.length }, 'ffuf scan complete')
    return { available: true, target, hits: results.length }
  } finally {
    await rm(outFile, { force: true }).catch(() => {})
  }
}
