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

export async function nmapHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const target = String(params.target ?? domain.host)
  assertTargetInDomain(target, domain.host)

  if (!(await toolExists('nmap'))) {
    return { available: false, note: 'nmap binary not installed' }
  }
  // Deep scan: every port (-p-) + default NSE scripts (-sC) for rich, useful
  // detail (TLS certs, HTTP titles/headers, etc.) on top of version detection.
  // Modelled on `nmap -sS -sV -O -sC -p- -A` but adapted to run unprivileged:
  // -sS (SYN) and -O (OS) need root/admin + Npcap, so -O is only added when we
  // actually run as root; otherwise the scan degrades to a connect scan and the
  // rest of the data still comes back.
  const deep = params.deep === true
  progress(`scanning ${target} with nmap${deep ? ' (deep: all ports + scripts)' : ''}`)

  const args = ['-Pn', deep ? '-T4' : '-T3', '-sV', '-oX', '-']
  if (deep) {
    args.push('-sC', '-p-')
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0
    if (isRoot) args.push('-O')
  } else {
    // -sV so the service column is populated; nmap's own top-1000 default (vs the
    // old top-100) so a manual `nmap <host>` and the dashboard agree.
    const portSpec = params.ports ? String(params.ports) : ''
    if (portSpec) {
      if (!PORT_SPEC_RE.test(portSpec)) throw new Error(`invalid port spec: ${portSpec}`)
      args.push('-p', portSpec)
    } else {
      args.push('--top-ports', '1000')
    }
  }
  args.push(target)

  let xml = ''
  try {
    // Keep the run timeout just under the worker's 20-min job cap so a slow deep
    // scan times out here first — that path preserves partial stdout to parse.
    const res = await run('nmap', args, { timeoutMs: deep ? 1_140_000 : 600_000, signal })
    xml = res.stdout
  } catch (err) {
    const e = err as Error & { stdout?: string }
    xml = e.stdout ?? ''
    if (!xml) throw err
  }

  const arr = (x: any): any[] => (Array.isArray(x) ? x : x ? [x] : [])
  // Normalize an nmap <script> element (or list) into {id, output} pairs.
  const scriptsOf = (node: any) =>
    arr(node?.script)
      .map((s: any) => ({ id: String(s?.['@_id'] ?? ''), output: String(s?.['@_output'] ?? '').trim() }))
      .filter((s: any) => s.id && s.output)

  let parsed: any = {}
  try {
    const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' })
    parsed = parser.parse(xml) as any
  } catch (err) {
    // Truncated XML (e.g. an aborted deep scan) — salvage nothing rather than crash.
    log.warn({ target, err }, 'nmap XML parse failed; returning empty result')
  }
  const hostNode = parsed?.nmaprun?.host
  const portArray = arr(hostNode?.ports?.port)

  // Keep open + filtered ports (filtered = firewalled, still worth showing);
  // closed ports are dropped as noise. Each row carries its state so the UI can
  // render an open/filtered column.
  const KEEP = new Set(['open', 'filtered'])
  const allPorts = portArray
    .filter((p: any) => KEEP.has(p?.state?.['@_state']))
    .map((p: any) => {
      const svc = p?.service ?? {}
      return {
        port: Number(p['@_portid']),
        protocol: String(p['@_protocol'] ?? 'tcp'),
        state: String(p?.state?.['@_state'] ?? 'open'),
        service: svc['@_name'] ?? null,
        product: svc['@_product'] ?? null,
        version: svc['@_version'] ?? null,
        extrainfo: svc['@_extrainfo'] ?? null,
        // NSE script output per port (deep scans only).
        ...(deep ? { scripts: scriptsOf(p) } : {}),
      }
    })
  // openPorts stays the open-only subset (same shape as before) for existing
  // consumers — overview counts, scoring, reports, exports.
  const openPorts = allPorts.filter((p) => p.state === 'open')

  // Deep extras: OS fingerprint guesses and host-level script output.
  const os = deep
    ? arr(hostNode?.os?.osmatch)
        .map((m: any) => ({ name: String(m?.['@_name'] ?? ''), accuracy: Number(m?.['@_accuracy'] ?? 0) }))
        .filter((m: any) => m.name)
        .slice(0, 3)
    : []
  const hostScripts = deep ? scriptsOf(hostNode?.hostscript) : []

  const finding = { target, deep, openPorts, allPorts, ...(deep ? { os, hostScripts } : {}) }
  await addScoredFinding({ domainId, type: 'nmap', data: finding, tags: ['nmap', 'active', ...(deep ? ['deep'] : [])] })
  log.info({ target, deep, open: openPorts.length, kept: allPorts.length }, 'nmap scan complete')
  return { available: true, ...finding }
}

// --- nuclei ------------------------------------------------------------------

export async function nucleiHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const target = String(params.target ?? domain.host)
  assertTargetInDomain(target, domain.host)

  if (!(await toolExists('nuclei'))) {
    return { available: false, note: 'nuclei binary not installed' }
  }
  progress(`running nuclei against ${target}`)

  const scheme = params.scheme === 'http' ? 'http' : 'https'
  const url = `${scheme}://${target}`
  const args = ['-u', url, '-jsonl', '-silent', '-no-color']
  if (params.severity && /^[a-z,]+$/.test(String(params.severity))) {
    args.push('-severity', String(params.severity))
  }
  // OWASP tag filtering: only validated tag tokens are passed.
  if (Array.isArray(params.tags) && params.tags.length) {
    const tags = (params.tags as unknown[])
      .map((t) => String(t))
      .filter((t) => /^[a-z0-9-]+$/.test(t))
    if (tags.length) args.push('-tags', tags.join(','))
  }
  const owaspCategory = typeof params.owaspCategory === 'string' ? params.owaspCategory : undefined

  let stdout = ''
  try {
    const res = await run('nuclei', args, { timeoutMs: 600_000, signal })
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
        owaspCategory,
        info: r.info,
      },
      tags: ['nuclei', 'active', ...(owaspCategory ? [`owasp:${owaspCategory}`] : [])],
    })
  }

  log.info({ target, findings: results.length }, 'nuclei scan complete')
  return { available: true, target, count: results.length }
}

// --- ffuf --------------------------------------------------------------------

export async function ffufHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const target = String(params.target ?? domain.host)
  assertTargetInDomain(target, domain.host)

  if (!(await toolExists('ffuf'))) {
    return { available: false, note: 'ffuf binary not installed' }
  }
  progress(`fuzzing ${target} with ffuf`)

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
      await run('ffuf', args, { timeoutMs: 600_000, signal })
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
