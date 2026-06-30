import { Socket } from 'node:net'
import { performance } from 'node:perf_hooks'
import { resolveDns } from './dns'
import { probeHost, type ProbeResult } from './httpProbe'
import { run, ToolNotFoundError } from '../util/exec'
import { isInternalIp, isValidHostname, isValidIp } from '../util/validate'

// "Check host" style reachability: resolve a host, then probe it the way an
// operator would — ICMP ping (latency/loss), TCP connect on common service
// ports, and a light HTTP probe. All checks are bounded by tight timeouts.
//
// SSRF defense (consistent with probe/screenshot): we refuse to check a target
// that resolves to an internal/private/loopback address.

const TCP_TIMEOUT_MS = 4_000
const PING_TIMEOUT_S = 5
const PING_COUNT = 4

// Common service ports worth a connect check by default.
export const DEFAULT_PORTS = [80, 443, 22, 21, 25, 3389, 8080, 8443]
const MAX_PORTS = 20

export interface TcpResult {
  port: number
  open: boolean
  latencyMs: number | null
}

export interface PingResult {
  available: boolean // false when the ping binary isn't installed
  alive: boolean
  transmitted: number | null
  received: number | null
  lossPct: number | null
  rttMs: { min: number; avg: number; max: number } | null
  error: string | null
}

export interface CheckHostResult {
  target: string
  resolvedIp: string | null
  dns: { a: string[]; aaaa: string[]; cname: string[]; ns: string[] } | { error: string }
  ping: PingResult
  tcp: TcpResult[]
  http: Pick<ProbeResult, 'scheme' | 'status' | 'title' | 'server' | 'url'> | null
}

/** Single TCP connect, measuring time-to-connect. Never rejects. */
export function tcpConnect(host: string, port: number): Promise<TcpResult> {
  return new Promise((resolve) => {
    const socket = new Socket()
    const start = performance.now()
    let settled = false

    const done = (open: boolean) => {
      if (settled) return
      settled = true
      const latencyMs = open ? Math.round(performance.now() - start) : null
      socket.destroy()
      resolve({ port, open, latencyMs })
    }

    socket.setTimeout(TCP_TIMEOUT_MS)
    socket.once('connect', () => done(true))
    socket.once('timeout', () => done(false))
    socket.once('error', () => done(false))
    socket.connect(port, host)
  })
}

function parsePing(stdout: string): Omit<PingResult, 'available' | 'error'> {
  // iputils ping: "4 packets transmitted, 4 received, 0% packet loss"
  //               "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.0 ms"
  const stat = stdout.match(/(\d+)\s+packets transmitted,\s+(\d+)\s+received/i)
  const loss = stdout.match(/([\d.]+)%\s+packet loss/i)
  const rtt = stdout.match(/=\s*([\d.]+)\/([\d.]+)\/([\d.]+)/)
  const transmitted = stat ? Number(stat[1]) : null
  const received = stat ? Number(stat[2]) : null
  return {
    alive: received != null && received > 0,
    transmitted,
    received,
    lossPct: loss ? Number(loss[1]) : received != null && transmitted ? Math.round((1 - received / transmitted) * 100) : null,
    rttMs: rtt ? { min: Number(rtt[1]), avg: Number(rtt[2]), max: Number(rtt[3]) } : null,
  }
}

/** ICMP ping via the system `ping` binary. Degrades gracefully if unavailable. */
export async function icmpPing(ip: string): Promise<PingResult> {
  try {
    // -c count, -w deadline (s). `ping` exits non-zero on 100% loss, which `run`
    // turns into a throw with stdout attached — we still parse that stdout.
    const { stdout } = await run('ping', ['-c', String(PING_COUNT), '-w', String(PING_TIMEOUT_S), ip], {
      timeoutMs: (PING_TIMEOUT_S + 3) * 1000,
    })
    return { available: true, error: null, ...parsePing(stdout) }
  } catch (err) {
    if (err instanceof ToolNotFoundError) {
      return { available: false, alive: false, transmitted: null, received: null, lossPct: null, rttMs: null, error: 'ping binary not available' }
    }
    const out = (err as { stdout?: string }).stdout ?? ''
    // Non-zero exit with parseable output (e.g. 100% loss) is still a valid result.
    if (/packets transmitted/i.test(out)) {
      return { available: true, error: null, ...parsePing(out) }
    }
    return { available: true, alive: false, transmitted: null, received: null, lossPct: null, rttMs: null, error: 'host unreachable' }
  }
}

export class CheckHostError extends Error {}

export async function checkHost(target: string, ports?: number[]): Promise<CheckHostResult> {
  const t = target.trim().toLowerCase().replace(/\.$/, '')
  const isIp = isValidIp(t)
  if (!isIp && !isValidHostname(t)) {
    throw new CheckHostError(`invalid host (expected a domain or IP): ${target}`)
  }

  // Resolve to an IP and enforce the SSRF guard before touching the network.
  let resolvedIp: string | null = null
  let dns: CheckHostResult['dns']
  if (isIp) {
    resolvedIp = t
    dns = { a: [t], aaaa: [], cname: [], ns: [] }
  } else {
    try {
      const records = await resolveDns(t)
      resolvedIp = records.a[0] ?? records.aaaa[0] ?? null
      dns = { a: records.a, aaaa: records.aaaa, cname: records.cname, ns: records.ns }
    } catch (err) {
      dns = { error: err instanceof Error ? err.message : String(err) }
    }
  }

  if (resolvedIp && isInternalIp(resolvedIp)) {
    throw new CheckHostError(`refusing to check an internal/private address (${resolvedIp})`)
  }
  if (!resolvedIp) {
    return {
      target: t,
      resolvedIp: null,
      dns,
      ping: { available: true, alive: false, transmitted: null, received: null, lossPct: null, rttMs: null, error: 'host did not resolve' },
      tcp: [],
      http: null,
    }
  }

  const portList = (ports && ports.length ? ports : DEFAULT_PORTS)
    .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
    .slice(0, MAX_PORTS)

  const [ping, tcp, probe] = await Promise.all([
    icmpPing(resolvedIp),
    Promise.all(portList.map((p) => tcpConnect(resolvedIp!, p))),
    probeHost(t).catch(() => null),
  ])

  return {
    target: t,
    resolvedIp,
    dns,
    ping,
    tcp,
    http: probe ? { scheme: probe.scheme, status: probe.status, title: probe.title, server: probe.server, url: probe.url } : null,
  }
}
