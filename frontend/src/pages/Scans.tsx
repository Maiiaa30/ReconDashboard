import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { api, ApiError, type Finding, type MetaStatus } from '../api'
import { useApp, useHosts, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, ScoreBadge } from '../components/ui'
import { useConfirm } from '../components/Confirm'
import { useToast } from '../components/Toast'
import { timeAgo } from '../lib/format'

type Scheme = 'https' | 'http'

// Common nuclei template-tag presets — the high-signal categories an operator
// reaches for most. Clicking toggles them into the tags field.
const NUCLEI_TAG_PRESETS = ['cve', 'exposure', 'misconfig', 'takeover', 'default-login', 'tech', 'panel', 'xss', 'sqli', 'lfi', 'rce']

interface ScanResult {
  jobId: number | null
  error: string | null
}
const emptyResult: ScanResult = { jobId: null, error: null }

function SchemeSelect({ value, onChange }: { value: Scheme; onChange: (v: Scheme) => void }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as Scheme)}
      className="mt-1 block rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
    >
      <option value="https">https</option>
      <option value="http">http</option>
    </select>
  )
}

function ResultLine({ result }: { result: ScanResult }) {
  if (result.error) return <p className="mt-2 text-sm text-red-400">{result.error}</p>
  if (result.jobId != null)
    return <p className="mt-2 text-sm text-green-400">queued job #{result.jobId} — see Logs tab</p>
  return null
}

export function Scans() {
  const { selected } = useApp()
  const ask = useConfirm()
  const toast = useToast()
  const hosts = useHosts(selected)
  const [meta, setMeta] = useState<MetaStatus | null>(null)
  const [target, setTarget] = useState('')

  const [ports, setPorts] = useState('')
  const [nmapResult, setNmapResult] = useState<ScanResult>(emptyResult)
  const [nmapBusy, setNmapBusy] = useState(false)
  const [sweepBusy, setSweepBusy] = useState(false)

  const [severity, setSeverity] = useState('')
  const [nucleiTags, setNucleiTags] = useState('')
  const [nucleiScheme, setNucleiScheme] = useState<Scheme>('https')
  const [nucleiResult, setNucleiResult] = useState<ScanResult>(emptyResult)
  const [nucleiBusy, setNucleiBusy] = useState(false)

  const [path, setPath] = useState('FUZZ')
  const [wordlist, setWordlist] = useState('')
  const [ffufScheme, setFfufScheme] = useState<Scheme>('https')
  const [ffufResult, setFfufResult] = useState<ScanResult>(emptyResult)
  const [ffufBusy, setFfufBusy] = useState(false)

  const [results, setResults] = useState<Finding[]>([])

  const loadMeta = useCallback(() => {
    api.meta().then(setMeta).catch(() => {})
  }, [])
  usePoll(loadMeta, 60000, meta == null)

  // Poll nmap + nuclei findings for the selected domain so results show right
  // here instead of only on the Logs/Findings pages.
  const selectedId = selected?.id ?? null
  const loadResults = useCallback(() => {
    if (selectedId == null) return
    Promise.all([
      api.findings({ domainId: selectedId, type: 'nmap', limit: 50 }),
      api.findings({ domainId: selectedId, type: 'nuclei', limit: 100 }),
    ])
      .then(([a, b]) =>
        setResults(
          [...a.findings, ...b.findings].sort(
            (x, y) => new Date(y.createdAt).getTime() - new Date(x.createdAt).getTime(),
          ),
        ),
      )
      .catch(() => {})
  }, [selectedId])
  usePoll(loadResults, 5000, selectedId != null)

  useEffect(() => {
    setTarget(selected?.host ?? '')
  }, [selected])

  if (!selected) return <Empty>Select a domain to run scans.</Empty>

  const active = selected.mode === 'active_authorized'

  // Run a scan. On a passive_only domain, warn and require confirmation first,
  // then run with confirm:true (the server enforces the same gate).
  async function run(
    toolName: string,
    setBusy: (b: boolean) => void,
    setResult: (r: ScanResult) => void,
    call: (confirm: boolean) => Promise<{ jobId: number }>,
  ): Promise<void> {
    if (!selected) return
    if (!active) {
      const ok = await ask({
        title: 'Run a loud scan?',
        message: `${selected.host} is passive_only.\n\n${toolName} is a LOUD, active scan. Only run it against ${target} if you are authorized to actively test this target.`,
        confirmLabel: 'Run anyway',
        tone: 'danger',
      })
      if (!ok) return
    }
    setBusy(true)
    setResult(emptyResult)
    try {
      const { jobId } = await call(!active)
      setResult({ jobId, error: null })
    } catch (err) {
      setResult({ jobId: null, error: err instanceof ApiError ? err.message : 'scan failed to enqueue' })
    } finally {
      setBusy(false)
    }
  }

  const nmapInstalled = meta?.tools.nmap ?? false
  const nucleiInstalled = meta?.tools.nuclei ?? false
  const ffufInstalled = meta?.tools.ffuf ?? false
  const runLabel = (busy: boolean, name: string) => (busy ? 'Queuing…' : active ? `Run ${name}` : `Run ${name} (confirm)`)

  return (
    <div>
      <PageHeader
        title="Scans"
        subtitle={`${selected.host} — active / loud tooling`}
        actions={<Badge tone="amber">LOUD / ACTIVE</Badge>}
      />

      {!active && (
        <Card className="mb-4 border-amber-900/60 bg-amber-950/20">
          <div className="mb-1 flex items-center gap-2">
            <Badge tone="amber">passive_only</Badge>
            <span className="text-sm font-medium text-amber-200">This domain is passive — scans need confirmation</span>
          </div>
          <p className="text-sm text-amber-200/80">
            nmap, nuclei and ffuf are loud. You can run them here after a confirmation prompt, but only against a
            target you are authorized to actively test. Set the domain to{' '}
            <span className="font-mono">active_authorized</span> in Domains to skip the prompt.
          </p>
        </Card>
      )}

      {/* Shared target host */}
      <Card className="mb-4">
        <label className="text-sm">
          <span className="text-zinc-400">Target host</span>
          <select
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="mt-1 block w-72 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-accent-500"
          >
            {hosts.length === 0 && <option value={selected.host}>{selected.host}</option>}
            {hosts.map((h) => (
              <option key={h.host} value={h.host}>
                {h.host}
                {h.live ? ' • live' : ''}
              </option>
            ))}
          </select>
        </label>
        <p className="mt-1 text-xs text-zinc-600">Pick the apex or any discovered subdomain to scan.</p>
      </Card>

      <div className="space-y-4">
        {/* nmap */}
        <Card>
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-zinc-200">nmap</h2>
            {!nmapInstalled && meta && <span className="text-xs text-zinc-500">nmap not installed in this image</span>}
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="text-zinc-400">Ports</span>
              <input
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder="top-100 if blank, e.g. 80,443,8000-8100"
                className="mt-1 block w-72 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-accent-500"
              />
            </label>
            <Button
              variant="loud"
              disabled={!nmapInstalled || nmapBusy || !target}
              onClick={() => run('nmap', setNmapBusy, setNmapResult, (confirm) => api.nmap(selected.id, { target, ports: ports || undefined, confirm }))}
            >
              {runLabel(nmapBusy, 'nmap')}
            </Button>
            <Button
              variant="ghost"
              disabled={!nmapInstalled || nmapBusy || !target}
              title="Full sweep: all 65535 ports + service/version + default NSE scripts (TLS certs, HTTP titles/headers…) + OS detection when privileged. Ignores the Ports field. Much slower."
              onClick={async () => {
                const ok = await ask({
                  title: 'Start deep scan?',
                  message:
                    `Deep scan probes ALL 65,535 ports with version detection + NSE scripts on ${target}.\n\n` +
                    `It is far slower than a normal scan — expect several minutes (up to ~15 min before nmap stops itself). The Ports field is ignored.`,
                  confirmLabel: 'Start deep scan',
                })
                if (!ok) return
                run('nmap (deep)', setNmapBusy, setNmapResult, (confirm) => api.nmap(selected.id, { target, deep: true, confirm }))
              }}
            >
              {nmapBusy ? 'Queuing…' : 'Deep scan'}
            </Button>
            <Button
              variant="ghost"
              disabled={!nmapInstalled || sweepBusy}
              title="Attack-surface sweep: queue an nmap scan for every live host of this domain (apex + discovered subdomains), deduped by IP. Uses the quick top-1000 scan per host."
              onClick={async () => {
                const ok = await ask({
                  title: 'Scan all live hosts?',
                  message:
                    `Queue an nmap scan for every live host of ${selected.host} — the apex plus discovered subdomains that resolved to an IP, deduped so a shared IP is scanned once.\n\n` +
                    `This can enqueue many loud scans that run one after another. Watch Logs for progress.`,
                  confirmLabel: 'Scan all hosts',
                  tone: active ? 'default' : 'danger',
                })
                if (!ok) return
                setSweepBusy(true)
                try {
                  const r = await api.nmapSweep(selected.id, { confirm: !active })
                  if (r.queued === 0) {
                    toast.info(
                      `No live hosts to scan${r.skipped.length ? ` — ${r.skipped.length} skipped` : ''}. Run discovery first.`,
                    )
                  } else {
                    toast.success(
                      `Queued ${r.queued} host scan${r.queued === 1 ? '' : 's'}` +
                        (r.skipped.length ? ` · ${r.skipped.length} skipped` : '') +
                        (r.capped ? ' · capped at 50' : ''),
                    )
                  }
                } catch (err) {
                  toast.error(err instanceof ApiError ? err.message : 'sweep failed to enqueue')
                } finally {
                  setSweepBusy(false)
                }
              }}
            >
              {sweepBusy ? 'Queuing…' : 'Scan all live hosts'}
            </Button>
          </div>
          <div className="mt-2 flex items-start gap-2 rounded-lg border border-amber-900/50 bg-amber-950/20 px-3 py-2 text-xs text-amber-200/90">
            <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-400" />
            <span>
              <span className="font-semibold">Deep scan is slow.</span> It sweeps all 65,535 ports with version detection + NSE
              scripts (and OS detection if the server runs privileged), so it can take several minutes versus seconds for a
              normal scan. It ignores the Ports field and runs in the background — watch Logs for progress.
            </span>
          </div>
          <ResultLine result={nmapResult} />
        </Card>

        {/* nuclei */}
        <Card>
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-zinc-200">nuclei</h2>
            {!nucleiInstalled && meta && <span className="text-xs text-zinc-500">nuclei not installed in this image</span>}
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="text-zinc-400">Severity</span>
              <input
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                placeholder="e.g. medium,high,critical"
                className="mt-1 block w-56 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-accent-500"
              />
            </label>
            <label className="text-sm">
              <span className="text-zinc-400">Template tags</span>
              <input
                value={nucleiTags}
                onChange={(e) => setNucleiTags(e.target.value)}
                placeholder="cve,exposure,misconfig"
                className="mt-1 block w-64 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-accent-500"
              />
            </label>
            <label className="text-sm">
              <span className="text-zinc-400">Scheme</span>
              <SchemeSelect value={nucleiScheme} onChange={setNucleiScheme} />
            </label>
            <Button
              variant="loud"
              disabled={!nucleiInstalled || nucleiBusy || !target}
              onClick={() => run('nuclei', setNucleiBusy, setNucleiResult, (confirm) => api.nuclei(selected.id, { target, severity: severity || undefined, tags: nucleiTags || undefined, scheme: nucleiScheme, confirm }))}
            >
              {runLabel(nucleiBusy, 'nuclei')}
            </Button>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-zinc-500">presets:</span>
            {NUCLEI_TAG_PRESETS.map((t) => {
              const on = nucleiTags.split(',').map((x) => x.trim()).includes(t)
              return (
                <button
                  key={t}
                  type="button"
                  onClick={() =>
                    setNucleiTags((cur) => {
                      const list = cur.split(',').map((x) => x.trim()).filter(Boolean)
                      return on ? list.filter((x) => x !== t).join(',') : [...list, t].join(',')
                    })
                  }
                  className={`rounded-full px-2.5 py-0.5 text-xs transition ${
                    on ? 'bg-accent-500/20 text-accent-fg ring-1 ring-accent-500/30' : 'border border-hair text-zinc-400 hover:bg-ink-800'
                  }`}
                >
                  {t}
                </button>
              )
            })}
          </div>
          <p className="mt-2 text-xs text-zinc-500">
            Tags pick which nuclei templates run (e.g. <span className="font-mono">cve</span>,{' '}
            <span className="font-mono">exposure</span>, <span className="font-mono">takeover</span>). Leave blank for the full default set.
          </p>
          <ResultLine result={nucleiResult} />
        </Card>

        {/* ffuf */}
        <Card>
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-zinc-200">ffuf</h2>
            {!ffufInstalled && meta && <span className="text-xs text-zinc-500">ffuf not installed in this image</span>}
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="text-zinc-400">Path</span>
              <input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="FUZZ"
                className="mt-1 block w-44 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-accent-500"
              />
            </label>
            <label className="text-sm">
              <span className="text-zinc-400">Wordlist</span>
              <select
                value={wordlist}
                onChange={(e) => setWordlist(e.target.value)}
                className="mt-1 block w-64 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
              >
                <option value="">default (common.txt)</option>
                {(meta?.wordlists ?? []).map((w) => (
                  <option key={w.path} value={w.path}>
                    {w.name} ({w.sizeKb > 1024 ? `${(w.sizeKb / 1024).toFixed(1)}MB` : `${w.sizeKb}KB`})
                  </option>
                ))}
              </select>
            </label>
            <label className="text-sm">
              <span className="text-zinc-400">Scheme</span>
              <SchemeSelect value={ffufScheme} onChange={setFfufScheme} />
            </label>
            <Button
              variant="loud"
              disabled={!ffufInstalled || ffufBusy || !target || !path.includes('FUZZ')}
              onClick={() => run('ffuf', setFfufBusy, setFfufResult, (confirm) => api.ffuf(selected.id, { target, path: path || 'FUZZ', wordlist: wordlist || undefined, scheme: ffufScheme, confirm }))}
            >
              {runLabel(ffufBusy, 'ffuf')}
            </Button>
          </div>
          <p className="mt-2 text-xs text-zinc-500">Path must contain FUZZ.</p>
          <ResultLine result={ffufResult} />
        </Card>
      </div>

      {/* Live results — nmap + nuclei findings for this domain */}
      <div className="mt-8 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-zinc-200">
          Scan results <span className="text-zinc-500">— {selected.host} ({results.length})</span>
        </h2>
        <span className="text-xs text-zinc-600">auto-refreshing · full history in Findings</span>
      </div>
      {results.length === 0 ? (
        <Empty>No nmap/nuclei results yet for {selected.host}. Run a scan above — findings appear here live.</Empty>
      ) : (
        <div className="mt-3 space-y-2">
          {results.map((f) => (
            <ScanResultCard key={f.id} f={f} />
          ))}
        </div>
      )}
    </div>
  )
}

function sevTone(sev: unknown): 'zinc' | 'green' | 'amber' | 'red' | 'blue' {
  switch (String(sev ?? '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'red'
    case 'medium':
      return 'amber'
    case 'low':
      return 'blue'
    default:
      return 'zinc'
  }
}

interface NmapPort {
  port: number
  protocol?: string
  state?: string
  service?: string | null
  product?: string | null
  version?: string | null
  extrainfo?: string | null
  scripts?: { id: string; output: string }[]
}

// Renders an nmap or nuclei finding with type-appropriate detail (open ports as
// chips; nuclei severity + matched URL). Deep nmap scans also show OS guesses,
// service versions and NSE script output.
function ScanResultCard({ f }: { f: Finding }) {
  const d = f.data ?? {}
  const isNmap = f.type === 'nmap'
  const ports: NmapPort[] = Array.isArray(d.openPorts) ? d.openPorts : []
  const allPorts: NmapPort[] = Array.isArray(d.allPorts) ? d.allPorts : ports
  const os: { name: string; accuracy: number }[] = Array.isArray(d.os) ? d.os : []
  const hostScripts: { id: string; output: string }[] = Array.isArray(d.hostScripts) ? d.hostScripts : []
  const deep = d.deep === true
  const filteredCount = allPorts.filter((p) => p.state === 'filtered').length
  // Every port that carries version or script detail worth expanding.
  const detailPorts = allPorts.filter((p) => p.product || p.version || (p.scripts && p.scripts.length))
  const hasDetail = detailPorts.length > 0 || hostScripts.length > 0

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <ScoreBadge score={f.score} />
        <Badge tone="indigo">{f.type}</Badge>
        {isNmap && deep && <Badge tone="purple">deep</Badge>}
        {!isNmap && <Badge tone={sevTone(d.severity)}>{String(d.severity ?? 'info')}</Badge>}
        <span className="text-sm font-medium text-zinc-100">
          {isNmap
            ? `${d.target ?? ''} · ${ports.length} open${filteredCount ? ` · ${filteredCount} filtered` : ''}`
            : String(d.name ?? d.templateId ?? 'nuclei match')}
        </span>
        <span className="font-mono text-xs text-zinc-500 break-all">
          {isNmap ? '' : String(d.matched ?? d.target ?? '')}
        </span>
        <span className="ml-auto text-xs text-zinc-500">{timeAgo(new Date(f.createdAt).getTime())}</span>
      </div>

      {/* OS fingerprint guesses (deep scans, privileged runs) */}
      {isNmap && os.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-zinc-500">OS:</span>
          {os.map((o, i) => (
            <Badge key={i} tone="blue">
              {o.name}
              {o.accuracy ? ` ${o.accuracy}%` : ''}
            </Badge>
          ))}
        </div>
      )}

      {/* Open-port chips */}
      {isNmap && ports.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {ports.map((p, i) => (
            <span
              key={i}
              className="rounded bg-ink-800/70 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300"
              title={[p.product, p.version, p.extrainfo].filter(Boolean).join(' ') || undefined}
            >
              {p.port}
              {p.service ? `/${p.service}` : ''}
            </span>
          ))}
        </div>
      )}

      {/* Deep detail: per-port versions + NSE script output */}
      {isNmap && hasDetail && (
        <details className="mt-2">
          <summary className="cursor-pointer text-xs text-zinc-500 hover:text-zinc-300">
            Service &amp; script detail ({detailPorts.length + hostScripts.length})
          </summary>
          <div className="mt-2 space-y-2">
            {detailPorts.map((p, i) => (
              <div key={i} className="rounded-lg border border-hair/60 bg-ink-900/50 p-2">
                <div className="font-mono text-xs text-zinc-200">
                  {p.port}/{p.protocol ?? 'tcp'}
                  {p.service ? ` ${p.service}` : ''}
                  <span className="text-zinc-400">
                    {' '}
                    {[p.product, p.version, p.extrainfo && `(${p.extrainfo})`].filter(Boolean).join(' ')}
                  </span>
                </div>
                {(p.scripts ?? []).map((s, j) => (
                  <div key={j} className="mt-1">
                    <div className="text-[10px] uppercase tracking-wide text-zinc-600">{s.id}</div>
                    <pre className="mt-0.5 max-h-40 overflow-auto whitespace-pre-wrap break-all text-[11px] text-zinc-400">
                      {s.output}
                    </pre>
                  </div>
                ))}
              </div>
            ))}
            {hostScripts.map((s, i) => (
              <div key={`h${i}`} className="rounded-lg border border-hair/60 bg-ink-900/50 p-2">
                <div className="text-[10px] uppercase tracking-wide text-zinc-600">host · {s.id}</div>
                <pre className="mt-0.5 max-h-40 overflow-auto whitespace-pre-wrap break-all text-[11px] text-zinc-400">
                  {s.output}
                </pre>
              </div>
            ))}
          </div>
        </details>
      )}
    </Card>
  )
}
