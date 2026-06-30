import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type MetaStatus } from '../api'
import { useApp, useHosts, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'

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
  const hosts = useHosts(selected)
  const [meta, setMeta] = useState<MetaStatus | null>(null)
  const [target, setTarget] = useState('')

  const [ports, setPorts] = useState('')
  const [nmapResult, setNmapResult] = useState<ScanResult>(emptyResult)
  const [nmapBusy, setNmapBusy] = useState(false)

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

  const loadMeta = useCallback(() => {
    api.meta().then(setMeta).catch(() => {})
  }, [])
  usePoll(loadMeta, 60000, meta == null)

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
      const ok = confirm(
        `⚠ ${selected.host} is passive_only.\n\n${toolName} is a LOUD, active scan. Only run it against ${target} if you are authorized to actively test this target.\n\nRun anyway?`,
      )
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
    </div>
  )
}
