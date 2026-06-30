import { useCallback, useState } from 'react'
import { api, ApiError, type MetaStatus } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'

type Scheme = 'https' | 'http'

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
      className="mt-1 block rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
    >
      <option value="https">https</option>
      <option value="http">http</option>
    </select>
  )
}

function ResultLine({ result }: { result: ScanResult }) {
  if (result.error) return <p className="mt-2 text-sm text-red-400">{result.error}</p>
  if (result.jobId != null)
    return (
      <p className="mt-2 text-sm text-green-400">
        queued job #{result.jobId} — see Jobs tab
      </p>
    )
  return null
}

export function Scans() {
  const { selected } = useApp()
  const [meta, setMeta] = useState<MetaStatus | null>(null)

  // nmap state
  const [ports, setPorts] = useState('')
  const [nmapResult, setNmapResult] = useState<ScanResult>(emptyResult)
  const [nmapBusy, setNmapBusy] = useState(false)

  // nuclei state
  const [severity, setSeverity] = useState('')
  const [nucleiScheme, setNucleiScheme] = useState<Scheme>('https')
  const [nucleiResult, setNucleiResult] = useState<ScanResult>(emptyResult)
  const [nucleiBusy, setNucleiBusy] = useState(false)

  // ffuf state
  const [path, setPath] = useState('FUZZ')
  const [wordlist, setWordlist] = useState('')
  const [ffufScheme, setFfufScheme] = useState<Scheme>('https')
  const [ffufResult, setFfufResult] = useState<ScanResult>(emptyResult)
  const [ffufBusy, setFfufBusy] = useState(false)

  const loadMeta = useCallback(() => {
    api
      .meta()
      .then(setMeta)
      .catch(() => {})
  }, [])

  // Fetch meta once (poll is inactive after first run; usePoll fires immediately).
  usePoll(loadMeta, 60000, meta == null)

  if (!selected) return <Empty>Select a domain to run scans.</Empty>

  const active = selected.mode === 'active_authorized'

  async function run(
    setBusy: (b: boolean) => void,
    setResult: (r: ScanResult) => void,
    call: () => Promise<{ jobId: number }>,
  ): Promise<void> {
    setBusy(true)
    setResult(emptyResult)
    try {
      const { jobId } = await call()
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

  return (
    <div>
      <PageHeader
        title="Scans"
        subtitle={`${selected.host} — active / loud tooling`}
        actions={<Badge tone="amber">LOUD / ACTIVE</Badge>}
      />

      {!active && (
        <Card className="mb-6 border-amber-900/60 bg-amber-950/30">
          <div className="mb-1 flex items-center gap-2">
            <Badge tone="amber">disabled</Badge>
            <span className="text-sm font-medium text-amber-200">
              Active scans are disabled for passive_only domains
            </span>
          </div>
          <p className="text-sm text-amber-200/80">
            nmap, nuclei and ffuf are loud, active scans. The operator must mark{' '}
            <span className="font-mono">{selected.host}</span> as{' '}
            <span className="font-mono">active_authorized</span> (in the Domains tab) — and only for a
            target you are authorized to actively test — before running these.
          </p>
        </Card>
      )}

      <div className="space-y-4">
        {/* nmap */}
        <Card>
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-zinc-200">nmap</h2>
            {!nmapInstalled && meta && (
              <span className="text-xs text-zinc-500">nmap not installed in this image</span>
            )}
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="text-zinc-400">Ports</span>
              <input
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder="top-100 if blank, e.g. 80,443,8000-8100"
                className="mt-1 block w-72 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-zinc-500"
              />
            </label>
            <Button
              variant="loud"
              disabled={!active || !nmapInstalled || nmapBusy}
              onClick={() =>
                run(setNmapBusy, setNmapResult, () => api.nmap(selected.id, ports || undefined))
              }
            >
              {nmapBusy ? 'Queuing…' : 'Run nmap'}
            </Button>
          </div>
          <ResultLine result={nmapResult} />
        </Card>

        {/* nuclei */}
        <Card>
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-zinc-200">nuclei</h2>
            {!nucleiInstalled && meta && (
              <span className="text-xs text-zinc-500">nuclei not installed in this image</span>
            )}
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="text-zinc-400">Severity</span>
              <input
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                placeholder="e.g. medium,high,critical"
                className="mt-1 block w-64 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-zinc-500"
              />
            </label>
            <label className="text-sm">
              <span className="text-zinc-400">Scheme</span>
              <SchemeSelect value={nucleiScheme} onChange={setNucleiScheme} />
            </label>
            <Button
              variant="loud"
              disabled={!active || !nucleiInstalled || nucleiBusy}
              onClick={() =>
                run(setNucleiBusy, setNucleiResult, () =>
                  api.nuclei(selected.id, severity || undefined, nucleiScheme),
                )
              }
            >
              {nucleiBusy ? 'Queuing…' : 'Run nuclei'}
            </Button>
          </div>
          <ResultLine result={nucleiResult} />
        </Card>

        {/* ffuf */}
        <Card>
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-zinc-200">ffuf</h2>
            {!ffufInstalled && meta && (
              <span className="text-xs text-zinc-500">ffuf not installed in this image</span>
            )}
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="text-zinc-400">Path</span>
              <input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="FUZZ"
                className="mt-1 block w-44 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-zinc-500"
              />
            </label>
            <label className="text-sm">
              <span className="text-zinc-400">Wordlist</span>
              <input
                value={wordlist}
                onChange={(e) => setWordlist(e.target.value)}
                placeholder="/usr/share/wordlists/common.txt"
                className="mt-1 block w-72 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 font-mono text-sm outline-none focus:border-zinc-500"
              />
            </label>
            <label className="text-sm">
              <span className="text-zinc-400">Scheme</span>
              <SchemeSelect value={ffufScheme} onChange={setFfufScheme} />
            </label>
            <Button
              variant="loud"
              disabled={!active || !ffufInstalled || ffufBusy}
              onClick={() =>
                run(setFfufBusy, setFfufResult, () =>
                  api.ffuf(selected.id, path || undefined, wordlist || undefined, ffufScheme),
                )
              }
            >
              {ffufBusy ? 'Queuing…' : 'Run ffuf'}
            </Button>
          </div>
          <p className="mt-2 text-xs text-zinc-500">Path must contain FUZZ.</p>
          <ResultLine result={ffufResult} />
        </Card>
      </div>
    </div>
  )
}
