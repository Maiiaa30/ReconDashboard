import { useEffect, useState, type ReactNode } from 'react'
import { api, ApiError, type Finding, type FindingLink, type FindingStatus } from '../../api'
import { useApp } from '../../state'
import { Badge, Button } from '../../components/ui'
import { useToast } from '../../components/Toast'
import { useConfirm } from '../../components/Confirm'
import { summarizeFinding, timeAgo } from '../../lib/format'
import { safeHttpUrl } from '../../lib/url'
import { setPendingReplay } from '../../lib/replayHandoff'
import { TYPE_LABEL } from './constants'

function Detail({ label, value }: { label: string; value: ReactNode }) {
  if (value == null || value === '' || (Array.isArray(value) && value.length === 0)) return null
  return (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 text-xs uppercase tracking-wide text-zinc-600">{label}</span>
      <span className="min-w-0 break-all text-zinc-300">{value}</span>
    </div>
  )
}

// "Why this score" — the scorer's reasons, stored on the finding data.
function ScoreReasons({ score, reasons }: { score: number | null; reasons: unknown }) {
  if (!Array.isArray(reasons) || reasons.length === 0) return null
  return (
    <div className="rounded-lg border border-hair bg-ink-900/60 p-2.5">
      <div className="mb-1.5 text-xs uppercase tracking-wide text-zinc-500">
        Why this scored {score ?? '—'}
      </div>
      <ul className="space-y-1">
        {(reasons as string[]).map((r, i) => (
          <li key={i} className="flex gap-2 text-xs text-zinc-300">
            <span className="text-accent-400">•</span>
            <span>{r}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

interface CveLike { cve_id: string; summary?: string; cvss?: number; cvss_v3?: number; kev?: boolean }

function CveList({ cves, vulns }: { cves: unknown; vulns: unknown }) {
  const list: CveLike[] = Array.isArray(cves) && cves.length
    ? (cves as CveLike[])
    : Array.isArray(vulns)
      ? (vulns as string[]).map((id) => ({ cve_id: id }))
      : []
  if (!list.length) return null
  return (
    <div>
      <div className="mb-1 text-xs uppercase tracking-wide text-zinc-600">CVEs ({list.length})</div>
      <div className="space-y-1">
        {list.map((c) => {
          const cvss = c.cvss_v3 ?? c.cvss
          const tone = cvss == null ? 'zinc' : cvss >= 9 ? 'red' : cvss >= 7 ? 'amber' : cvss >= 4 ? 'blue' : 'zinc'
          return (
            <div key={c.cve_id} className="flex flex-wrap items-center gap-2 text-xs">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve_id)}`}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-sky-400 hover:underline"
              >
                {c.cve_id}
              </a>
              {cvss != null && <Badge tone={tone}>CVSS {cvss}</Badge>}
              {c.kev && <Badge tone="red">KEV — exploited</Badge>}
              {c.summary && <span className="min-w-0 flex-1 truncate text-zinc-500">{c.summary}</span>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function NoteEditor({ f, onUpdate }: { f: Finding; onUpdate: (id: number, patch: { note?: string | null }) => void }) {
  const [note, setNote] = useState(f.note ?? '')
  const dirty = note !== (f.note ?? '')
  return (
    <div className="space-y-1">
      <span className="text-xs uppercase tracking-wide text-zinc-600">Triage note</span>
      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="why confirmed / false-positive, repro steps, links…"
        rows={2}
        className="block w-full rounded-lg border border-hair bg-ink-950 px-2.5 py-1.5 text-sm outline-none focus:border-accent-500"
      />
      {dirty && (
        <div className="flex gap-1.5">
          <Button variant="loud" className="px-2 py-1 text-xs" onClick={() => onUpdate(f.id, { note: note.trim() || null })}>
            Save note
          </Button>
          <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => setNote(f.note ?? '')}>
            Reset
          </Button>
        </div>
      )}
    </div>
  )
}

// Verify a passively-observed CVE by running its nuclei template (loud, gated).
// Surfaces the last verification outcome and, since the scan is loud, confirms
// first on a passive domain — the server enforces the same gate regardless.
function CveVerifyButton({ f }: { f: Finding }) {
  const { domains } = useApp()
  const ask = useConfirm()
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const d = (f.data ?? {}) as Record<string, any>
  const cveId: string | undefined = typeof d.cveId === 'string' ? d.cveId : undefined
  const verified = d.verified as { result?: string; at?: string; matchedAt?: string } | undefined
  const domain = domains.find((x) => x.id === f.domainId)
  const active = domain?.mode === 'active_authorized'
  // A scannable hostname (an IP-only asset can't be verified until it has one).
  const hostnames: string[] = Array.isArray(d.hostnames) ? d.hostnames : []
  const target = hostnames.find((h) => /[a-z]/i.test(h)) ?? (typeof d.host === 'string' && /[a-z]/i.test(d.host) ? d.host : undefined)

  if (!cveId || f.domainId == null) return null

  async function run() {
    if (f.domainId == null || !cveId) return
    if (!target) {
      toast.error('No scannable hostname for this CVE (IP-only asset).')
      return
    }
    if (!active) {
      const ok = await ask({
        title: 'Verify this CVE?',
        message: `Running the nuclei template for ${cveId} against ${target} is a LOUD, active scan. Only proceed if you are authorized to actively test this target.`,
        confirmLabel: 'Run anyway',
        tone: 'danger',
      })
      if (!ok) return
    }
    setBusy(true)
    try {
      await api.verifyCve(f.domainId, {
        cveId,
        target,
        ip: typeof d.ip === 'string' ? d.ip : undefined,
        kev: d.kev === true,
        confirm: !active,
      })
      toast.success(`Verifying ${cveId} — watch Logs for the result.`)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'failed to enqueue verification')
    } finally {
      setBusy(false)
    }
  }

  const verdictTone =
    verified?.result === 'confirmed' ? 'red' : verified?.result === 'no_template' ? 'amber' : verified?.result ? 'zinc' : 'zinc'
  const verdictLabel =
    verified?.result === 'confirmed'
      ? 'Confirmed exploitable'
      : verified?.result === 'not_reproduced'
        ? 'Not reproduced (presence-only)'
        : verified?.result === 'no_template'
          ? 'No nuclei template'
          : null

  return (
    <div className="mt-1 flex flex-wrap items-center gap-2">
      <Button variant="loud" className="px-2 py-1 text-xs" disabled={busy} onClick={run}>
        {busy ? 'Queuing…' : active ? 'Verify with nuclei' : 'Verify with nuclei (confirm)'}
      </Button>
      {verdictLabel && <Badge tone={verdictTone as any}>{verdictLabel}</Badge>}
      {!target && <span className="text-xs text-zinc-500">no scannable hostname</span>}
    </div>
  )
}

// The most useful URL to pivot on for a given finding (null if it has none).
function findingUrl(f: Finding): string | null {
  const d = (f.data ?? {}) as Record<string, any>
  if (f.type === 'param' || f.type === 'owasp' || f.type === 'ffuf') return typeof d.url === 'string' ? d.url : null
  if (f.type === 'nuclei') return d.matched || d.url || null
  if (f.type === 'api') return d.endpoint || d.specUrl || (d.host ? `https://${d.host}/` : null)
  return typeof d.url === 'string' ? d.url : null
}

// Put a {{P1}} Intruder marker on `param`'s value in the URL (adding it if absent).
function markParamUrl(rawUrl: string, param: string): string {
  try {
    const u = new URL(rawUrl)
    u.searchParams.set(param, 'RECONMARK')
    return u.toString().replace('RECONMARK', '{{P1}}')
  } catch {
    return rawUrl
  }
}

// Pivot from a URL-bearing finding straight into the Repeater or Intruder.
function FindingPivots({ f, navigate }: { f: Finding; navigate?: (page: string, domainId?: number) => void }) {
  const url = findingUrl(f)
  if (!url || !navigate) return null
  const d = (f.data ?? {}) as Record<string, any>
  const send = (mode: 'repeater' | 'intruder', u: string) => {
    setPendingReplay({ method: 'GET', url: u, headers: [], mode })
    navigate('replay')
  }
  const intruderUrl = f.type === 'param' && typeof d.param === 'string' ? markParamUrl(url, d.param) : url
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => send('repeater', url)}>
        Open in Repeater
      </Button>
      <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => send('intruder', intruderUrl)}>
        Send to Intruder{f.type === 'param' && d.param ? ` (mark ${d.param})` : ''}
      </Button>
    </div>
  )
}

const LINK_LABEL: Record<FindingLink['kind'], { out: string; in: string }> = {
  confirms: { out: 'Confirms', in: 'Confirmed by' },
  evidence_for: { out: 'Evidence for', in: 'Has evidence' },
  same_asset: { out: 'Same asset as', in: 'Same asset as' },
  chained_from: { out: 'Chained from', in: 'Chains to' },
}

// Related findings (e.g. the nuclei PoC that confirms a CVE) via finding_links —
// a queryable edge, not a naming-convention guess. Fetches when the detail opens.
function LinkedFindings({ id }: { id: number }) {
  const [links, setLinks] = useState<FindingLink[]>([])
  useEffect(() => {
    api.findingLinks(id).then((r) => setLinks(r.links)).catch(() => {})
  }, [id])
  if (!links.length) return null
  return (
    <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/15 p-2 text-xs">
      <div className="mb-1 uppercase tracking-wide text-emerald-300/80">Linked findings</div>
      <ul className="space-y-1">
        {links.map((l, i) => (
          <li key={i} className="flex flex-wrap items-center gap-1.5 text-zinc-300">
            <Badge tone="green">{l.direction === 'outgoing' ? LINK_LABEL[l.kind].out : LINK_LABEL[l.kind].in}</Badge>
            <span className="text-zinc-400">{TYPE_LABEL[l.finding.type] ?? l.finding.type}</span>
            <span className="min-w-0 break-all font-mono">{summarizeFinding(l.finding.type, l.finding.data)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function FindingDetail({
  f,
  onUpdate,
  onRetest,
  navigate,
}: {
  f: Finding
  onUpdate: (id: number, patch: { status?: FindingStatus; note?: string | null }) => void
  onRetest?: (id: number) => void
  navigate?: (page: string, domainId?: number) => void
}) {
  const d = f.data ?? {}
  return (
    <div className="space-y-3 border-t border-hair/60 bg-ink-900/50 p-3 text-sm">
      <ScoreReasons score={f.score} reasons={d._scoreReasons} />
      <div className="space-y-1">
        {f.type === 'new_subdomain' && (
          <>
            <Detail label="Host" value={<span className="font-mono">{d.host}</span>} />
            <Detail label="HTTP" value={d.status != null ? `${d.status}` : 'no response'} />
            <Detail label="Title" value={d.title} />
            <Detail label="Server" value={d.server} />
            <Detail label="IP" value={<span className="font-mono">{d.ip}</span>} />
            <Detail label="CNAMEs" value={Array.isArray(d.cnames) && d.cnames.length ? d.cnames.join(', ') : null} />
            {d.takeover?.service && (
              <Detail label="Takeover" value={<span className="text-red-400">candidate: {d.takeover.service} ({d.takeover.cname})</span>} />
            )}
            {d.status != null && d.scheme && (
              <Detail
                label="Open"
                value={
                  <a href={safeHttpUrl(`${d.scheme}://${d.host}`)} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">
                    {d.scheme}://{d.host} ↗
                  </a>
                }
              />
            )}
          </>
        )}
        {f.type === 'exposure' && (
          <>
            <Detail label="IP" value={<span className="font-mono">{d.ip}</span>} />
            <Detail label="Hostnames" value={Array.isArray(d.hostnames) ? d.hostnames.join(', ') : null} />
            <Detail label="Ports" value={Array.isArray(d.ports) ? d.ports.join(', ') : null} />
            <Detail label="CPEs" value={Array.isArray(d.cpes) ? d.cpes.join(', ') : null} />
            <CveList cves={d.cves} vulns={d.vulns} />
          </>
        )}
        {f.type === 'origin' && (
          <>
            <Detail label="WAF/CDN" value={d.provider ?? 'none'} />
            <Detail label="Apex IP" value={<span className="font-mono">{d.apexIp}</span>} />
            <Detail
              label="Origins"
              value={(d.confirmedOrigins ?? []).map((o: any) => o.ip).join(', ') || null}
            />
          </>
        )}
        {(f.type === 'nuclei' || f.type === 'nmap' || f.type === 'ffuf' || f.type === 'osint') && (
          <>
            <Detail label="Target" value={<span className="font-mono">{d.target ?? d.domain}</span>} />
            <Detail label="Name" value={d.name} />
            <Detail label="Severity" value={d.severity} />
            <Detail label="Matched" value={d.matched ? <span className="font-mono">{d.matched}</span> : null} />
            <Detail label="URL" value={d.url ? <span className="font-mono">{d.url}</span> : null} />
          </>
        )}
        {f.type === 'cve_new' && (
          <>
            <Detail label="Asset" value={<span className="font-mono">{d.host} ({d.ip})</span>} />
            <Detail
              label="CVE"
              value={
                d.cveId ? (
                  <a href={safeHttpUrl(`https://nvd.nist.gov/vuln/detail/${d.cveId}`)} target="_blank" rel="noreferrer" className="font-mono text-sky-400 hover:underline">
                    {d.cveId} ↗
                  </a>
                ) : null
              }
            />
            <Detail label="CVSS" value={d.cvss != null ? `${d.cvss}` : null} />
            {d.kev && <Detail label="KEV" value={<span className="text-red-400">Known exploited in the wild</span>} />}
            <CveVerifyButton f={f} />
          </>
        )}
      </div>
      <LinkedFindings id={f.id} />
      <FindingPivots f={f} navigate={navigate} />

      {/* Retest / remediation: mark a confirmed finding for retest; it auto-reopens
          to confirmed if a later scan re-detects it, and the operator marks it
          "Retest passed" (via the status control) once verified fixed. */}
      {f.status === 'retest_pending' && f.retestRequestedAt ? (
        <div className="rounded-lg border border-amber-900/40 bg-amber-950/15 p-2 text-xs text-amber-200/90">
          Awaiting retest — marked {timeAgo(new Date(f.retestRequestedAt).getTime())}. Re-run the scan that would
          detect it: if it reappears this auto-flips back to <span className="font-medium">confirmed</span>; set the
          status to <span className="font-medium">Retest passed</span> once you&apos;ve verified it&apos;s fixed.
        </div>
      ) : f.status === 'confirmed' && onRetest ? (
        <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => onRetest(f.id)} title="Mark this finding for retest (awaiting re-scan)">
          Mark for retest
        </Button>
      ) : null}

      <NoteEditor f={f} onUpdate={onUpdate} />

      <details>
        <summary className="cursor-pointer text-xs text-zinc-500 hover:text-zinc-300">raw data</summary>
        <pre className="mt-1 max-h-72 overflow-auto whitespace-pre-wrap break-all text-xs text-zinc-400">
          {JSON.stringify(f.data, null, 2)}
        </pre>
      </details>
    </div>
  )
}
