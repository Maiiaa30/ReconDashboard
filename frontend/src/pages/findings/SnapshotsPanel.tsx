import { useCallback, useEffect, useState } from 'react'
import { Camera } from 'lucide-react'
import { api, type ReportSnapshot } from '../../api'
import { Badge } from '../../components/ui'
import { useToast } from '../../components/Toast'

// Immutable report snapshots: freeze the current report as a dated, downloadable
// deliverable that never changes when findings are re-scanned.
export function SnapshotsPanel({ domainId }: { domainId: number }) {
  const toast = useToast()
  const [snaps, setSnaps] = useState<ReportSnapshot[]>([])
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [label, setLabel] = useState('')

  const load = useCallback(() => {
    api.snapshots(domainId).then((r) => setSnaps(r.snapshots)).catch(() => setSnaps([]))
  }, [domainId])
  useEffect(() => {
    load()
  }, [load])

  async function snapshot() {
    if (busy) return
    setBusy(true)
    try {
      await api.createSnapshot(domainId, label.trim() || undefined)
      setLabel('')
      setOpen(true)
      toast.success('Report snapshot frozen.')
      load()
    } catch {
      toast.error('Failed to create snapshot.')
    } finally {
      setBusy(false)
    }
  }

  async function remove(id: number) {
    if (busy) return
    setBusy(true)
    try {
      await api.deleteSnapshot(id)
      toast.success('Snapshot deleted.')
    } catch {
      toast.error('Failed to delete snapshot.')
    } finally {
      setBusy(false)
    }
    load()
  }

  return (
    <div className="mb-4 rounded-xl border border-hair bg-ink-900/40 p-3">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 text-left text-sm font-medium text-zinc-200"
      >
        <Camera size={15} className="text-zinc-400" /> Report snapshots
        <Badge tone={snaps.length ? 'indigo' : 'zinc'}>{snaps.length}</Badge>
        <span className="text-xs font-normal text-zinc-500">— frozen, dated deliverables</span>
        <span className="ml-auto text-xs text-zinc-500">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="mt-3">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Optional label (e.g. 'week 1 deliverable')"
              className="min-w-0 flex-1 rounded-lg border border-hair bg-ink-950 px-3 py-1.5 text-sm outline-none focus:border-accent-500"
            />
            <button
              onClick={snapshot}
              disabled={busy}
              className="shrink-0 rounded-lg bg-accent-500 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-accent-400 disabled:opacity-50"
            >
              {busy ? 'Freezing…' : 'Snapshot now'}
            </button>
          </div>

          {snaps.length === 0 ? (
            <p className="text-xs text-zinc-500">
              No snapshots yet. Freeze the current report so a delivered copy never changes under a later re-scan.
            </p>
          ) : (
            <div className="space-y-1.5">
              {snaps.map((s) => (
                <div
                  key={s.id}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-hair/60 bg-ink-950/40 px-3 py-2 text-sm"
                >
                  <span className="text-zinc-300">{new Date(s.createdAt).toLocaleString()}</span>
                  {s.label && <span className="text-xs text-accent-fg">{s.label}</span>}
                  {s.meta && (
                    <span className="text-xs text-zinc-500">
                      {s.meta.findings} findings · <span className="text-red-400">{s.meta.high} high</span> ·{' '}
                      {s.meta.cves} CVEs
                    </span>
                  )}
                  <span className="ml-auto flex items-center gap-2">
                    <a
                      href={api.reportPdfUrl(s.id)}
                      className="rounded border border-accent-500/40 bg-accent-500/10 px-2 py-0.5 text-xs text-accent-fg transition hover:bg-accent-500/20"
                      title="Download this snapshot as a PDF (rendered server-side)"
                    >
                      PDF
                    </a>
                    <a
                      href={api.snapshotUrl(s.id, 'html')}
                      className="rounded border border-hair px-2 py-0.5 text-xs text-zinc-300 transition hover:border-hair-strong hover:bg-ink-800"
                      title="Download the frozen HTML report"
                    >
                      HTML
                    </a>
                    <a
                      href={api.snapshotUrl(s.id, 'md')}
                      className="rounded border border-hair px-2 py-0.5 text-xs text-zinc-300 transition hover:border-hair-strong hover:bg-ink-800"
                      title="Download the frozen Markdown report"
                    >
                      MD
                    </a>
                    <button
                      onClick={() => remove(s.id)}
                      className="text-xs text-zinc-600 transition hover:text-red-400"
                      title="Delete this snapshot"
                    >
                      ✕
                    </button>
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
