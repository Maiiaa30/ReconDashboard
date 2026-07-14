import { useEffect, useRef, useState } from 'react'
import { Paperclip, Search, X } from 'lucide-react'
import { api, ApiError, type Finding } from '../api'
import { summarizeFinding } from '../lib/format'
import { ScoreBadge } from './ui'
import { useToast } from './Toast'

// Attach a composed request/response (from Replay or Traffic) as evidence to an
// existing finding. Renders a small trigger button + a lightweight inline
// popover that lists this target's findings, filterable by summary text.
export function AttachToFinding({
  domainId,
  request,
  response,
  note,
  label = 'Attach to finding',
  disabled = false,
}: {
  domainId: number | null
  request?: string
  response?: string
  note?: string
  label?: string
  disabled?: boolean
}) {
  const toast = useToast()
  const [open, setOpen] = useState(false)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(false)
  const [query, setQuery] = useState('')
  const [attaching, setAttaching] = useState<number | null>(null)
  const rootRef = useRef<HTMLDivElement>(null)

  // Pull this target's findings each time the popover opens (bounded set).
  useEffect(() => {
    if (!open || domainId == null) return
    setQuery('')
    setLoading(true)
    api
      .findings({ domainId, limit: 200 })
      .then((r) => setFindings(r.findings))
      .catch(() => toast.error('Failed to load findings.'))
      .finally(() => setLoading(false))
  }, [open, domainId, toast])

  // Dismiss on outside click or Escape.
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const q = query.trim().toLowerCase()
  const shown = q
    ? findings.filter(
        (f) => summarizeFinding(f.type, f.data).toLowerCase().includes(q) || f.type.toLowerCase().includes(q),
      )
    : findings

  async function attach(f: Finding) {
    if (attaching != null) return
    const body: { request?: string; response?: string; note?: string } = {}
    if (request) body.request = request
    if (response) body.response = response
    if (note) body.note = note
    setAttaching(f.id)
    try {
      await api.attachEvidence(f.id, body)
      toast.success(`Evidence attached to #${f.id}`)
      setOpen(false)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to attach evidence.')
    } finally {
      setAttaching(null)
    }
  }

  const noTarget = domainId == null
  return (
    <div ref={rootRef} className="relative inline-block">
      <button
        onClick={() => setOpen((v) => !v)}
        disabled={disabled || noTarget}
        title={noTarget ? 'Select a target first to attach evidence to a finding.' : label}
        className="inline-flex items-center gap-1.5 rounded-lg border border-hair px-2.5 py-1.5 text-xs font-medium text-zinc-300 transition hover:bg-ink-800 hover:border-hair-strong disabled:cursor-not-allowed disabled:opacity-40"
      >
        <Paperclip size={13} /> {label}
      </button>
      {open && (
        <div className="absolute right-0 z-50 mt-1 w-80 overflow-hidden rounded-xl border border-hair bg-ink-900 shadow-pop">
          <div className="flex items-center gap-2 border-b border-hair px-2.5">
            <Search size={14} className="shrink-0 text-zinc-500" />
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter findings…"
              spellCheck={false}
              className="w-full bg-transparent py-2.5 text-xs text-zinc-100 outline-none placeholder:text-zinc-600"
            />
            <button
              onClick={() => setOpen(false)}
              aria-label="Close"
              className="shrink-0 text-zinc-500 transition hover:text-zinc-200"
            >
              <X size={13} />
            </button>
          </div>
          <div className="max-h-72 overflow-y-auto py-1">
            {loading ? (
              <div className="px-3 py-6 text-center text-xs text-zinc-500">Loading findings…</div>
            ) : shown.length === 0 ? (
              <div className="px-3 py-6 text-center text-xs text-zinc-500">
                {findings.length === 0 ? 'No findings for this target yet.' : 'No findings match.'}
              </div>
            ) : (
              shown.map((f) => (
                <button
                  key={f.id}
                  onClick={() => attach(f)}
                  disabled={attaching != null}
                  className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs transition hover:bg-ink-800 disabled:opacity-50"
                >
                  <ScoreBadge score={f.score} />
                  <span className="min-w-0 flex-1 truncate text-zinc-200">{summarizeFinding(f.type, f.data)}</span>
                  <span className="shrink-0 text-[10px] text-zinc-600">#{f.id}</span>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
