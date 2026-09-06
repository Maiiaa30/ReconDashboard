import { useState } from 'react'
import { type Finding, type FindingStatus } from '../../api'
import { Badge } from '../../components/ui'
import { riskFromScore, summarizeFinding, timeAgo } from '../../lib/format'
import { RISK_BORDER, RISK_SCORE, STATUS_LABEL, STATUS_SELECT, STATUSES, TRIAGED_AWAY, TYPE_LABEL, tagTone } from './constants'
import { FindingDetail } from './FindingDetail'

export function FindingRow({
  f,
  idx,
  host,
  selected,
  onToggleSelect,
  onTag,
  onUpdate,
  navigate,
}: {
  f: Finding
  idx: number
  host: string
  selected: boolean
  onToggleSelect: (id: number, idx: number, range: boolean) => void
  onTag: (t: string) => void
  onUpdate: (id: number, patch: { status?: FindingStatus; note?: string | null }) => void
  navigate?: (page: string, domainId?: number) => void
}) {
  const [showAllTags, setShowAllTags] = useState(false)
  const [open, setOpen] = useState(false)
  const risk = riskFromScore(f.score)
  const tags = f.tags ?? []
  const shownTags = showAllTags ? tags : tags.slice(0, 7)
  const dimmed = TRIAGED_AWAY.includes(f.status)

  return (
    <div className={`rounded-xl border border-l-4 border-hair bg-ink-850/60 ${RISK_BORDER[risk]} ${dimmed ? 'opacity-60' : ''} ${selected ? 'ring-1 ring-accent-500/50' : ''}`}>
      <div className="flex items-start gap-3 p-3">
        <input
          type="checkbox"
          checked={selected}
          onChange={() => {}}
          onClick={(e) => {
            e.stopPropagation()
            onToggleSelect(f.id, idx, e.shiftKey)
          }}
          title="select (shift-click for range)"
          className="mt-2.5 h-4 w-4 shrink-0 cursor-pointer accent-accent-500"
        />
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-sm font-semibold ring-1 ${RISK_SCORE[risk]}`}>
          {f.score ?? '—'}
        </div>

        <div
          onClick={() => setOpen((v) => !v)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              setOpen((v) => !v)
            }
          }}
          className="min-w-0 flex-1 cursor-pointer text-left"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="zinc">{TYPE_LABEL[f.type] ?? f.type}</Badge>
            <span className="min-w-0 break-all font-mono text-sm text-zinc-100">{summarizeFinding(f.type, f.data)}</span>
            <span className="text-xs text-zinc-600">{open ? '▾' : '▸'}</span>
          </div>
          {tags.length > 0 && (
            <div className="mt-1.5 flex flex-wrap items-center gap-1">
              {shownTags.map((t) => (
                <button
                  key={t}
                  onClick={(e) => {
                    e.stopPropagation()
                    onTag(t)
                  }}
                  title="filter by this tag"
                >
                  <Badge tone={tagTone(t)}>{t}</Badge>
                </button>
              ))}
              {!showAllTags && tags.length > 7 && (
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    setShowAllTags(true)
                  }}
                  className="text-[10px] text-zinc-500 hover:text-zinc-300"
                >
                  +{tags.length - 7} more
                </button>
              )}
            </div>
          )}
        </div>

        <div className="flex shrink-0 flex-col items-end gap-1 text-right text-xs text-zinc-500">
          <select
            value={f.status}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => onUpdate(f.id, { status: e.target.value as FindingStatus })}
            title="triage status"
            className={`cursor-pointer rounded-md border bg-ink-950 px-1.5 py-0.5 text-xs outline-none focus:border-accent-500 ${STATUS_SELECT[f.status]}`}
          >
            {STATUSES.map((s) => (
              <option key={s} value={s} className="text-zinc-200">
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
          <div className="font-mono text-zinc-400">{host}</div>
          <div>{timeAgo(new Date(f.createdAt).getTime())}</div>
        </div>
      </div>

      {open && <FindingDetail f={f} onUpdate={onUpdate} navigate={navigate} />}
    </div>
  )
}
