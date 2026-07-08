import { classifyPort, riskTone, CATEGORY_META } from '../lib/portIntel'

// A single port rendered as a badge. Known interesting services are colored by
// risk and carry a tooltip explaining what's probably behind them; unknown/plain
// ports stay muted. Optionally shows the service label inline.
export function PortBadge({ port, showLabel = false }: { port: number; showLabel?: boolean }) {
  const info = classifyPort(port)
  const tone = info ? riskTone(info.risk) : 'zinc'
  const cat = info ? CATEGORY_META[info.category] : null
  const isHot = info && info.category !== 'web' && (info.risk === 'high' || info.risk === 'medium')

  const toneCls: Record<string, string> = {
    red: 'bg-red-500/15 text-red-300 ring-red-500/25',
    amber: 'bg-amber-500/15 text-amber-300 ring-amber-500/25',
    zinc: 'bg-ink-700 text-zinc-300 ring-transparent',
  }

  const title = info ? `${cat!.icon} ${cat!.label} · ${info.label} (:${port})\n${info.note}` : `port ${port}`

  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs ring-1 ring-inset ${toneCls[tone]}`}
    >
      {isHot && <span className="text-[10px] leading-none">{cat!.icon}</span>}
      <span className="font-mono">{port}</span>
      {showLabel && info && <span className="text-[10px] opacity-80">{info.label}</span>}
    </span>
  )
}
