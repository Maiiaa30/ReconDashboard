import { useRef, type ReactNode, type KeyboardEvent } from 'react'

export interface TabItem<K extends string> {
  key: K
  label: string
  icon?: ReactNode
}

/**
 * An accessible tab strip: a `role="tablist"` of `role="tab"` buttons with
 * `aria-selected`, roving tabindex (only the active tab is in the Tab order), and
 * Arrow/Home/End keyboard navigation that wraps — the WAI-ARIA tabs pattern.
 * Purely a selector; the caller renders the panel and should give it
 * `role="tabpanel"` + `aria-label`.
 */
export function Tabs<K extends string>({
  items,
  value,
  onChange,
  label,
  className,
}: {
  items: TabItem<K>[]
  value: K
  onChange: (key: K) => void
  label: string
  className?: string
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])

  function onKeyDown(e: KeyboardEvent<HTMLButtonElement>, index: number) {
    let next = index
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (index + 1) % items.length
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (index - 1 + items.length) % items.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = items.length - 1
    else return
    e.preventDefault()
    onChange(items[next].key)
    refs.current[next]?.focus()
  }

  return (
    <div role="tablist" aria-label={label} className={className ?? 'inline-flex rounded-lg border border-hair bg-ink-850 p-0.5'}>
      {items.map((item, i) => {
        const active = item.key === value
        return (
          <button
            key={item.key}
            ref={(el) => { refs.current[i] = el }}
            role="tab"
            type="button"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(item.key)}
            onKeyDown={(e) => onKeyDown(e, i)}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition ${
              active ? 'bg-accent-500/15 text-accent-fg' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {item.icon} {item.label}
          </button>
        )
      })}
    </div>
  )
}
