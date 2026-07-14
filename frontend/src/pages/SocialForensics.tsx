import { useMemo, useState, type MouseEvent, type ReactNode } from 'react'
import { ExternalLink, ShieldAlert, Search, Copy, Check } from 'lucide-react'
import { Card, Empty, PageHeader } from '../components/ui'
import { copyText } from '../lib/clipboard'
import {
  buildUrl,
  METHODOLOGY,
  RESOURCES,
  SELECTOR_LABELS,
  type Resource,
  type ResourceCategory,
  type SelectorType,
} from '../data/socialForensics'

type Tab = 'pivot' | 'methodology'

const TYPES: SelectorType[] = ['username', 'email', 'name', 'phone']

const CATEGORY_ORDER: ResourceCategory[] = [
  'Social',
  'Professional',
  'Developer',
  'Media & video',
  'Messaging',
  'Gaming',
  'Search dork',
  'Breach & exposure',
  'Reverse & metadata',
]

// Passive people-OSINT: pivots a selector (username/email/name/phone) into
// clickable links to public profiles, search dorks, and breach front-ends. The
// operator's browser opens each link — nothing is queried server-side.
export function SocialForensics() {
  const [tab, setTab] = useState<Tab>('pivot')
  const [type, setType] = useState<SelectorType>('username')
  const [value, setValue] = useState('')

  const v = value.trim()

  // Resources relevant to the chosen selector type.
  const grouped = useMemo(() => {
    const matches = RESOURCES.filter((r) => r.types.includes(type))
    const byCat = new Map<ResourceCategory, Resource[]>()
    for (const r of matches) {
      if (!byCat.has(r.category)) byCat.set(r.category, [])
      byCat.get(r.category)!.push(r)
    }
    return CATEGORY_ORDER.filter((c) => byCat.has(c)).map((c) => ({ category: c, items: byCat.get(c)! }))
  }, [type])

  return (
    <div>
      <PageHeader
        title="Social Forensics"
        subtitle="People & account OSINT — pivot a selector into public presence"
      />

      <div className="mb-5 flex items-start gap-2 rounded-xl border border-amber-900/50 bg-amber-950/20 p-3 text-xs text-amber-200/90">
        <ShieldAlert size={16} className="mt-0.5 shrink-0 text-amber-400" />
        <span>
          Passive OSINT for <strong>authorized</strong> engagement reconnaissance. Every link opens in your
          browser — nothing is queried from the server. Aggregates public profiles and search-engine results;
          stay in scope and use breach data for exposure assessment only.
        </span>
      </div>

      {/* Tabs */}
      <div className="mb-4 flex flex-wrap gap-1 border-b border-hair">
        <TabBtn active={tab === 'pivot'} onClick={() => setTab('pivot')}>
          Pivot
        </TabBtn>
        <TabBtn active={tab === 'methodology'} onClick={() => setTab('methodology')}>
          Methodology
        </TabBtn>
      </div>

      {tab === 'pivot' && (
        <>
          <div className="mb-5 space-y-3">
            <div className="flex flex-wrap gap-1.5">
              {TYPES.map((t) => (
                <Chip key={t} label={SELECTOR_LABELS[t]} active={type === t} onClick={() => setType(t)} />
              ))}
            </div>
            <div className="relative max-w-md">
              <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={placeholderFor(type)}
                className="w-full rounded-lg border border-hair bg-ink-850 py-2 pl-9 pr-3 text-sm outline-none transition placeholder:text-zinc-600 hover:border-hair-strong focus:border-accent-500"
              />
            </div>
          </div>

          {!v ? (
            <Empty>Enter a {SELECTOR_LABELS[type].toLowerCase()} to generate lookup links across platforms.</Empty>
          ) : (
            <div className="space-y-4">
              {grouped.map((g) => (
                <div key={g.category}>
                  <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-zinc-200">
                    {g.category}
                    <span className="text-xs font-normal text-zinc-500">({g.items.length})</span>
                  </h3>
                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    {g.items.map((r) => (
                      <LinkTile key={r.id} resource={r} value={v} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {tab === 'methodology' && (
        <div className="space-y-3">
          {METHODOLOGY.map((m) => (
            <Card key={m.phase}>
              <div className="flex flex-wrap items-baseline gap-2">
                <h3 className="text-sm font-semibold text-zinc-100">{m.phase}</h3>
                <span className="text-xs text-zinc-500">{m.goal}</span>
              </div>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <ListBlock title="Steps" items={m.steps} />
                <ListBlock title="Tips" items={m.tips} tone="amber" />
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}

function placeholderFor(type: SelectorType): string {
  switch (type) {
    case 'username':
      return 'e.g. johndoe'
    case 'email':
      return 'e.g. john.doe@example.com'
    case 'name':
      return 'e.g. John Doe'
    case 'phone':
      return 'e.g. +15551234567'
  }
}

function LinkTile({ resource, value }: { resource: Resource; value: string }) {
  const [copied, setCopied] = useState(false)
  const url = buildUrl(resource.url, value)

  async function copy(e: MouseEvent) {
    e.preventDefault()
    e.stopPropagation()
    if (await copyText(url)) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
  }

  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer noopener"
      className="group flex items-start gap-2 rounded-lg border border-hair bg-ink-850 p-2.5 transition hover:border-accent-500/60 hover:bg-ink-800"
      title={url}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5 text-sm text-zinc-100">
          <span className="truncate">{resource.name}</span>
          <ExternalLink size={12} className="shrink-0 text-zinc-600 group-hover:text-accent-fg" />
        </div>
        {resource.note && <p className="mt-0.5 text-[11px] leading-snug text-zinc-500">{resource.note}</p>}
      </div>
      <button
        onClick={copy}
        title="Copy URL"
        className="shrink-0 rounded-md border border-hair bg-ink-900 p-1 text-zinc-500 transition hover:text-zinc-200 hover:border-hair-strong"
      >
        {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
      </button>
    </a>
  )
}

function ListBlock({ title, items, tone = 'zinc' }: { title: string; items: string[]; tone?: 'zinc' | 'amber' }) {
  const dot = { zinc: 'bg-zinc-600', amber: 'bg-amber-500' }[tone]
  return (
    <div>
      <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">{title}</h4>
      <ul className="space-y-1">
        {items.map((it, i) => (
          <li key={i} className="flex gap-2 text-xs leading-relaxed text-zinc-300">
            <span className={`mt-1.5 h-1 w-1 shrink-0 rounded-full ${dot}`} />
            <span>{it}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`-mb-px border-b-2 px-3 py-2 text-sm transition ${
        active ? 'border-accent-500 font-medium text-accent-fg' : 'border-transparent text-zinc-400 hover:text-zinc-200'
      }`}
    >
      {children}
    </button>
  )
}

function Chip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-xs transition ${
        active
          ? 'border-accent-500 bg-accent-500/15 text-accent-fg'
          : 'border-hair text-zinc-400 hover:border-hair-strong hover:text-zinc-200'
      }`}
    >
      {label}
    </button>
  )
}
