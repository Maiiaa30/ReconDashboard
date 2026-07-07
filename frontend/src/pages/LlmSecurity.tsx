import { useMemo, useState, type ReactNode } from 'react'
import { Copy, Check, ExternalLink, ShieldAlert } from 'lucide-react'
import { Badge, Card, Empty, PageHeader } from '../components/ui'
import {
  MODEL_LABELS,
  MODEL_METHODOLOGY,
  OWASP_LLM,
  PAYLOADS,
  type LlmModel,
  type OwaspLlmItem,
  type Payload,
  type PayloadCategory,
} from '../data/llmSecurity'

type Tab = 'owasp' | 'payloads' | 'methodology'

const MODELS: LlmModel[] = ['generic', 'gemini', 'llama', 'gpt', 'claude', 'grok', 'mistral']

type BadgeTone = 'zinc' | 'green' | 'amber' | 'red' | 'blue' | 'indigo' | 'purple'

// Per-category color so the payload library reads at a glance instead of being
// a wall of identical purple chips.
const CATEGORY_STYLE: Record<PayloadCategory, { tone: BadgeTone; border: string }> = {
  'Prompt Injection': { tone: 'red', border: 'border-l-red-500/70' },
  'Indirect Injection': { tone: 'amber', border: 'border-l-amber-500/70' },
  'System Prompt Leak': { tone: 'blue', border: 'border-l-blue-500/70' },
  'Jailbreak Framing': { tone: 'purple', border: 'border-l-purple-500/70' },
  'Encoding / Obfuscation': { tone: 'indigo', border: 'border-l-accent-500/70' },
  'Output Handling': { tone: 'red', border: 'border-l-red-500/70' },
  'Data Exfiltration': { tone: 'amber', border: 'border-l-amber-500/70' },
  'Tool / Agent Abuse': { tone: 'purple', border: 'border-l-purple-500/70' },
}

const SEV_BORDER = { high: 'border-l-red-500/70', medium: 'border-l-amber-500/70', low: 'border-l-blue-500/60' } as const

// Reference module: OWASP Top 10 for LLMs, a searchable payload library, and
// per-model testing methodology — for AUTHORIZED assessment of LLM apps only.
export function LlmSecurity() {
  const [tab, setTab] = useState<Tab>('owasp')
  const [query, setQuery] = useState('')
  const [model, setModel] = useState<LlmModel | 'all'>('all')

  const q = query.trim().toLowerCase()

  const owasp = useMemo(() => {
    if (!q) return OWASP_LLM
    return OWASP_LLM.filter((o) =>
      [o.id, o.title, o.summary, ...o.approach, ...o.examples, ...o.mitigations].join(' ').toLowerCase().includes(q),
    )
  }, [q])

  const payloads = useMemo(() => {
    return PAYLOADS.filter((p) => {
      const modelOk = model === 'all' || p.models.includes(model) || p.models.includes('generic')
      const textOk =
        !q || [p.title, p.text, p.category, p.owasp, p.notes ?? ''].join(' ').toLowerCase().includes(q)
      return modelOk && textOk
    })
  }, [q, model])

  const methodology = useMemo(() => {
    return MODEL_METHODOLOGY.filter((m) => {
      const modelOk = model === 'all' || m.model === model
      const textOk =
        !q ||
        [MODEL_LABELS[m.model].label, MODEL_LABELS[m.model].vendor, m.guardrails, ...m.approach, ...m.quirks]
          .join(' ')
          .toLowerCase()
          .includes(q)
      return modelOk && textOk
    })
  }, [q, model])

  return (
    <div>
      <PageHeader
        title="LLM Security"
        subtitle="OWASP Top 10 for LLMs · red-team payloads · per-model methodology"
      />

      <div className="mb-5 flex items-start gap-2 rounded-xl border border-amber-900/50 bg-amber-950/20 p-3 text-xs text-amber-200/90">
        <ShieldAlert size={16} className="mt-0.5 shrink-0 text-amber-400" />
        <span>
          Reference material for <strong>authorized</strong> testing of LLM-backed applications you have
          permission to assess. Payloads are detection probes — copy them into the target you are engaged to
          test. Keep everything in-scope.
        </span>
      </div>

      {/* Tabs */}
      <div className="mb-4 flex flex-wrap gap-1 border-b border-hair">
        <TabBtn active={tab === 'owasp'} onClick={() => setTab('owasp')}>
          OWASP Top 10 {q && <Count n={owasp.length} />}
        </TabBtn>
        <TabBtn active={tab === 'payloads'} onClick={() => setTab('payloads')}>
          Payloads <Count n={payloads.length} />
        </TabBtn>
        <TabBtn active={tab === 'methodology'} onClick={() => setTab('methodology')}>
          Model methodology <Count n={methodology.length} />
        </TabBtn>
      </div>

      {/* Search + model filter */}
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={
            tab === 'owasp' ? 'Search risks…' : tab === 'payloads' ? 'Search payloads…' : 'Search methodology…'
          }
          className="w-full rounded-lg border border-hair bg-ink-850 px-3 py-2 text-sm outline-none transition placeholder:text-zinc-600 hover:border-hair-strong focus:border-accent-500 sm:max-w-xs"
        />
        {tab !== 'owasp' && (
          <div className="flex flex-wrap gap-1.5">
            <ModelChip label="All" active={model === 'all'} onClick={() => setModel('all')} />
            {MODELS.map((m) => (
              <ModelChip
                key={m}
                label={MODEL_LABELS[m].label}
                active={model === m}
                onClick={() => setModel(m)}
              />
            ))}
          </div>
        )}
      </div>

      {tab === 'owasp' &&
        (owasp.length === 0 ? (
          <Empty>No risks match “{query}”.</Empty>
        ) : (
          <div className="space-y-3">
            {owasp.map((o) => (
              <OwaspCard key={o.id} item={o} />
            ))}
          </div>
        ))}

      {tab === 'payloads' &&
        (payloads.length === 0 ? (
          <Empty>No payloads match your filters.</Empty>
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">
            {payloads.map((p) => (
              <PayloadCard key={p.id} p={p} />
            ))}
          </div>
        ))}

      {tab === 'methodology' &&
        (methodology.length === 0 ? (
          <Empty>No methodology matches your filters.</Empty>
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">
            {methodology.map((m) => (
              <MethodologyCard key={m.model} m={m} />
            ))}
          </div>
        ))}
    </div>
  )
}

const SEV_TONE = { high: 'red', medium: 'amber', low: 'blue' } as const

function OwaspCard({ item }: { item: OwaspLlmItem }) {
  return (
    <Card className={`border-l-4 ${SEV_BORDER[item.severity]}`}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="indigo">{item.id}</Badge>
        <h3 className="text-sm font-semibold text-zinc-100">{item.title}</h3>
        <Badge tone={SEV_TONE[item.severity]}>{item.severity}</Badge>
        <a
          href={item.ref}
          target="_blank"
          rel="noreferrer"
          className="ml-auto inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-accent-fg"
        >
          OWASP <ExternalLink size={12} />
        </a>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-zinc-300">{item.summary}</p>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <ListBlock title="How to test" items={item.approach} />
        <ListBlock title="Mitigations" items={item.mitigations} tone="green" />
      </div>
      {item.examples.length > 0 && (
        <div className="mt-3">
          <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">Example probes</h4>
          <div className="space-y-1.5">
            {item.examples.map((ex, i) => (
              <CopyBlock key={i} text={ex} />
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

function PayloadCard({ p }: { p: Payload }) {
  const style = CATEGORY_STYLE[p.category]
  return (
    <Card className={`flex flex-col border-l-4 ${style.border}`}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={style.tone}>{p.category}</Badge>
        <h3 className="text-sm font-semibold text-zinc-100">{p.title}</h3>
      </div>
      <div className="mt-2">
        <CopyBlock text={p.text} />
      </div>
      {p.notes && <p className="mt-2 text-xs leading-relaxed text-zinc-400">{p.notes}</p>}
      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        {p.models.map((m) => (
          <span key={m} className="rounded bg-ink-800 px-1.5 py-0.5 text-[10px] text-zinc-400">
            {MODEL_LABELS[m].label}
          </span>
        ))}
        <span className="ml-auto text-[10px] text-zinc-600">{p.owasp}</span>
      </div>
    </Card>
  )
}

function MethodologyCard({ m }: { m: (typeof MODEL_METHODOLOGY)[number] }) {
  const info = MODEL_LABELS[m.model]
  return (
    <Card>
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-semibold text-zinc-100">{info.label}</h3>
        <span className="text-xs text-zinc-500">{info.vendor}</span>
      </div>
      <p className="mt-1.5 text-xs leading-relaxed text-zinc-400">{m.guardrails}</p>
      <div className="mt-3">
        <ListBlock title="Testing approach" items={m.approach} />
      </div>
      <div className="mt-3">
        <ListBlock title="Quirks to exploit" items={m.quirks} tone="amber" />
      </div>
    </Card>
  )
}

function ListBlock({ title, items, tone = 'zinc' }: { title: string; items: string[]; tone?: 'zinc' | 'green' | 'amber' }) {
  const dot = { zinc: 'bg-zinc-600', green: 'bg-green-500', amber: 'bg-amber-500' }[tone]
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

function CopyBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked — no-op */
    }
  }
  return (
    <div className="group relative rounded-lg border border-hair bg-ink-950/70 p-2.5 pr-9">
      <code className="block whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed text-zinc-300">
        {text}
      </code>
      <button
        onClick={copy}
        title="Copy"
        className="absolute right-1.5 top-1.5 rounded-md border border-hair bg-ink-900 p-1.5 text-zinc-400 transition hover:text-zinc-100 hover:border-hair-strong"
      >
        {copied ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
      </button>
    </div>
  )
}

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`-mb-px border-b-2 px-3 py-2 text-sm transition ${
        active
          ? 'border-accent-500 font-medium text-accent-fg'
          : 'border-transparent text-zinc-400 hover:text-zinc-200'
      }`}
    >
      {children}
    </button>
  )
}

function Count({ n }: { n: number }) {
  return <span className="ml-1 rounded-full bg-ink-800 px-1.5 py-0.5 text-[10px] text-zinc-400">{n}</span>
}

function ModelChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-2.5 py-1 text-xs transition ${
        active
          ? 'border-accent-500 bg-accent-500/15 text-accent-fg'
          : 'border-hair text-zinc-400 hover:border-hair-strong hover:text-zinc-200'
      }`}
    >
      {label}
    </button>
  )
}
