import { useEffect, useState } from 'react'
import { api } from '../../api'
import { Badge } from '../../components/ui'
import { useToast } from '../../components/Toast'
import { copyText } from '../../lib/clipboard'

export function EncoderBar({ toast }: { toast: ReturnType<typeof useToast> }) {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState('')
  const [chain, setChain] = useState<string[]>([])
  const [output, setOutput] = useState('')
  const [transforms, setTransforms] = useState<string[]>([])

  useEffect(() => {
    if (open && transforms.length === 0) api.payloads().then((d) => setTransforms(d.transforms)).catch(() => {})
  }, [open, transforms.length])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    if (!input || chain.length === 0) {
      setOutput('')
      return
    }
    api
      .encodePayload(input, chain)
      .then((r) => !cancelled && setOutput(r.output))
      .catch(() => !cancelled && setOutput(''))
    return () => {
      cancelled = true
    }
  }, [open, input, chain])

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-[11px] text-zinc-500 hover:text-zinc-300">
        ▸ encoder
      </button>
    )
  }

  return (
    <div className="space-y-1.5 rounded-lg border border-hair bg-ink-900/50 p-2 text-xs">
      <div className="flex items-center justify-between">
        <span className="uppercase tracking-wide text-zinc-500">Encoder chain</span>
        <button onClick={() => setOpen(false)} className="text-zinc-500 hover:text-zinc-300">
          ▾ hide
        </button>
      </div>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="text to encode"
        className="block w-full rounded border border-hair bg-ink-950 px-2 py-1 font-mono outline-none focus:border-accent-500"
      />
      <div className="flex flex-wrap gap-1">
        {transforms.map((t) => (
          <button
            key={t}
            onClick={() => setChain((c) => [...c, t])}
            className="rounded border border-hair px-1.5 py-0.5 text-[10px] text-zinc-400 hover:text-accent-fg"
          >
            {t}
          </button>
        ))}
      </div>
      {chain.length > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-zinc-500">chain:</span>
          {chain.map((t, i) => (
            <Badge key={i} tone="zinc">
              {t}
            </Badge>
          ))}
          <button onClick={() => setChain([])} className="text-zinc-500 hover:text-zinc-300">
            clear
          </button>
        </div>
      )}
      {output && (
        <div className="flex items-start gap-2">
          <code className="min-w-0 flex-1 break-all rounded bg-ink-950 px-2 py-1 font-mono text-accent-fg">{output}</code>
          <button
            onClick={() => {
              copyText(output).then((ok) => ok && toast.success('Copied.'))
            }}
            className="shrink-0 rounded border border-hair px-1.5 py-1 text-zinc-400 hover:text-zinc-200"
          >
            copy
          </button>
        </div>
      )}
    </div>
  )
}
