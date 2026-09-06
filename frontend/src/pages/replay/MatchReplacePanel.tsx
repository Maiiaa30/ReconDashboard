import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type MatchReplaceRule } from '../../api'
import { Badge, Button } from '../../components/ui'
import { useToast } from '../../components/Toast'

export function MatchReplacePanel({ domainId, domainHost, toast }: { domainId: number; domainHost: string; toast: ReturnType<typeof useToast> }) {
  const [open, setOpen] = useState(false)
  const [rules, setRules] = useState<MatchReplaceRule[]>([])
  const [form, setForm] = useState<{ name: string; scope: 'global' | 'domain'; part: 'url' | 'header' | 'body'; match: string; replace: string; isRegex: boolean }>({
    name: '',
    scope: 'domain',
    part: 'header',
    match: '',
    replace: '',
    isRegex: false,
  })

  const load = useCallback(() => {
    api.matchReplaceRules().then((r) => setRules(r.rules)).catch(() => {})
  }, [])
  useEffect(() => load(), [load])

  // Rules that will actually run against THIS target: global + this domain's.
  const active = rules.filter((r) => r.enabled && (r.domainId == null || r.domainId === domainId))

  async function add() {
    if (!form.name.trim() || !form.match.trim()) return toast.error('Rule needs a name and a match/header-name.')
    try {
      await api.createMatchReplace({
        name: form.name.trim(),
        domainId: form.scope === 'global' ? null : domainId,
        part: form.part,
        match: form.match,
        replace: form.replace,
        isRegex: form.isRegex,
      })
      setForm((f) => ({ ...f, name: '', match: '', replace: '' }))
      load()
      toast.success('Rule added.')
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Could not add rule.')
    }
  }
  async function toggle(r: MatchReplaceRule) {
    await api.updateMatchReplace(r.id, { enabled: !r.enabled }).catch(() => {})
    load()
  }
  async function remove(id: number) {
    await api.deleteMatchReplace(id).catch(() => {})
    load()
  }

  return (
    <div className="mb-3 rounded-xl border border-hair bg-ink-850/40 text-sm">
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center justify-between px-3 py-2 text-left">
        <span className="flex items-center gap-2 text-zinc-300">
          <span className="text-zinc-500">{open ? '▾' : '▸'}</span> Match / replace rules
          {active.length > 0 && <Badge tone="blue">{active.length} active</Badge>}
        </span>
        <span className="text-[11px] text-zinc-500">rewrites the Repeater + Intruder request before sending</span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-hair/60 p-3">
          {rules.length > 0 && (
            <div className="space-y-1">
              {rules.map((r) => {
                const applies = r.domainId == null || r.domainId === domainId
                return (
                  <div key={r.id} className={`flex flex-wrap items-center gap-2 rounded-lg border border-hair/60 px-2 py-1.5 text-xs ${applies ? '' : 'opacity-40'}`}>
                    <input type="checkbox" checked={r.enabled} onChange={() => toggle(r)} className="h-3.5 w-3.5 accent-accent-500" />
                    <Badge tone={r.domainId == null ? 'amber' : 'zinc'}>{r.domainId == null ? 'global' : 'domain'}</Badge>
                    <span className="font-medium text-zinc-200">{r.name}</span>
                    <span className="text-zinc-500">
                      {r.part}: <span className="font-mono">{r.match || '∅'}</span> → <span className="font-mono">{r.replace || '∅'}</span>
                      {r.isRegex && <span className="ml-1 text-zinc-600">(regex)</span>}
                    </span>
                    <button onClick={() => remove(r.id)} className="ml-auto text-zinc-500 hover:text-red-300">
                      delete
                    </button>
                  </div>
                )
              })}
            </div>
          )}
          <div className="flex flex-wrap items-end gap-2 text-xs">
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="rule name" className="w-32 rounded-lg border border-hair bg-ink-950 px-2 py-1.5 outline-none focus:border-accent-500" />
            <select value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value as 'global' | 'domain' })} className="rounded-lg border border-hair bg-ink-950 px-2 py-1.5 outline-none focus:border-accent-500">
              <option value="domain">{domainHost}</option>
              <option value="global">global</option>
            </select>
            <select value={form.part} onChange={(e) => setForm({ ...form, part: e.target.value as 'url' | 'header' | 'body' })} className="rounded-lg border border-hair bg-ink-950 px-2 py-1.5 outline-none focus:border-accent-500">
              <option value="header">header</option>
              <option value="url">url</option>
              <option value="body">body</option>
            </select>
            <input value={form.match} onChange={(e) => setForm({ ...form, match: e.target.value })} placeholder={form.part === 'header' ? 'Header-Name' : 'match'} className="w-36 rounded-lg border border-hair bg-ink-950 px-2 py-1.5 font-mono outline-none focus:border-accent-500" />
            <input value={form.replace} onChange={(e) => setForm({ ...form, replace: e.target.value })} placeholder={form.part === 'header' ? 'value (empty = delete)' : 'replace'} className="w-40 rounded-lg border border-hair bg-ink-950 px-2 py-1.5 font-mono outline-none focus:border-accent-500" />
            {form.part !== 'header' && (
              <label className="inline-flex items-center gap-1 text-zinc-400">
                <input type="checkbox" checked={form.isRegex} onChange={(e) => setForm({ ...form, isRegex: e.target.checked })} className="h-3.5 w-3.5 accent-accent-500" /> regex
              </label>
            )}
            <Button variant="loud" className="px-2 py-1.5" onClick={add}>
              Add rule
            </Button>
          </div>
          <p className="text-[11px] text-zinc-600">
            Header rules set/replace a header by name (empty value deletes it). url/body rules find & replace text (regex optional). Rules run before the
            request is sent; reserved-header stripping and SSRF/redirect guards still apply.
          </p>
        </div>
      )}
    </div>
  )
}
