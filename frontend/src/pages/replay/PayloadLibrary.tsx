import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../../api'
import { useToast } from '../../components/Toast'

type PayloadData = Awaited<ReturnType<typeof api.payloads>>

// Pick a built-in or saved payload set and load it into the Intruder list, or
// save the current list as a new reusable set.
export function PayloadLibrary({
  currentList,
  onLoad,
  toast,
}: {
  currentList: string
  onLoad: (payloads: string[]) => void
  toast: ReturnType<typeof useToast>
}) {
  const [data, setData] = useState<PayloadData | null>(null)
  const [pick, setPick] = useState('')
  const [saving, setSaving] = useState(false)

  const load = useCallback(() => {
    api.payloads().then(setData).catch(() => {})
  }, [])
  useEffect(() => load(), [load])

  function loadSet(key: string) {
    setPick(key)
    if (!data || !key) return
    const [kind, id] = key.split(':')
    const set = kind === 'b' ? data.builtins.find((s) => s.id === id) : data.custom.find((s) => String(s.id) === id)
    if (set) {
      onLoad(set.payloads)
      toast.success(`Loaded ${set.payloads.length} payloads from "${set.name}".`)
      if ('notes' in set && set.notes?.length) toast.info(set.notes.join(' · '))
    }
  }

  async function saveCurrent() {
    const payloads = currentList.split('\n').map((l) => l.trim()).filter(Boolean)
    if (!payloads.length) return toast.error('Nothing to save — the list is empty.')
    const name = window.prompt('Save current list as a payload set named:')
    if (!name) return
    setSaving(true)
    try {
      await api.createPayloadSet({ name: name.trim(), category: 'custom', payloads })
      toast.success(`Saved "${name}" (${payloads.length} payloads).`)
      load()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Could not save set.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <select
        value={pick}
        onChange={(e) => loadSet(e.target.value)}
        className="rounded-lg border border-hair bg-ink-950 px-2 py-1.5 outline-none focus:border-accent-500"
      >
        <option value="">＋ Load from library…</option>
        <optgroup label="Built-in">
          {data?.builtins.map((s) => (
            <option key={s.id} value={`b:${s.id}`}>
              {s.name} ({s.payloads.length})
            </option>
          ))}
        </optgroup>
        {data && data.custom.length > 0 && (
          <optgroup label="Saved">
            {data.custom.map((s) => (
              <option key={s.id} value={`c:${s.id}`}>
                {s.name} ({s.payloads.length})
              </option>
            ))}
          </optgroup>
        )}
      </select>
      <button onClick={saveCurrent} disabled={saving} className="rounded-lg border border-hair px-2 py-1.5 text-zinc-400 hover:text-zinc-200 disabled:opacity-50">
        Save list as set
      </button>
    </div>
  )
}
