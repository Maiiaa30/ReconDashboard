import { useState } from 'react'
import { Users } from 'lucide-react'
import { api, ApiError, type Identity } from '../../api'
import { Badge, Button } from '../../components/ui'
import { useToast } from '../../components/Toast'
import { parseHeaders } from './shared'

export function IdentityBar({
  domainId,
  identities,
  identityId,
  setIdentityId,
  onChange,
  selectable,
  toast,
}: {
  domainId: number
  identities: Identity[]
  identityId: number | null
  setIdentityId: (id: number | null) => void
  onChange: () => void
  selectable: boolean
  toast: ReturnType<typeof useToast>
}) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [headersText, setHeadersText] = useState('')
  const [isAnon, setIsAnon] = useState(false)
  const [busy, setBusy] = useState(false)

  async function save() {
    if (busy) return
    if (!name.trim()) return toast.error('Give the identity a name.')
    setBusy(true)
    try {
      await api.saveIdentity({ domainId, name: name.trim(), headers: isAnon ? {} : parseHeaders(headersText), isAnon })
      setName('')
      setHeadersText('')
      setIsAnon(false)
      onChange()
      toast.success('Identity saved.')
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to save identity.')
    } finally {
      setBusy(false)
    }
  }
  async function remove(id: number) {
    try {
      await api.deleteIdentity(id)
      if (identityId === id) setIdentityId(null)
      onChange()
    } catch {
      toast.error('Failed to delete identity.')
    }
  }

  return (
    <div className="mb-3 rounded-lg border border-hair bg-ink-900/50 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="inline-flex items-center gap-1.5 text-zinc-400">
          <Users size={14} /> Identities
        </span>
        {selectable ? (
          <select
            value={identityId ?? ''}
            onChange={(e) => setIdentityId(e.target.value ? Number(e.target.value) : null)}
            className="rounded-lg border border-hair bg-ink-950 px-2 py-1 text-xs outline-none focus:border-accent-500"
          >
            <option value="">Send as: default (typed headers)</option>
            {identities.map((i) => (
              <option key={i.id} value={i.id}>
                Send as: {i.name}
                {i.isAnon ? ' (anon)' : ''}
              </option>
            ))}
          </select>
        ) : (
          <span className="text-zinc-600">defined once, selectable as identity B below</span>
        )}
        {selectable && identityId != null && <Badge tone="indigo">headers merged</Badge>}
        <button onClick={() => setOpen((o) => !o)} className="ml-auto text-accent-fg hover:underline">
          {open ? 'Close' : 'Manage'}
        </button>
      </div>

      {open && (
        <div className="mt-2 space-y-2 border-t border-hair pt-2">
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="name (e.g. admin, userB)"
              className="w-44 rounded-lg border border-hair bg-ink-950 px-2 py-1 text-xs outline-none focus:border-accent-500"
            />
            <label className="inline-flex items-center gap-1 text-[11px] text-zinc-500">
              <input type="checkbox" checked={isAnon} onChange={(e) => setIsAnon(e.target.checked)} /> anonymous (strip creds)
            </label>
            <Button variant="ghost" onClick={save} disabled={busy}>
              {busy ? 'Saving…' : 'Save identity'}
            </Button>
          </div>
          {!isAnon && (
            <textarea
              value={headersText}
              onChange={(e) => setHeadersText(e.target.value)}
              placeholder={'Cookie: session=…\nAuthorization: Bearer …'}
              rows={2}
              spellCheck={false}
              className="block w-full rounded-lg border border-hair bg-ink-950 px-2 py-1.5 font-mono text-xs outline-none focus:border-accent-500"
            />
          )}
          {identities.length > 0 && (
            <ul className="space-y-1 text-xs">
              {identities.map((i) => (
                <li key={i.id} className="flex items-center gap-2">
                  <span className="font-mono text-zinc-300">{i.name}</span>
                  {i.isAnon ? <Badge tone="zinc">anon</Badge> : <span className="text-zinc-600">{Object.keys(i.headers).length} header(s)</span>}
                  <button onClick={() => remove(i.id)} className="ml-auto text-red-300 hover:underline">
                    delete
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}
