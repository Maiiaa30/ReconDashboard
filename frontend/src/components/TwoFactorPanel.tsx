import { useState } from 'react'
import { api, ApiError } from '../api'

// Minimal 2FA management. TOTP is generated server-side per operator but stays
// disabled until enabled here. Phase 1 shows the otpauth URL as text (no QR dep);
// a QR render can be added later without backend changes.
export function TwoFactorPanel({ initialEnabled }: { initialEnabled: boolean }) {
  const [enabled, setEnabled] = useState(initialEnabled)
  const [otpauthUrl, setOtpauthUrl] = useState<string | null>(null)
  const [token, setToken] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function beginEnroll() {
    setMsg(null)
    setBusy(true)
    try {
      const res = await api.enroll()
      setOtpauthUrl(res.otpauthUrl)
    } catch {
      setMsg('Failed to load enrollment info.')
    } finally {
      setBusy(false)
    }
  }

  async function enable() {
    setMsg(null)
    setBusy(true)
    try {
      await api.enableTotp(token)
      setEnabled(true)
      setOtpauthUrl(null)
      setToken('')
      setMsg('Two-factor authentication enabled.')
    } catch (err) {
      setMsg(err instanceof ApiError ? err.message : 'Failed to enable 2FA.')
    } finally {
      setBusy(false)
    }
  }

  async function disable() {
    setMsg(null)
    setBusy(true)
    try {
      await api.disableTotp(token)
      setEnabled(false)
      setToken('')
      setMsg('Two-factor authentication disabled.')
    } catch (err) {
      setMsg(err instanceof ApiError ? err.message : 'Failed to disable 2FA.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">Two-factor authentication</h2>
        <span
          className={`rounded-full px-2 py-0.5 text-xs ${
            enabled ? 'bg-green-900/50 text-green-300' : 'bg-zinc-800 text-zinc-400'
          }`}
        >
          {enabled ? 'On' : 'Off'}
        </span>
      </div>

      {!enabled && !otpauthUrl && (
        <div className="mt-3">
          <p className="text-sm text-zinc-400">
            2FA is optional and currently off. You can enable a TOTP code (Google Authenticator,
            Aegis, 1Password, etc.) at any time.
          </p>
          <button
            onClick={beginEnroll}
            disabled={busy}
            className="mt-3 rounded-lg bg-zinc-100 px-3 py-1.5 text-sm font-medium text-zinc-900 hover:bg-white disabled:opacity-40"
          >
            Enable 2FA
          </button>
        </div>
      )}

      {!enabled && otpauthUrl && (
        <div className="mt-3 space-y-3">
          <p className="text-sm text-zinc-400">
            Add this to your authenticator (paste the URL or its secret), then enter the current
            6-digit code to confirm.
          </p>
          <code className="block break-all rounded-lg border border-zinc-800 bg-zinc-950 p-2 text-xs text-zinc-300">
            {otpauthUrl}
          </code>
          <div className="flex gap-2">
            <input
              inputMode="numeric"
              placeholder="123456"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="w-32 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
            />
            <button
              onClick={enable}
              disabled={busy || token.length < 6}
              className="rounded-lg bg-zinc-100 px-3 py-1.5 text-sm font-medium text-zinc-900 hover:bg-white disabled:opacity-40"
            >
              Confirm
            </button>
          </div>
        </div>
      )}

      {enabled && (
        <div className="mt-3 space-y-3">
          <p className="text-sm text-zinc-400">
            2FA is on. To turn it off, enter a current code.
          </p>
          <div className="flex gap-2">
            <input
              inputMode="numeric"
              placeholder="123456"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="w-32 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
            />
            <button
              onClick={disable}
              disabled={busy || token.length < 6}
              className="rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-40"
            >
              Disable
            </button>
          </div>
        </div>
      )}

      {msg && <p className="mt-3 text-sm text-zinc-300">{msg}</p>}
    </section>
  )
}
