import { FormEvent, useState } from 'react'
import { Radar } from 'lucide-react'
import { api, ApiError } from '../api'
import { useToast } from './Toast'

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const toast = useToast()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await api.login(username, password, showToken ? token : undefined)
      onSuccess()
    } catch (err) {
      const msg =
        err instanceof ApiError && err.status === 429
          ? 'Too many attempts. Wait a minute and try again.'
          : 'Invalid credentials.'
      setError(msg)
      toast.error(msg)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-full flex items-center justify-center p-6 bg-ink-950 text-zinc-100">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-2xl border border-hair bg-ink-900/60 p-8 shadow-pop"
      >
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-500 shadow-sm shadow-accent-500/30">
            <Radar size={22} className="text-white" />
          </span>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Recon Dashboard</h1>
            <p className="text-sm text-zinc-400">Operator login</p>
          </div>
        </div>

        <label className="mt-6 block text-sm">
          <span className="text-zinc-400">Username</span>
          <input
            className="mt-1 w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent-500"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
          />
        </label>

        <label className="mt-4 block text-sm">
          <span className="text-zinc-400">Password</span>
          <input
            type="password"
            className="mt-1 w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent-500"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>

        {showToken ? (
          <label className="mt-4 block text-sm">
            <span className="text-zinc-400">2FA code</span>
            <input
              inputMode="numeric"
              className="mt-1 w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent-500"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              autoComplete="one-time-code"
              placeholder="123456"
            />
          </label>
        ) : (
          <button
            type="button"
            onClick={() => setShowToken(true)}
            className="mt-3 text-xs text-zinc-500 hover:text-zinc-300"
          >
            I have a 2FA code
          </button>
        )}

        {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={busy || !username || !password}
          className="mt-6 w-full rounded-lg bg-accent-500 px-3 py-2 text-sm font-medium text-white shadow-sm shadow-accent-500/20 transition hover:bg-accent-400 disabled:opacity-40 disabled:hover:bg-accent-500"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
