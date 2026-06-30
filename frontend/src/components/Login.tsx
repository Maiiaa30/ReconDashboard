import { FormEvent, useState } from 'react'
import { api, ApiError } from '../api'

export function Login({ onSuccess }: { onSuccess: () => void }) {
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
      if (err instanceof ApiError && err.status === 429) {
        setError('Too many attempts. Wait a minute and try again.')
      } else {
        setError('Invalid credentials.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-full flex items-center justify-center p-6 bg-zinc-950 text-zinc-100">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900/60 p-8 shadow-xl"
      >
        <h1 className="text-xl font-semibold tracking-tight">Recon Dashboard</h1>
        <p className="mt-1 text-sm text-zinc-400">Operator login</p>

        <label className="mt-6 block text-sm">
          <span className="text-zinc-400">Username</span>
          <input
            className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-zinc-500"
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
            className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-zinc-500"
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
              className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-zinc-500"
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
          className="mt-6 w-full rounded-lg bg-zinc-100 px-3 py-2 text-sm font-medium text-zinc-900 hover:bg-white disabled:opacity-40"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
