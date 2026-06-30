import { useEffect, useState } from 'react'
import { api, type MetaStatus } from '../api'
import { Badge, Button, Card, PageHeader } from '../components/ui'
import { TwoFactorPanel } from '../components/TwoFactorPanel'

export function Settings({ totpEnabled }: { totpEnabled: boolean }) {
  const [meta, setMeta] = useState<MetaStatus | null>(null)

  useEffect(() => {
    api.meta().then(setMeta).catch(() => setMeta(null))
  }, [])

  return (
    <div className="max-w-2xl space-y-6">
      <PageHeader title="Settings" />

      <TwoFactorPanel initialEnabled={totpEnabled} />

      <ChangeUsernamePanel />

      <ChangePasswordPanel />

      <Card>
        <h2 className="text-sm font-semibold">System status</h2>
        {!meta ? (
          <p className="mt-2 text-sm text-zinc-500">Loading…</p>
        ) : (
          <div className="mt-3 space-y-2 text-sm">
            <Row label="Finding scorer">
              <Badge tone="blue">{meta.scorer}</Badge>
            </Row>
            <Row label="Discord alerts">
              {meta.discordConfigured ? <Badge tone="green">configured</Badge> : <Badge>off</Badge>}
            </Row>
            <Row label="Subdomain scheduler">
              {meta.scheduler.enabled ? (
                <Badge tone="green">every {meta.scheduler.intervalMinutes} min</Badge>
              ) : (
                <Badge>manual only</Badge>
              )}
            </Row>
            <Row label="Recon tools installed">
              <span className="flex flex-wrap gap-1">
                {(['subfinder', 'nmap', 'nuclei', 'ffuf'] as const).map((t) => (
                  <Badge key={t} tone={meta.tools[t] ? 'green' : 'zinc'}>
                    {t}: {meta.tools[t] ? 'yes' : 'no'}
                  </Badge>
                ))}
              </span>
            </Row>
          </div>
        )}
      </Card>

      <BackupPanel />
    </div>
  )
}

function ChangeUsernamePanel() {
  const [currentName, setCurrentName] = useState('')
  const [password, setPassword] = useState('')
  const [newUsername, setNewUsername] = useState('')
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.me().then((m) => setCurrentName(m.user.username)).catch(() => {})
  }, [])

  async function submit() {
    setMsg(null)
    setBusy(true)
    try {
      const r = await api.changeUsername(password, newUsername.trim())
      setCurrentName(r.username)
      setPassword('')
      setNewUsername('')
      setMsg({ ok: true, text: `Username changed to “${r.username}”.` })
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : 'failed to change username' })
    } finally {
      setBusy(false)
    }
  }

  const inputCls =
    'mt-1 block w-72 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500'

  return (
    <Card>
      <h2 className="text-sm font-semibold">Change username</h2>
      <p className="mt-1 text-sm text-zinc-400">
        Current username: <span className="font-mono text-zinc-200">{currentName || '…'}</span>. Letters,
        digits, dot, underscore and hyphen only. Requires your password.
      </p>
      <div className="mt-3 space-y-2">
        <label className="block text-sm text-zinc-400">
          New username
          <input value={newUsername} onChange={(e) => setNewUsername(e.target.value)} className={inputCls} autoComplete="username" />
        </label>
        <label className="block text-sm text-zinc-400">
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={inputCls} autoComplete="current-password" />
        </label>
      </div>
      {msg && <p className={`mt-2 text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>{msg.text}</p>}
      <Button className="mt-3" onClick={submit} disabled={busy || !password || !/^[A-Za-z0-9._-]+$/.test(newUsername.trim())}>
        {busy ? 'Updating…' : 'Change username'}
      </Button>
    </Card>
  )
}

function ChangePasswordPanel() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit() {
    setMsg(null)
    if (next !== confirm) {
      setMsg({ ok: false, text: 'New passwords do not match.' })
      return
    }
    setBusy(true)
    try {
      await api.changePassword(current, next)
      setCurrent('')
      setNext('')
      setConfirm('')
      setMsg({ ok: true, text: 'Password changed. You can now remove ADMIN_PASSWORD from .env.' })
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : 'failed to change password' })
    } finally {
      setBusy(false)
    }
  }

  const inputCls =
    'mt-1 block w-72 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500'

  return (
    <Card>
      <h2 className="text-sm font-semibold">Change password</h2>
      <p className="mt-1 text-sm text-zinc-400">
        Set a new operator password (min 10 chars). Stored only as an argon2 hash in the database —
        once changed, the <code className="text-zinc-300">ADMIN_PASSWORD</code> in your{' '}
        <code className="text-zinc-300">.env</code> is no longer used and should be removed.
      </p>
      <div className="mt-3 space-y-2">
        <label className="block text-sm text-zinc-400">
          Current password
          <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} className={inputCls} autoComplete="current-password" />
        </label>
        <label className="block text-sm text-zinc-400">
          New password
          <input type="password" value={next} onChange={(e) => setNext(e.target.value)} className={inputCls} autoComplete="new-password" />
        </label>
        <label className="block text-sm text-zinc-400">
          Confirm new password
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} className={inputCls} autoComplete="new-password" />
        </label>
      </div>
      {msg && <p className={`mt-2 text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>{msg.text}</p>}
      <Button className="mt-3" onClick={submit} disabled={busy || !current || next.length < 10}>
        {busy ? 'Updating…' : 'Change password'}
      </Button>
    </Card>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-zinc-400">{label}</span>
      {children}
    </div>
  )
}

function BackupPanel() {
  const [serverConfigured, setServerConfigured] = useState<boolean | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .backupStatus()
      .then((s) => setServerConfigured(s.serverPassphraseConfigured))
      .catch(() => setServerConfigured(null))
  }, [])

  async function download() {
    setError(null)
    setBusy(true)
    try {
      const res = await fetch('/api/backup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(serverConfigured ? {} : { passphrase }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || `HTTP ${res.status}`)
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const cd = res.headers.get('Content-Disposition') || ''
      const m = cd.match(/filename="([^"]+)"/)
      a.download = m ? m[1] : 'recon-backup.rdb'
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'backup failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <h2 className="text-sm font-semibold">Encrypted backup</h2>
      <p className="mt-1 text-sm text-zinc-400">
        Download an AES-256-GCM encrypted snapshot of the database. Keep the passphrase safe — without
        it the backup cannot be restored.
      </p>
      {serverConfigured ? (
        <p className="mt-2 text-xs text-zinc-500">
          A server-side passphrase (BACKUP_PASSPHRASE) is configured; it will be used automatically.
        </p>
      ) : (
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="Backup passphrase (min 12 chars)"
          className="mt-3 block w-72 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
        />
      )}
      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
      <Button
        className="mt-3"
        onClick={download}
        disabled={busy || (!serverConfigured && passphrase.length < 12)}
      >
        {busy ? 'Preparing…' : 'Download encrypted backup'}
      </Button>
    </Card>
  )
}
