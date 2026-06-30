import { useState } from 'react'
import type { Me } from '../api'
import { api } from '../api'
import { useApp } from '../state'
import { Domains } from '../pages/Domains'
import { Intel } from '../pages/Intel'
import { Subdomains } from '../pages/Subdomains'
import { Screenshots } from '../pages/Screenshots'
import { Fuzzing } from '../pages/Fuzzing'
import { Exposure } from '../pages/Exposure'
import { Osint } from '../pages/Osint'
import { Origin } from '../pages/Origin'
import { Scans } from '../pages/Scans'
import { Owasp } from '../pages/Owasp'
import { Notes } from '../pages/Notes'
import { Canvas } from '../pages/Canvas'
import { Findings } from '../pages/Findings'
import { Jobs } from '../pages/Jobs'
import { Settings } from '../pages/Settings'

const MODULES = [
  { key: 'domains', label: 'Domains' },
  { key: 'intel', label: 'Intel' },
  { key: 'subdomains', label: 'Subdomains' },
  { key: 'screenshots', label: 'Screenshots' },
  { key: 'fuzzing', label: 'Fuzzing' },
  { key: 'exposure', label: 'Exposure' },
  { key: 'osint', label: 'OSINT' },
  { key: 'origin', label: 'WAF / Origin' },
  { key: 'scans', label: 'Scans' },
  { key: 'owasp', label: 'OWASP' },
  { key: 'findings', label: 'Findings' },
  { key: 'notes', label: 'Notes' },
  { key: 'canvas', label: 'Canvas' },
  { key: 'jobs', label: 'Logs' },
  { key: 'settings', label: 'Settings' },
] as const

type ModuleKey = (typeof MODULES)[number]['key']

// Modules that operate on a selected domain show the domain picker.
const DOMAIN_SCOPED: ModuleKey[] = ['subdomains', 'screenshots', 'fuzzing', 'exposure', 'osint', 'origin', 'scans', 'owasp', 'notes']

export function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const { domains, selectedId, select } = useApp()
  const [active, setActive] = useState<ModuleKey>('domains')
  const [navOpen, setNavOpen] = useState(false)

  async function logout() {
    try {
      await api.logout()
    } finally {
      // Always drop the local session view, even if the request fails.
      onLogout()
    }
  }

  return (
    <div className="min-h-full bg-zinc-950 text-zinc-100 flex flex-col md:flex-row">
      <header className="md:hidden flex items-center justify-between border-b border-zinc-800 px-4 py-3">
        <button onClick={() => setNavOpen((v) => !v)} className="text-sm text-zinc-300">
          ☰ Menu
        </button>
        <span className="text-sm font-semibold">Recon Dashboard</span>
      </header>

      <aside
        className={`${navOpen ? 'block' : 'hidden'} md:block w-full md:w-52 shrink-0 border-b md:border-b-0 md:border-r border-zinc-800 bg-zinc-900/40 md:h-screen md:sticky md:top-0`}
      >
        <div className="hidden md:block px-4 py-4">
          <div className="text-sm font-semibold tracking-tight">Recon Dashboard</div>
          <div className="text-xs text-zinc-500">{me.user.username}</div>
        </div>
        <nav className="p-2">
          {MODULES.map((m) => (
            <button
              key={m.key}
              onClick={() => {
                setActive(m.key)
                setNavOpen(false)
              }}
              className={`block w-full rounded-lg px-3 py-2 text-left text-sm ${
                active === m.key ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:bg-zinc-800/50'
              }`}
            >
              {m.label}
            </button>
          ))}
        </nav>
        <div className="p-2 border-t border-zinc-800">
          <button
            onClick={logout}
            className="w-full rounded-lg px-3 py-2 text-left text-sm text-zinc-400 hover:bg-zinc-800/50"
          >
            Log out
          </button>
        </div>
      </aside>

      <main className="flex-1 p-6">
        {DOMAIN_SCOPED.includes(active) && domains.length > 0 && (
          <div className="mb-4 flex items-center gap-2 text-sm">
            <span className="text-zinc-500">Target:</span>
            <select
              value={selectedId ?? ''}
              onChange={(e) => select(Number(e.target.value))}
              className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm"
            >
              {domains.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.host} ({d.mode === 'active_authorized' ? 'active' : 'passive'})
                </option>
              ))}
            </select>
          </div>
        )}

        {active === 'domains' && <Domains />}
        {active === 'intel' && <Intel />}
        {active === 'subdomains' && <Subdomains />}
        {active === 'screenshots' && <Screenshots />}
        {active === 'fuzzing' && <Fuzzing />}
        {active === 'exposure' && <Exposure />}
        {active === 'osint' && <Osint />}
        {active === 'origin' && <Origin />}
        {active === 'scans' && <Scans />}
        {active === 'owasp' && <Owasp />}
        {active === 'findings' && <Findings />}
        {active === 'notes' && <Notes />}
        {active === 'canvas' && <Canvas />}
        {active === 'jobs' && <Jobs />}
        {active === 'settings' && <Settings totpEnabled={me.user.totpEnabled} />}
      </main>
    </div>
  )
}
