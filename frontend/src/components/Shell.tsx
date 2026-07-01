import { useState } from 'react'
import {
  Home as HomeIcon, Globe, Brain, Network, Camera, Crosshair, Radar, Eye, ShieldAlert, FileText,
  Activity, ScanSearch, ShieldCheck, Flag, StickyNote, PenTool, ScrollText,
  Settings as SettingsIcon, LogOut, Menu, Radar as RadarLogo, Wrench, History, type LucideIcon,
} from 'lucide-react'
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
import { Whois } from '../pages/Whois'
import { CheckHost } from '../pages/CheckHost'
import { Scans } from '../pages/Scans'
import { Tools } from '../pages/Tools'
import { Owasp } from '../pages/Owasp'
import { Notes } from '../pages/Notes'
import { Canvas } from '../pages/Canvas'
import { Findings } from '../pages/Findings'
import { Jobs } from '../pages/Jobs'
import { Audit } from '../pages/Audit'
import { Home } from '../pages/Home'
import { Settings } from '../pages/Settings'

const MODULES: { key: string; label: string; icon: LucideIcon }[] = [
  { key: 'home', label: 'Home', icon: HomeIcon },
  { key: 'domains', label: 'Domains', icon: Globe },
  { key: 'intel', label: 'Intel', icon: Brain },
  { key: 'subdomains', label: 'Subdomains', icon: Network },
  { key: 'screenshots', label: 'Screenshots', icon: Camera },
  { key: 'fuzzing', label: 'Fuzzing', icon: Crosshair },
  { key: 'exposure', label: 'Exposure', icon: Radar },
  { key: 'osint', label: 'OSINT', icon: Eye },
  { key: 'origin', label: 'WAF / Origin', icon: ShieldAlert },
  { key: 'whois', label: 'WHOIS', icon: FileText },
  { key: 'checkhost', label: 'Check Host', icon: Activity },
  { key: 'scans', label: 'Scans', icon: ScanSearch },
  { key: 'tools', label: 'Tools', icon: Wrench },
  { key: 'owasp', label: 'OWASP', icon: ShieldCheck },
  { key: 'findings', label: 'Findings', icon: Flag },
  { key: 'notes', label: 'Notes', icon: StickyNote },
  { key: 'canvas', label: 'Canvas', icon: PenTool },
  { key: 'jobs', label: 'Logs', icon: ScrollText },
  { key: 'audit', label: 'Audit', icon: History },
  { key: 'settings', label: 'Settings', icon: SettingsIcon },
]

type ModuleKey = (typeof MODULES)[number]['key']

// Modules that operate on a selected domain show the domain picker.
const DOMAIN_SCOPED: ModuleKey[] = ['intel', 'subdomains', 'screenshots', 'fuzzing', 'exposure', 'osint', 'origin', 'scans', 'tools', 'owasp', 'notes']

export function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const { domains, selectedId, select } = useApp()
  const [active, setActive] = useState<ModuleKey>('home')
  const [navOpen, setNavOpen] = useState(false)

  // Deep-link from cross-target views (Home): switch page and optionally target.
  const navigate = (page: string, domainId?: number) => {
    if (domainId != null) select(domainId)
    setActive(page)
    setNavOpen(false)
  }

  async function logout() {
    try {
      await api.logout()
    } finally {
      // Always drop the local session view, even if the request fails.
      onLogout()
    }
  }

  return (
    <div className="min-h-full bg-ink-950 text-zinc-100 flex flex-col md:flex-row">
      <header className="md:hidden flex items-center justify-between border-b border-hair px-4 py-3">
        <button onClick={() => setNavOpen((v) => !v)} className="flex items-center gap-2 text-sm text-zinc-300">
          <Menu size={18} /> Menu
        </button>
        <span className="text-sm font-semibold">Recon Dashboard</span>
      </header>

      <aside
        className={`${navOpen ? 'block' : 'hidden'} md:flex md:flex-col w-full md:w-56 shrink-0 border-b md:border-b-0 md:border-r border-hair bg-ink-900 md:h-screen md:sticky md:top-0`}
      >
        <div className="hidden md:flex items-center gap-2.5 px-4 py-4">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent-500 shadow-sm shadow-accent-500/30">
            <RadarLogo size={18} className="text-white" />
          </span>
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold tracking-tight">Recon Dashboard</div>
            <div className="truncate text-xs text-zinc-500">{me.user.username}</div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto p-2">
          {MODULES.map((m) => {
            const Icon = m.icon
            const isActive = active === m.key
            return (
              <button
                key={m.key}
                onClick={() => {
                  setActive(m.key)
                  setNavOpen(false)
                }}
                className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition ${
                  isActive
                    ? 'bg-accent-500/15 font-medium text-accent-fg'
                    : 'text-zinc-400 hover:bg-ink-800 hover:text-zinc-200'
                }`}
              >
                <Icon size={17} className={isActive ? 'text-accent-400' : 'text-zinc-500'} />
                {m.label}
              </button>
            )
          })}
        </nav>
        <div className="p-2 border-t border-hair">
          <button
            onClick={logout}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm text-zinc-400 hover:bg-ink-800 hover:text-zinc-200"
          >
            <LogOut size={17} className="text-zinc-500" /> Log out
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
              className="rounded-lg border border-hair bg-ink-850 px-3 py-1.5 text-sm outline-none transition hover:border-hair-strong focus:border-accent-500"
            >
              {domains.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.host} ({d.mode === 'active_authorized' ? 'active' : 'passive'})
                </option>
              ))}
            </select>
          </div>
        )}

        {active === 'home' && <Home navigate={navigate} />}
        {active === 'domains' && <Domains />}
        {active === 'intel' && <Intel />}
        {active === 'subdomains' && <Subdomains />}
        {active === 'screenshots' && <Screenshots />}
        {active === 'fuzzing' && <Fuzzing />}
        {active === 'exposure' && <Exposure />}
        {active === 'osint' && <Osint />}
        {active === 'origin' && <Origin />}
        {active === 'whois' && <Whois />}
        {active === 'checkhost' && <CheckHost />}
        {active === 'scans' && <Scans />}
        {active === 'tools' && <Tools />}
        {active === 'owasp' && <Owasp />}
        {active === 'findings' && <Findings />}
        {active === 'notes' && <Notes />}
        {active === 'canvas' && <Canvas />}
        {active === 'jobs' && <Jobs />}
        {active === 'audit' && <Audit />}
        {active === 'settings' && <Settings totpEnabled={me.user.totpEnabled} />}
      </main>
    </div>
  )
}
