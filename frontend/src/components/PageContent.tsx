import { lazy, Suspense } from 'react'
import { SkeletonList } from './ui'
import type { ModuleKey } from './navigation'

const Home = lazy(() => import('../pages/Home').then((module) => ({ default: module.Home })))
const CommandCenter = lazy(() => import('../pages/CommandCenter').then((module) => ({ default: module.CommandCenter })))
const NextActions = lazy(() => import('../pages/NextActions').then((module) => ({ default: module.NextActions })))
const Domains = lazy(() => import('../pages/Domains').then((module) => ({ default: module.Domains })))
const Assets = lazy(() => import('../pages/Assets').then((module) => ({ default: module.Assets })))
const ScanProfiles = lazy(() => import('../pages/ScanProfiles').then((module) => ({ default: module.ScanProfiles })))
const AssessmentRuns = lazy(() => import('../pages/AssessmentRuns').then((module) => ({ default: module.AssessmentRuns })))
const Reports = lazy(() => import('../pages/Reports').then((module) => ({ default: module.Reports })))
const Changes = lazy(() => import('../pages/Changes').then((module) => ({ default: module.Changes })))
const Intel = lazy(() => import('../pages/Intel').then((module) => ({ default: module.Intel })))
const Methodology = lazy(() => import('../pages/Methodology').then((module) => ({ default: module.Methodology })))
const Subdomains = lazy(() => import('../pages/Subdomains').then((module) => ({ default: module.Subdomains })))
const Screenshots = lazy(() => import('../pages/Screenshots').then((module) => ({ default: module.Screenshots })))
const Fuzzing = lazy(() => import('../pages/Fuzzing').then((module) => ({ default: module.Fuzzing })))
const Replay = lazy(() => import('../pages/Replay').then((module) => ({ default: module.Replay })))
const Traffic = lazy(() => import('../pages/Traffic').then((module) => ({ default: module.Traffic })))
const Exposure = lazy(() => import('../pages/Exposure').then((module) => ({ default: module.Exposure })))
const Ports = lazy(() => import('../pages/Ports').then((module) => ({ default: module.Ports })))
const ApiSurface = lazy(() => import('../pages/ApiSurface').then((module) => ({ default: module.ApiSurface })))
const Osint = lazy(() => import('../pages/Osint').then((module) => ({ default: module.Osint })))
const SocialForensics = lazy(() => import('../pages/SocialForensics').then((module) => ({ default: module.SocialForensics })))
const DataLeaks = lazy(() => import('../pages/DataLeaks').then((module) => ({ default: module.DataLeaks })))
const Origin = lazy(() => import('../pages/Origin').then((module) => ({ default: module.Origin })))
const Whois = lazy(() => import('../pages/Whois').then((module) => ({ default: module.Whois })))
const CheckHost = lazy(() => import('../pages/CheckHost').then((module) => ({ default: module.CheckHost })))
const Scans = lazy(() => import('../pages/Scans').then((module) => ({ default: module.Scans })))
const Tools = lazy(() => import('../pages/Tools').then((module) => ({ default: module.Tools })))
const Owasp = lazy(() => import('../pages/Owasp').then((module) => ({ default: module.Owasp })))
const LlmSecurity = lazy(() => import('../pages/LlmSecurity').then((module) => ({ default: module.LlmSecurity })))
const Findings = lazy(() => import('../pages/Findings').then((module) => ({ default: module.Findings })))
const Notes = lazy(() => import('../pages/Notes').then((module) => ({ default: module.Notes })))
const Canvas = lazy(() => import('../pages/Canvas').then((module) => ({ default: module.Canvas })))
const Jobs = lazy(() => import('../pages/Jobs').then((module) => ({ default: module.Jobs })))
const Audit = lazy(() => import('../pages/Audit').then((module) => ({ default: module.Audit })))
const Settings = lazy(() => import('../pages/Settings').then((module) => ({ default: module.Settings })))

export const PAGE_KEYS: readonly ModuleKey[] = [
  'home', 'command', 'actions', 'domains', 'assets', 'profiles', 'runs', 'reports', 'changes', 'intel',
  'methodology', 'subdomains', 'screenshots', 'fuzzing', 'replay', 'traffic', 'exposure', 'ports', 'api',
  'osint', 'social', 'leaks', 'origin', 'whois', 'checkhost', 'scans', 'tools', 'owasp', 'llm', 'findings',
  'notes', 'canvas', 'jobs', 'audit', 'settings',
]

interface PageContentProps {
  active: ModuleKey
  navigate: (page: string, domainId?: number) => void
  totpEnabled: boolean
}

function ActivePage({ active, navigate, totpEnabled }: PageContentProps) {
  switch (active) {
    case 'home': return <Home navigate={navigate} />
    case 'command': return <CommandCenter navigate={navigate} />
    case 'actions': return <NextActions navigate={navigate} />
    case 'domains': return <Domains />
    case 'assets': return <Assets navigate={navigate} />
    case 'profiles': return <ScanProfiles navigate={navigate} />
    case 'runs': return <AssessmentRuns navigate={navigate} />
    case 'reports': return <Reports navigate={navigate} />
    case 'changes': return <Changes navigate={navigate} />
    case 'intel': return <Intel navigate={navigate} />
    case 'methodology': return <Methodology navigate={navigate} />
    case 'subdomains': return <Subdomains />
    case 'screenshots': return <Screenshots />
    case 'fuzzing': return <Fuzzing />
    case 'replay': return <Replay />
    case 'traffic': return <Traffic navigate={navigate} />
    case 'exposure': return <Exposure />
    case 'ports': return <Ports />
    case 'api': return <ApiSurface navigate={navigate} />
    case 'osint': return <Osint />
    case 'social': return <SocialForensics />
    case 'leaks': return <DataLeaks />
    case 'origin': return <Origin />
    case 'whois': return <Whois />
    case 'checkhost': return <CheckHost />
    case 'scans': return <Scans />
    case 'tools': return <Tools />
    case 'owasp': return <Owasp />
    case 'llm': return <LlmSecurity />
    case 'findings': return <Findings navigate={navigate} />
    case 'notes': return <Notes />
    case 'canvas': return <Canvas />
    case 'jobs': return <Jobs />
    case 'audit': return <Audit />
    case 'settings': return <Settings totpEnabled={totpEnabled} />
  }
}

export function PageContent(props: PageContentProps) {
  return (
    <Suspense fallback={<SkeletonList rows={6} />}>
      <ActivePage {...props} />
    </Suspense>
  )
}
