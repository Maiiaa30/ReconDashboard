import { listFindings } from '../findings/store'
import { listJobs } from '../jobs/queue'
import { safeJsonParse } from '../util/json'
import { SKILLS, type StepDetect } from './registry'

// Computes methodology coverage for a domain from data we already store: which
// skills apply (tech fingerprint / open ports) and, per step, whether the
// matching job has run and/or produced a finding. No new schema — pure read.

export type StepStatus = 'found' | 'done' | 'running' | 'todo'

export interface MethodologyStep {
  key: string
  label: string
  why: string
  run: string
  status: StepStatus
}
export interface MethodologySkill {
  id: string
  name: string
  description: string
  applicable: boolean
  reason: string
  coverage: number // 0-100 over applicable steps
  steps: MethodologyStep[]
}
export interface Methodology {
  tech: string[]
  ports: number[]
  skills: MethodologySkill[]
}

export function buildMethodology(domainId: number): Methodology {
  const findings = listFindings({ domainId, limit: 5000 })
  const jobs = listJobs(1000)
    .map((j) => ({ ...j, p: safeJsonParse<{ tool?: string; domainId?: number }>(j.params, {}) }))
    .filter((j) => j.domainId === domainId || j.p?.domainId === domainId)

  // Target signals.
  const tech = new Set<string>()
  const ports = new Set<number>()
  for (const f of findings) {
    for (const t of f.tags ?? []) if (t.startsWith('tech:')) tech.add(t.slice(5))
    const d = (f.data ?? {}) as any
    if (f.type === 'exposure' && Array.isArray(d.ports)) for (const p of d.ports) ports.add(Number(p))
    if (f.type === 'nmap' && Array.isArray(d.openPorts)) for (const p of d.openPorts) ports.add(Number(p?.port ?? p))
    if (f.type === 'tool' && d.tool === 'naabu' && Array.isArray(d.items)) for (const p of d.items) ports.add(Number(p))
  }

  const detectStatus = (detect: StepDetect): StepStatus => {
    // Finding-level match is the strongest signal (ran AND surfaced something).
    const found = findings.some((f) => {
      const d = (f.data ?? {}) as any
      if (detect.findingType && f.type === detect.findingType) return true
      if (detect.findingTool && f.type === 'tool' && d.tool === detect.findingTool) return true
      if (detect.owaspCategory && f.type === 'owasp' && String(d.category ?? '').startsWith(detect.owaspCategory)) return true
      return false
    })
    if (found) return 'found'

    const jobMatches = (statuses: string[]) =>
      jobs.some(
        (j) =>
          statuses.includes(j.status) &&
          (((detect.jobTypes?.includes(j.type as any)) ?? false) ||
            (!!detect.jobTool && j.type === 'tool_scan' && j.p?.tool === detect.jobTool)),
      )
    if (jobMatches(['done'])) return 'done'
    if (jobMatches(['queued', 'running'])) return 'running'
    return 'todo'
  }

  const skills = SKILLS.map((s) => {
    const matchedTech = (s.appliesWhen.tech ?? []).filter((t) => tech.has(t))
    const matchedPorts = (s.appliesWhen.ports ?? []).filter((p) => ports.has(p))
    const applicable = !!s.appliesWhen.always || matchedTech.length > 0 || matchedPorts.length > 0
    const reason = s.appliesWhen.always
      ? 'baseline'
      : [...matchedTech.map((t) => `tech:${t}`), ...matchedPorts.map((p) => `port ${p}`)].join(', ') || 'not matched'

    const steps: MethodologyStep[] = s.steps.map((st) => ({
      key: st.key,
      label: st.label,
      why: st.why,
      run: st.run,
      status: detectStatus(st.detect),
    }))
    const covered = steps.filter((st) => st.status === 'found' || st.status === 'done').length
    const coverage = steps.length ? Math.round((covered / steps.length) * 100) : 0

    return { id: s.id, name: s.name, description: s.description, applicable, reason, coverage, steps }
  })

  return { tech: [...tech].sort(), ports: [...ports].sort((a, b) => a - b), skills }
}
