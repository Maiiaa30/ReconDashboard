import { listFindings } from '../findings/store'
import { listJobs } from '../jobs/queue'
import { safeJsonParse } from '../util/json'
import { SKILLS, type StepAction, type StepDetect } from './registry'
import { getStepOverrides } from './overrides'

// Computes methodology coverage for a domain from data we already store: which
// skills apply (tech fingerprint / open ports) and, per step, whether the
// matching job has run and/or produced a finding — plus any manual overrides.

export type StepStatus = 'found' | 'done' | 'running' | 'todo' | 'skipped'

export interface MethodologyStep {
  key: string
  label: string
  why: string
  action: StepAction
  status: StepStatus
  manual: boolean // status came from a manual override
}
export interface MethodologySkill {
  id: string
  name: string
  description: string
  applicable: boolean
  reason: string
  coverage: number // 0-100 over applicable (non-skipped) steps
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
  const overrides = getStepOverrides(domainId)

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

  const autoStatus = (detect: StepDetect): StepStatus => {
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

    const steps: MethodologyStep[] = s.steps.map((st) => {
      const auto = autoStatus(st.detect)
      const override = overrides.get(`${s.id}:${st.key}`)
      let status: StepStatus = auto
      let manual = false
      if (override === 'skipped') {
        status = 'skipped'
        manual = true
      } else if (override === 'done' && auto !== 'found') {
        status = 'done'
        manual = true
      }
      return { key: st.key, label: st.label, why: st.why, action: st.action, status, manual }
    })

    const counted = steps.filter((st) => st.status !== 'skipped')
    const covered = counted.filter((st) => st.status === 'found' || st.status === 'done').length
    const coverage = counted.length ? Math.round((covered / counted.length) * 100) : 100

    return { id: s.id, name: s.name, description: s.description, applicable, reason, coverage, steps }
  })

  return { tech: [...tech].sort(), ports: [...ports].sort((a, b) => a - b), skills }
}
