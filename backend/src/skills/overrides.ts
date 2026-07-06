import { and, eq } from 'drizzle-orm'
import { db } from '../db/index'
import { skillStepState } from '../db/schema'

export type OverrideState = 'done' | 'skipped'

// All manual step overrides for a domain, keyed by `${skillId}:${stepKey}`.
export function getStepOverrides(domainId: number): Map<string, OverrideState> {
  const rows = db.select().from(skillStepState).where(eq(skillStepState.domainId, domainId)).all()
  const map = new Map<string, OverrideState>()
  for (const r of rows) map.set(`${r.skillId}:${r.stepKey}`, r.state as OverrideState)
  return map
}

// Set/clear a manual override. state 'clear' removes any override (revert to auto).
export function setStepOverride(
  domainId: number,
  skillId: string,
  stepKey: string,
  state: OverrideState | 'clear',
): void {
  if (state === 'clear') {
    db.delete(skillStepState)
      .where(
        and(
          eq(skillStepState.domainId, domainId),
          eq(skillStepState.skillId, skillId),
          eq(skillStepState.stepKey, stepKey),
        ),
      )
      .run()
    return
  }
  db.insert(skillStepState)
    .values({ domainId, skillId, stepKey, state, updatedAt: new Date() })
    .onConflictDoUpdate({
      target: [skillStepState.domainId, skillStepState.skillId, skillStepState.stepKey],
      set: { state, updatedAt: new Date() },
    })
    .run()
}
