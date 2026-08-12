import { and, eq, isNull, lt, or } from 'drizzle-orm'
import { db } from '../db/index'
import { users } from '../db/schema'
import { checkTotpStep } from './totp'

// Verify and atomically consume a TOTP time-step. The conditional update makes
// concurrent reuse of the same valid code fail closed.
export function consumeTotp(op: { id: number; totpSecret: string }, token: string): boolean {
  const step = checkTotpStep(token, op.totpSecret)
  if (step == null) return false
  const consumed = db
    .update(users)
    .set({ lastTotpStep: step, updatedAt: new Date() })
    .where(and(eq(users.id, op.id), or(isNull(users.lastTotpStep), lt(users.lastTotpStep, step))))
    .run()
  return consumed.changes === 1
}
