import { and, eq, isNull, or } from 'drizzle-orm'
import { db } from '../db/index'
import { matchReplaceRules } from '../db/schema'
import { orderRules, type MatchReplaceRule, type RulePart } from './matchReplace'

const PARTS: RulePart[] = ['url', 'header', 'body']

function mapRow(r: typeof matchReplaceRules.$inferSelect): MatchReplaceRule {
  return {
    id: r.id,
    domainId: r.domainId,
    name: r.name,
    enabled: r.enabled,
    part: (PARTS.includes(r.part as RulePart) ? r.part : 'url') as RulePart,
    match: r.match,
    replace: r.replace,
    isRegex: r.isRegex,
  }
}

export function listRules(): MatchReplaceRule[] {
  return db.select().from(matchReplaceRules).orderBy(matchReplaceRules.id).all().map(mapRow)
}

// Rules that apply to a request for this domain: global (domain_id null) + the
// domain's own, ordered global-first so a domain rule can override a global one.
export function applicableRules(domainId: number | null): MatchReplaceRule[] {
  const rows = db
    .select()
    .from(matchReplaceRules)
    .where(
      and(
        eq(matchReplaceRules.enabled, true),
        domainId == null ? isNull(matchReplaceRules.domainId) : or(isNull(matchReplaceRules.domainId), eq(matchReplaceRules.domainId, domainId)),
      ),
    )
    .all()
    .map(mapRow)
  return orderRules(rows)
}

export function getRule(id: number): MatchReplaceRule | undefined {
  const r = db.select().from(matchReplaceRules).where(eq(matchReplaceRules.id, id)).limit(1).all()[0]
  return r ? mapRow(r) : undefined
}

export function createRule(input: { name: string; domainId?: number | null; part: RulePart; match?: string; replace?: string; isRegex?: boolean; enabled?: boolean }): MatchReplaceRule {
  const part: RulePart = PARTS.includes(input.part) ? input.part : 'url'
  const res = db
    .insert(matchReplaceRules)
    .values({
      name: input.name.slice(0, 120),
      domainId: input.domainId ?? null,
      part,
      match: (input.match ?? '').slice(0, 2000),
      replace: (input.replace ?? '').slice(0, 4000),
      isRegex: input.isRegex ?? false,
      enabled: input.enabled ?? true,
    })
    .run()
  return getRule(Number(res.lastInsertRowid))!
}

export function updateRule(id: number, patch: Partial<{ name: string; domainId: number | null; part: RulePart; match: string; replace: string; isRegex: boolean; enabled: boolean }>): MatchReplaceRule | undefined {
  const set: Record<string, unknown> = { updatedAt: new Date() }
  if (patch.name !== undefined) set.name = patch.name.slice(0, 120)
  if (patch.domainId !== undefined) set.domainId = patch.domainId
  if (patch.part !== undefined && PARTS.includes(patch.part)) set.part = patch.part
  if (patch.match !== undefined) set.match = patch.match.slice(0, 2000)
  if (patch.replace !== undefined) set.replace = patch.replace.slice(0, 4000)
  if (patch.isRegex !== undefined) set.isRegex = patch.isRegex
  if (patch.enabled !== undefined) set.enabled = patch.enabled
  db.update(matchReplaceRules).set(set).where(eq(matchReplaceRules.id, id)).run()
  return getRule(id)
}

export function deleteRule(id: number): boolean {
  return db.delete(matchReplaceRules).where(eq(matchReplaceRules.id, id)).run().changes > 0
}
