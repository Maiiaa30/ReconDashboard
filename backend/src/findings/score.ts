import { getScorer } from '../scoring'
import { addFinding, type NewFinding } from './store'

// Score a finding with the active scorer, then persist it.
export async function addScoredFinding(f: Omit<NewFinding, 'score'>): Promise<number> {
  const { score, tags } = await getScorer().score({ type: f.type, data: f.data })
  return addFinding({
    ...f,
    score,
    tags: [...new Set([...(f.tags ?? []), ...tags])],
  })
}
