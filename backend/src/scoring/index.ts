import { config } from '../config'
import { RulesScorer } from './rules'
import type { Scorer } from './types'

let scorer: Scorer

export function getScorer(): Scorer {
  if (!scorer) {
    if (config.aiProvider === 'ollama') {
      // Not implemented — fail FAST here (called once at startup) rather than
      // silently failing every job's scoring later. Scoring stays deterministic
      // (the narrative-only LLM in util/llm.ts is a separate, opt-in feature).
      throw new Error('AI_PROVIDER=ollama is not implemented yet. Use AI_PROVIDER=rules.')
    }
    scorer = new RulesScorer()
  }
  return scorer
}

export type { Scorer, ScoreInput, ScoreResult } from './types'
