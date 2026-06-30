import { config } from '../config'
import { RulesScorer } from './rules'
import type { Scorer } from './types'

let scorer: Scorer

export function getScorer(): Scorer {
  if (!scorer) {
    if (config.aiProvider === 'ollama') {
      // Disabled placeholder (see ollama.ts). Fail FAST here — called once at
      // startup — rather than silently failing every job's scoring later.
      throw new Error('AI_PROVIDER=ollama is not implemented yet. Use AI_PROVIDER=rules.')
    }
    scorer = new RulesScorer()
  }
  return scorer
}

export type { Scorer, ScoreInput, ScoreResult } from './types'
