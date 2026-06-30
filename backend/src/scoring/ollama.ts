import type { Scorer, ScoreInput, ScoreResult } from './types'

// DISABLED placeholder. The local-LLM scorer is intentionally NOT implemented
// yet. It exists only so the provider selection in index.ts has a second branch
// and so a future implementation can be dropped in here without touching any
// caller. Selecting AI_PROVIDER=ollama today throws at startup on purpose.
export class OllamaScorer implements Scorer {
  readonly name = 'ollama'

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async score(_input: ScoreInput): Promise<ScoreResult> {
    throw new Error('Ollama scorer is not implemented yet (AI_PROVIDER=ollama is disabled)')
  }
}
