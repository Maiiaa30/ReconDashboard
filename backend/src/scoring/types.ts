import type { FindingType } from '../findings/store'

export interface ScoreInput {
  type: FindingType
  data: unknown
}

export interface ScoreResult {
  score: number // 0-100, higher = more interesting
  tags: string[]
}

// A Scorer turns a finding into a priority score + tags. The interface is async
// so a future network-backed provider (e.g. local Ollama) can slot in without
// touching any caller.
export interface Scorer {
  readonly name: string
  score(input: ScoreInput): Promise<ScoreResult>
}
