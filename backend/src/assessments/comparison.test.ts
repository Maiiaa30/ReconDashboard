import { describe, expect, it } from 'vitest'
import { compareFindingSnapshots, type AssessmentFindingSnapshot } from './runs'

function finding(findingKey: string, score = 40, status = 'open'): AssessmentFindingSnapshot {
  return { findingKey, findingId: null, type: 'nuclei', title: findingKey, target: 'example.com', score, severity: 'medium', status }
}

describe('assessment finding comparison', () => {
  it('classifies new, unchanged, resolved and regressed findings', () => {
    const comparison = compareFindingSnapshots(
      [finding('same'), finding('new'), finding('worse', 80), finding('reopened', 30, 'open')],
      [finding('same'), finding('gone'), finding('worse', 40), finding('reopened', 30, 'resolved')],
    )
    expect(comparison.counts).toEqual({ new: 1, unchanged: 1, resolved: 1, regressed: 2 })
    expect(comparison.new.map((item) => item.findingKey)).toEqual(['new'])
    expect(comparison.resolved.map((item) => item.findingKey)).toEqual(['gone'])
  })
})
