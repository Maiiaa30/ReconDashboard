import { beforeEach, describe, expect, it } from 'vitest'
import {
  setPendingFindingFilter,
  setPendingOwasp,
  setPendingScan,
  takePendingFindingFilter,
  takePendingOwasp,
  takePendingScan,
} from './navigationHandoff'

describe('navigation handoffs', () => {
  beforeEach(() => {
    takePendingFindingFilter()
    takePendingOwasp()
    takePendingScan()
  })

  it('delivers a scan handoff exactly once', () => {
    setPendingScan({ target: 'api.example.test', ports: '443,8443' })

    expect(takePendingScan()).toEqual({ target: 'api.example.test', ports: '443,8443' })
    expect(takePendingScan()).toBeNull()
  })

  it('keeps independent handoff channels isolated', () => {
    setPendingFindingFilter({ domainId: 7, asset: '10.0.0.7' })
    setPendingOwasp({ target: 'web.example.test' })

    expect(takePendingOwasp()).toEqual({ target: 'web.example.test' })
    expect(takePendingFindingFilter()).toEqual({ domainId: 7, asset: '10.0.0.7' })
  })
})
