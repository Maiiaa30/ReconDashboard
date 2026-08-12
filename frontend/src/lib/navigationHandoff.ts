export interface PendingScan {
  target: string
  ports?: string
}

export interface PendingFindingFilter {
  domainId?: number
  asset: string
}

let pendingScan: PendingScan | null = null
let pendingFindingFilter: PendingFindingFilter | null = null

export function setPendingScan(value: PendingScan): void {
  pendingScan = value
}

export function takePendingScan(): PendingScan | null {
  const value = pendingScan
  pendingScan = null
  return value
}

export function setPendingFindingFilter(value: PendingFindingFilter): void {
  pendingFindingFilter = value
}

export function takePendingFindingFilter(): PendingFindingFilter | null {
  const value = pendingFindingFilter
  pendingFindingFilter = null
  return value
}
