import { AsyncLocalStorage } from 'node:async_hooks'

// Ambient "which job is running" context. The worker runs each handler inside
// runInJobContext(job.id, …) so addFinding() can stamp findings with the job that
// produced them without threading job.id through every source/handler/helper.
// AsyncLocalStorage (not a module-level var) keeps the two worker lanes
// (passive + loud) from clobbering each other's current job.
const store = new AsyncLocalStorage<{ jobId: number }>()

export function runInJobContext<T>(jobId: number, fn: () => Promise<T>): Promise<T> {
  return store.run({ jobId }, fn)
}

export function currentJobId(): number | null {
  return store.getStore()?.jobId ?? null
}
