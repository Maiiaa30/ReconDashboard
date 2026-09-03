import { get, post, type RequestOptions } from './http'

export type JobStatus = 'queued' | 'running' | 'done' | 'error' | 'cancelled' | 'dead'

export interface Job {
  id: number
  type: string
  status: JobStatus
  domainId: number | null
  params: unknown
  result: unknown
  error: string | null
  progress: string | null
  createdAt: string
  startedAt: string | null
  finishedAt: string | null
  updatedAt: string
}

export const jobsApi = {
  jobs: (options?: RequestOptions) => get<{ jobs: Job[] }>('/jobs', options),
  job: (id: number) => get<{ job: Job }>(`/jobs/${id}`),
  cancelJob: (id: number) => post<{ job: Job }>(`/jobs/${id}/cancel`),
}
