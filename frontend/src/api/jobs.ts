import { z } from 'zod'
import { get, post, type RequestOptions } from './http'
import { jobSchema } from './schemas'

// Types now live with their schema (single source of truth).
export type { Job, JobStatus } from './schemas'

const jobsResponse = z.object({ jobs: z.array(jobSchema) }).passthrough()
const jobResponse = z.object({ job: jobSchema }).passthrough()

export const jobsApi = {
  jobs: (options?: RequestOptions) => get('/jobs', options, jobsResponse),
  job: (id: number) => get(`/jobs/${id}`, {}, jobResponse),
  cancelJob: (id: number) => post(`/jobs/${id}/cancel`, undefined, jobResponse),
}
