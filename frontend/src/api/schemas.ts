import { z } from 'zod'

// Runtime contracts for the core transport objects, and the single source of
// truth for their TypeScript types (exported via z.infer). Every object schema is
// `.passthrough()` so a backend that adds a field still validates — only a
// missing or wrong-typed known field is a contract violation worth failing on.
//
// Scanner-specific freeform payloads stay `unknown` (Finding.data, Job params/
// result): they are genuinely open-ended and validated by the code that reads
// them, not at the transport boundary.

// --- Job ---------------------------------------------------------------------
export const jobStatusSchema = z.enum(['queued', 'running', 'done', 'error', 'cancelled', 'dead'])

export const jobSchema = z
  .object({
    id: z.number(),
    type: z.string(),
    status: jobStatusSchema,
    domainId: z.number().nullable(),
    params: z.unknown(),
    result: z.unknown(),
    error: z.string().nullable(),
    progress: z.string().nullable(),
    createdAt: z.string(),
    startedAt: z.string().nullable(),
    finishedAt: z.string().nullable(),
    updatedAt: z.string(),
  })
  .passthrough()

// --- Finding -----------------------------------------------------------------
export const findingStatusSchema = z.enum([
  'open', 'confirmed', 'retest_pending', 'retest_passed', 'false_positive', 'resolved', 'ignored',
])

export const findingSchema = z
  .object({
    id: z.number(),
    domainId: z.number().nullable(),
    type: z.string(),
    data: z.any(),
    score: z.number().nullable(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).nullable(),
    host: z.string().nullable(),
    ip: z.string().nullable(),
    url: z.string().nullable(),
    jobId: z.number().nullable(),
    tags: z.array(z.string()),
    status: findingStatusSchema,
    note: z.string().nullable(),
    createdAt: z.string(),
    lastSeenAt: z.string().nullable(),
    retestRequestedAt: z.string().nullable(),
  })
  .passthrough()

export const findingPageSchema = z
  .object({ findings: z.array(findingSchema), nextCursor: z.string().nullable() })
  .passthrough()

export const findingSummarySchema = z
  .object({
    total: z.number(),
    byStatus: z.record(z.number()),
    bySeverity: z.record(z.number()),
  })
  .passthrough()

// --- Subdomain ---------------------------------------------------------------
export const subdomainSchema = z
  .object({
    id: z.number(),
    domainId: z.number(),
    host: z.string(),
    source: z.string().nullable(),
    isNew: z.boolean(),
    ipAddress: z.string().nullable(),
    httpStatus: z.number().nullable(),
    title: z.string().nullable(),
    server: z.string().nullable(),
    scheme: z.string().nullable(),
    waf: z.string().nullable(),
    certFp: z.string().nullable(),
    faviconHash: z.number().nullable(),
    probedAt: z.string().nullable(),
    screenshotPath: z.string().nullable(),
    screenshotAt: z.string().nullable(),
    firstSeen: z.string(),
    lastSeen: z.string(),
  })
  .passthrough()

export const subdomainPageSchema = z
  .object({ subdomains: z.array(subdomainSchema), nextCursor: z.string().nullable() })
  .passthrough()

export const subdomainSummarySchema = z
  .object({ total: z.number(), newCount: z.number() })
  .passthrough()

// Inferred types — import these instead of re-declaring the shapes by hand.
export type JobStatus = z.infer<typeof jobStatusSchema>
export type Job = z.infer<typeof jobSchema>
export type FindingStatus = z.infer<typeof findingStatusSchema>
export type Finding = z.infer<typeof findingSchema>
export type FindingPage = z.infer<typeof findingPageSchema>
export type FindingSummary = z.infer<typeof findingSummarySchema>
export type Subdomain = z.infer<typeof subdomainSchema>
export type SubdomainPage = z.infer<typeof subdomainPageSchema>
export type SubdomainSummary = z.infer<typeof subdomainSummarySchema>
