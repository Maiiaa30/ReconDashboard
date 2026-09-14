import { z, type ZodTypeAny } from 'zod'

// Backend-side runtime contracts for the core transport objects the API returns.
//
// WHY: the frontend already validates these shapes on receipt
// (`frontend/src/api/schemas.ts`), which surfaces drift as a runtime failure in
// the browser. These schemas move that guard to the SOURCE: a `preSerialization`
// hook (see `responseValidation.ts`) checks a flagged route's payload before it
// leaves the backend, so a backend shape change that used to compile cleanly and
// only break at runtime now fails loud in the backend test suite / CI instead.
//
// These definitions MIRROR `frontend/src/api/schemas.ts` — keep the two in sync
// when a transport object changes. Unifying them into one shared module is the
// deferred monorepo step (both packages currently build independently).
//
// Every object schema is `.passthrough()` so an ADDITIVE backend change (a new
// field) still validates — only a missing or wrong-typed KNOWN field is a
// contract violation worth failing on. Freeform scanner payloads (Finding.data,
// Job params/result) stay open (`z.unknown()`/`z.any()`): they are validated by
// the code that reads them, not at the transport boundary.

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

export const jobListSchema = z.object({ jobs: z.array(jobSchema) }).passthrough()

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

// --- Capture -----------------------------------------------------------------
export const captureSchema = z
  .object({
    id: z.number(),
    domainId: z.number().nullable(),
    method: z.string(),
    url: z.string(),
    host: z.string(),
    headers: z.array(z.tuple([z.string(), z.string()])),
    body: z.string().nullable(),
    hasBody: z.boolean().optional(),
    source: z.string(),
    createdAt: z.string(),
  })
  .passthrough()

export const capturePageSchema = z
  .object({ captures: z.array(captureSchema), nextCursor: z.string().nullable() })
  .passthrough()

export const captureSummarySchema = z
  .object({ total: z.number(), byMethod: z.record(z.number()) })
  .passthrough()

// --- Audit -------------------------------------------------------------------
export const auditEntrySchema = z
  .object({
    id: z.number(),
    ts: z.string(),
    actor: z.string(),
    action: z.string(),
    domainId: z.number().nullable(),
    target: z.string().nullable(),
    mode: z.string().nullable(),
    jobId: z.number().nullable(),
    detail: z.string().nullable(),
  })
  .passthrough()

export const auditPageSchema = z
  .object({ entries: z.array(auditEntrySchema), nextCursor: z.string().nullable() })
  .passthrough()

export const auditSummarySchema = z
  .object({ total: z.number(), byAction: z.record(z.number()) })
  .passthrough()

// --- Inferred types (available to backend code that wants the shared shape) ---
export type Job = z.infer<typeof jobSchema>
export type Finding = z.infer<typeof findingSchema>
export type FindingPage = z.infer<typeof findingPageSchema>
export type FindingSummary = z.infer<typeof findingSummarySchema>
export type Subdomain = z.infer<typeof subdomainSchema>
export type SubdomainPage = z.infer<typeof subdomainPageSchema>

// --- Response contract registry ----------------------------------------------
// Maps `"<METHOD> <route-pattern>"` (the Fastify route URL, params as `:id`) to
// the schema its 2xx JSON payload must satisfy. The preSerialization hook looks
// each response up here; a route with no entry is not validated (opt-in, so
// migration is incremental and un-covered routes are unaffected).
export const responseContracts: Record<string, ZodTypeAny> = {
  'GET /api/jobs': jobListSchema,
  'GET /api/findings': findingPageSchema,
  'GET /api/findings/summary': findingSummarySchema,
  'GET /api/domains/:id/subdomains/page': subdomainPageSchema,
  'GET /api/domains/:id/subdomains/summary': subdomainSummarySchema,
  'GET /api/capture': capturePageSchema,
  'GET /api/capture/summary': captureSummarySchema,
  'GET /api/audit': auditPageSchema,
  'GET /api/audit/summary': auditSummarySchema,
}
