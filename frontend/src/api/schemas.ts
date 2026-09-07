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

// --- Domain ------------------------------------------------------------------
export const domainModeSchema = z.enum(['passive_only', 'active_authorized'])

export const domainProfileSchema = z
  .object({
    hasLogin: z.boolean(),
    hasParams: z.boolean(),
    hasUpload: z.boolean(),
    hasApi: z.boolean(),
    hasRedirects: z.boolean(),
  })
  .partial()
  .passthrough()

export const owaspConfigSchema = z
  .object({
    xssParams: z.array(z.string()),
    xssPayloads: z.array(z.string()),
    redirectParams: z.array(z.string()),
    sensitivePaths: z.array(z.string()),
    authHeader: z.string(),
  })
  .partial()
  .passthrough()

export const scopeConfigSchema = z
  .object({ allow: z.array(z.string()), deny: z.array(z.string()) })
  .partial()
  .passthrough()

export const domainSchema = z
  .object({
    id: z.number(),
    host: z.string(),
    label: z.string().nullable(),
    mode: domainModeSchema,
    profile: domainProfileSchema.optional(),
    owaspConfig: owaspConfigSchema.optional(),
    scopeConfig: scopeConfigSchema.optional(),
    authorizedFrom: z.string().nullable().optional(),
    authorizedUntil: z.string().nullable().optional(),
    monitorIntervalHours: z.number().optional(),
    createdAt: z.string(),
    updatedAt: z.string(),
  })
  .passthrough()

export const domainOverviewSchema = z
  .object({
    id: z.number(),
    host: z.string(),
    label: z.string().nullable(),
    mode: domainModeSchema,
    createdAt: z.number().nullable(),
    subdomains: z.object({ total: z.number(), new: z.number() }).passthrough(),
    findings: z.object({ total: z.number(), maxScore: z.number().nullable() }).passthrough(),
    exposure: z.object({ ips: z.number(), openPorts: z.number(), cves: z.number() }).passthrough(),
    lastActivity: z.number().nullable(),
    monitorIntervalHours: z.number(),
  })
  .passthrough()

// --- Home overview -----------------------------------------------------------
export const homeFindingSchema = z
  .object({
    id: z.number(),
    domainId: z.number().nullable(),
    type: z.string(),
    data: z.any(),
    score: z.number().nullable(),
    tags: z.array(z.string()),
  })
  .passthrough()

export const recentChangeSchema = z
  .object({
    id: z.number(),
    domainId: z.number().nullable(),
    type: z.enum(['cve_new', 'asset_change']),
    data: z
      .object({
        ip: z.string(),
        host: z.string(),
        cveId: z.string(),
        cvss: z.number().nullable(),
        kev: z.boolean(),
        title: z.string(),
        detail: z.string(),
        action: z.object({ kind: z.enum(['nmap', 'owasp']), label: z.string(), target: z.string() }).passthrough(),
      })
      .partial()
      .passthrough(),
    score: z.number().nullable(),
    createdAt: z.string(),
  })
  .passthrough()

export const homeResponseSchema = z
  .object({
    overview: z.array(domainOverviewSchema),
    topFindings: z.array(homeFindingSchema),
    recentChanges: z.array(recentChangeSchema),
  })
  .passthrough()

export type Capture = z.infer<typeof captureSchema>
export type CapturePage = z.infer<typeof capturePageSchema>
export type CaptureSummary = z.infer<typeof captureSummarySchema>
export type AuditEntry = z.infer<typeof auditEntrySchema>
export type AuditPage = z.infer<typeof auditPageSchema>
export type AuditSummary = z.infer<typeof auditSummarySchema>
export type DomainMode = z.infer<typeof domainModeSchema>
export type DomainProfile = z.infer<typeof domainProfileSchema>
export type OwaspConfig = z.infer<typeof owaspConfigSchema>
export type ScopeConfig = z.infer<typeof scopeConfigSchema>
export type Domain = z.infer<typeof domainSchema>
export type DomainOverview = z.infer<typeof domainOverviewSchema>
export type HomeFinding = z.infer<typeof homeFindingSchema>
export type RecentChange = z.infer<typeof recentChangeSchema>
