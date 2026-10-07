import { z } from "zod";
import { recipientIdentityTypeSchema, resourceIdSchema, tenantIdSchema } from "./primitives.js";
import { refineAssertionIssuedDateRange } from "./assertion-record-filter-queries.js";

/** Explicit permissions supported by the institution integration API. */
export const programmaticApiScopeSchema = z.enum([
  "queue.issue",
  "queue.revoke",
  "operations.read",
  "templates.read",
  "assertions.read",
]);
/** A permission checked at a programmatic HTTP boundary. */
export type ProgrammaticApiScope = z.infer<typeof programmaticApiScopeSchema>;

const id = resourceIdSchema.max(256);
const pageShape = {
  tenantId: tenantIdSchema.max(256),
  // (?![\s\S]) requires absolute end-of-string, including after a trailing newline.
  limit: z
    .string()
    .regex(/^(?:[1-9]\d?|100)(?![\s\S])/u)
    .default("50")
    .transform(Number)
    .pipe(z.number().int().max(100)),
  cursor: id.optional(),
};
/** Institution scope for an operation or individual resource lookup. */
export const programmaticTenantQuerySchema = z.strictObject({ tenantId: pageShape.tenantId });
/** Validated operation identifier. */
export const programmaticOperationParamsSchema = z.strictObject({ operationId: id });
/** Validated assertion identifier. */
export const programmaticAssertionParamsSchema = z.strictObject({ assertionId: id });
/** Validated template identifier. */
export const programmaticTemplateParamsSchema = z.strictObject({ badgeTemplateId: id });
/** Bounded template listing with an exclusive ID cursor. */
export const programmaticTemplateQuerySchema = z.strictObject({
  ...pageShape,
  includeArchived: z
    .enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
});
/** Bounded assertion reconciliation with exact recipient and inclusive UTC date filters. */
export const programmaticAssertionQuerySchema = z
  .strictObject({
    ...pageShape,
    badgeTemplateId: id.optional(),
    recipientIdentity: z.string().min(1).max(2048).optional(),
    recipientIdentityType: recipientIdentityTypeSchema.optional(),
    issuedFrom: z.iso.date().optional(),
    issuedTo: z.iso.date().optional(),
  })
  .superRefine(refineAssertionIssuedDateRange);
/** Parsed template listing request. */
export type ProgrammaticTemplateQuery = z.infer<typeof programmaticTemplateQuerySchema>;
/** Parsed assertion reconciliation request. */
export type ProgrammaticAssertionQuery = z.infer<typeof programmaticAssertionQuerySchema>;

/** Machine-readable failures callers can handle without matching message text. */
export const programmaticErrorCodeSchema = z.enum([
  "invalid_request",
  "invalid_expiry",
  "api_key_required",
  "invalid_api_key",
  "tenant_mismatch",
  "insufficient_scope",
  "invalid_api_key_scopes",
  "api_key_owner_required",
  "idempotency_conflict",
  "template_not_found",
  "template_archived",
  "artwork_required",
  "storage_unavailable",
  "operation_not_found",
  "assertion_not_found",
]);
/** A handled failure at the integration HTTP boundary. */
export type ProgrammaticErrorCode = z.infer<typeof programmaticErrorCodeSchema>;
/** Stable, safe errors returned by programmatic endpoints. */
export const programmaticErrorSchema = z.object({
  code: programmaticErrorCodeSchema,
  error: z.string(),
  details: z.array(z.object({ path: z.array(z.string()), message: z.string() })).optional(),
});
const timestamp = z.iso.datetime({ offset: true });
const url = z.url();
/** Public links, never object-storage keys or transport hostnames. */
export const programmaticBadgeLinksSchema = z.object({
  badgeUrl: url.nullable(),
  credentialUrl: url.nullable(),
});
/** Public template response without internal governance or storage metadata. */
export const programmaticTemplateSchema = z.object({
  badgeTemplateId: id,
  title: z.string(),
  description: z.string().nullable(),
  criteriaUrl: url.nullable(),
  imageUrl: url.nullable(),
  archived: z.boolean(),
});
/** Public assertion response for institution reconciliation. */
export const programmaticAssertionSchema = programmaticBadgeLinksSchema.extend({
  assertionId: id,
  badgeTemplateId: id,
  recipientIdentity: z.string(),
  recipientIdentityType: recipientIdentityTypeSchema,
  issuedAt: timestamp,
  validUntil: timestamp.nullable(),
  state: z.enum(["active", "suspended", "revoked", "expired"]),
});
/** Paginated template response. */
export const programmaticTemplatePageSchema = z.object({
  tenantId: tenantIdSchema,
  templates: z.array(programmaticTemplateSchema),
  nextCursor: id.nullable(),
});
/** Paginated assertion response. */
export const programmaticAssertionPageSchema = z.object({
  tenantId: tenantIdSchema,
  assertions: z.array(programmaticAssertionSchema),
  nextCursor: id.nullable(),
});
const acceptedBase = z.object({
  status: z.literal("queued"),
  channel: z.literal("programmatic_api_key"),
  assertionId: id,
  idempotencyKey: z.string(),
  operationId: id,
  statusUrl: url,
});
/** Revocation acceptance always includes its reserved revocation ID; replay retains all IDs. */
export const programmaticAcceptedSchema = z.discriminatedUnion("jobType", [
  acceptedBase.extend({ jobType: z.literal("issue_badge") }),
  acceptedBase.extend({ jobType: z.literal("revoke_badge"), revocationId: id }),
]);
const operationBase = z.object({
  operationId: id,
  tenantId: tenantIdSchema,
  jobType: z.enum(["issue_badge", "revoke_badge"]),
  assertionId: id,
  idempotencyKey: z.string(),
  attemptCount: z.number().int().nonnegative(),
  createdAt: timestamp,
  updatedAt: timestamp,
});
/** Processing states expose only the data meaningful for that state. */
export const programmaticOperationSchema = z.discriminatedUnion("status", [
  operationBase.extend({
    status: z.literal("pending"),
    nextAttemptAt: timestamp,
  }),
  operationBase.extend({ status: z.literal("processing") }),
  operationBase.extend({
    status: z.literal("completed"),
    completedAt: timestamp,
    result: programmaticBadgeLinksSchema,
  }),
  operationBase.extend({
    status: z.literal("failed"),
    failedAt: timestamp,
    failure: z.object({ code: z.literal("operation_failed"), message: z.string() }),
  }),
]);
