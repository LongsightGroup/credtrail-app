import { z } from "zod";
import { orgUnitTypeSchema, resourceIdSchema } from "./primitives.js";
import {
  refineAssertionIssuedDateRange,
  tenantAssertionRecordFilterQueryShape,
} from "./assertion-record-filter-queries.js";

const reportingDateSchema = z.iso.date();

export const tenantAssertionLedgerExportQuerySchema = z
  .object(tenantAssertionRecordFilterQueryShape)
  .superRefine(refineAssertionIssuedDateRange);

export const tenantReportingOverviewQuerySchema = z
  .object({
    issuedFrom: reportingDateSchema.optional(),
    issuedTo: reportingDateSchema.optional(),
    badgeTemplateId: resourceIdSchema.optional(),
    orgUnitId: resourceIdSchema.optional(),
    state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.issuedFrom === undefined || value.issuedTo === undefined) {
      return;
    }

    if (value.issuedFrom > value.issuedTo) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["issuedTo"],
        message: "issuedTo must be on or after issuedFrom",
      });
    }
  });

const tenantReportingEngagementQueryRangeSchema = <T extends z.ZodRawShape>(shape: T) => {
  return z.object(shape).superRefine((value, ctx) => {
    const range = value as {
      from?: string | undefined;
      to?: string | undefined;
    };

    if (range.from === undefined || range.to === undefined) {
      return;
    }

    if (range.from > range.to) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["to"],
        message: "to must be on or after from",
      });
    }
  });
};

export const tenantReportingTrendQuerySchema = tenantReportingEngagementQueryRangeSchema({
  from: reportingDateSchema.optional(),
  to: reportingDateSchema.optional(),
  badgeTemplateId: resourceIdSchema.optional(),
  orgUnitId: resourceIdSchema.optional(),
  state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
  bucket: z.enum(["day"]).default("day"),
});

export const tenantReportingComparisonQuerySchema = tenantReportingEngagementQueryRangeSchema({
  from: reportingDateSchema.optional(),
  to: reportingDateSchema.optional(),
  badgeTemplateId: resourceIdSchema.optional(),
  orgUnitId: resourceIdSchema.optional(),
  state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
  groupBy: z.enum(["badgeTemplate", "orgUnit"]).default("badgeTemplate"),
});

export const tenantReportingHierarchyQuerySchema = tenantReportingEngagementQueryRangeSchema({
  from: reportingDateSchema.optional(),
  to: reportingDateSchema.optional(),
  badgeTemplateId: resourceIdSchema.optional(),
  orgUnitId: resourceIdSchema.optional(),
  state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
  focusOrgUnitId: resourceIdSchema.optional(),
  level: orgUnitTypeSchema,
});

export const executiveDashboardAudienceSchema = z.enum([
  "system",
  "institution",
  "college",
  "department",
  "program",
]);

export const executiveDashboardWindowSchema = z.enum(["last-30-days", "last-90-days"]);

export const tenantExecutiveDashboardQuerySchema = z
  .object({
    issuedFrom: reportingDateSchema.optional(),
    issuedTo: reportingDateSchema.optional(),
    badgeTemplateId: resourceIdSchema.optional(),
    orgUnitId: resourceIdSchema.optional(),
    state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
    window: executiveDashboardWindowSchema.optional(),
    audience: executiveDashboardAudienceSchema.optional(),
    focusOrgUnitId: resourceIdSchema.optional(),
    comparisonLevel: orgUnitTypeSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (value.issuedFrom === undefined || value.issuedTo === undefined) {
      return;
    }

    if (value.issuedFrom > value.issuedTo) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["issuedTo"],
        message: "issuedTo must be on or after issuedFrom",
      });
    }
  });
// --- inferred types and parsers ---
export type TenantAssertionLedgerExportQuery = z.infer<
  typeof tenantAssertionLedgerExportQuerySchema
>;

export type TenantReportingOverviewQuery = z.infer<typeof tenantReportingOverviewQuerySchema>;

export type TenantReportingTrendQuery = z.infer<typeof tenantReportingTrendQuerySchema>;

export type TenantReportingComparisonQuery = z.infer<typeof tenantReportingComparisonQuerySchema>;

export type TenantReportingHierarchyQuery = z.infer<typeof tenantReportingHierarchyQuerySchema>;

export type ExecutiveDashboardAudience = z.infer<typeof executiveDashboardAudienceSchema>;

export type ExecutiveDashboardWindow = z.infer<typeof executiveDashboardWindowSchema>;

export type TenantExecutiveDashboardQuery = z.infer<typeof tenantExecutiveDashboardQuerySchema>;

export const parseTenantAssertionLedgerExportQuery = (
  input: unknown,
): TenantAssertionLedgerExportQuery => {
  return tenantAssertionLedgerExportQuerySchema.parse(input);
};

export const parseTenantReportingOverviewQuery = (input: unknown): TenantReportingOverviewQuery => {
  return tenantReportingOverviewQuerySchema.parse(input);
};

export const parseTenantReportingTrendQuery = (input: unknown): TenantReportingTrendQuery => {
  return tenantReportingTrendQuerySchema.parse(input);
};

export const parseTenantReportingComparisonQuery = (
  input: unknown,
): TenantReportingComparisonQuery => {
  return tenantReportingComparisonQuerySchema.parse(input);
};

export const parseTenantReportingHierarchyQuery = (
  input: unknown,
): TenantReportingHierarchyQuery => {
  return tenantReportingHierarchyQuerySchema.parse(input);
};

export const parseTenantExecutiveDashboardQuery = (
  input: unknown,
): TenantExecutiveDashboardQuery => {
  return tenantExecutiveDashboardQuerySchema.parse(input);
};
