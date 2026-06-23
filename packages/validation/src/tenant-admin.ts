import { z } from "zod";
import { jsonObjectSchema } from "./json.js";
import {
  isoTimestampSchema,
  orgUnitDisplayNameSchema,
  orgUnitSlugSchema,
  orgUnitTypeSchema,
  resourceIdSchema,
  tenantAuthProviderProtocolSchema,
  tenantLoginModeSchema,
  tenantMembershipOrgUnitScopeRoleSchema,
  tenantMembershipRoleSchema,
  delegatedIssuingAuthorityActionSchema,
  badgeTemplateOwnershipTransferReasonCodeSchema,
} from "./primitives.js";
import { tenantPathParamsSchema } from "./path-params.js";

export const createTenantOrgUnitRequestSchema = z.object({
  unitType: orgUnitTypeSchema,
  slug: orgUnitSlugSchema,
  displayName: orgUnitDisplayNameSchema,
  parentOrgUnitId: resourceIdSchema.optional(),
});

export const upsertTenantMembershipOrgUnitScopeRequestSchema = z.object({
  role: tenantMembershipOrgUnitScopeRoleSchema,
});

export const createTenantMemberRequestSchema = z.object({
  email: z.string().trim().email().max(320),
  role: tenantMembershipRoleSchema,
  sendInvite: z.boolean().optional(),
});

export const updateTenantMemberRoleRequestSchema = z.object({
  role: tenantMembershipRoleSchema,
});

export const createDelegatedIssuingAuthorityGrantRequestSchema = z
  .object({
    orgUnitId: resourceIdSchema,
    badgeTemplateIds: z.array(resourceIdSchema).min(1).max(100).optional(),
    allowedActions: z.array(delegatedIssuingAuthorityActionSchema).min(1).max(10),
    startsAt: isoTimestampSchema.optional(),
    endsAt: isoTimestampSchema,
    reason: z.string().trim().min(1).max(512).optional(),
  })
  .superRefine((value, ctx) => {
    const uniqueActions = new Set(value.allowedActions);

    if (uniqueActions.size !== value.allowedActions.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["allowedActions"],
        message: "allowedActions must not contain duplicates",
      });
    }

    if (value.badgeTemplateIds !== undefined) {
      const uniqueTemplateIds = new Set(value.badgeTemplateIds);

      if (uniqueTemplateIds.size !== value.badgeTemplateIds.length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["badgeTemplateIds"],
          message: "badgeTemplateIds must not contain duplicates",
        });
      }
    }

    if (value.startsAt !== undefined) {
      const startsAtMs = Date.parse(value.startsAt);
      const endsAtMs = Date.parse(value.endsAt);

      if (Number.isFinite(startsAtMs) && Number.isFinite(endsAtMs) && endsAtMs <= startsAtMs) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["endsAt"],
          message: "endsAt must be after startsAt",
        });
      }
    }
  });

export const revokeDelegatedIssuingAuthorityGrantRequestSchema = z.object({
  reason: z.string().trim().min(1).max(512).optional(),
  revokedAt: isoTimestampSchema.optional(),
});

export const transferBadgeTemplateOwnershipRequestSchema = z.object({
  toOrgUnitId: resourceIdSchema,
  reasonCode: badgeTemplateOwnershipTransferReasonCodeSchema,
  reason: z.string().trim().min(1).max(512).optional(),
  governanceMetadata: jsonObjectSchema.optional(),
  transferredAt: isoTimestampSchema.optional(),
});

export const createTenantApiKeyRequestSchema = z.object({
  label: z.string().trim().min(1).max(120),
  scopes: z.array(z.string().trim().min(1).max(120)).min(1).max(20).optional(),
  expiresAt: isoTimestampSchema.optional(),
});

export const revokeTenantApiKeyRequestSchema = z.object({
  revokedAt: isoTimestampSchema.optional(),
});

export const upsertTenantAuthPolicyRequestSchema = z.object({
  loginMode: tenantLoginModeSchema,
  breakGlassEnabled: z.boolean().optional(),
  localMfaRequired: z.boolean().optional(),
  defaultProviderId: resourceIdSchema.nullable().optional(),
});

export const upsertTenantAuthProviderRequestSchema = z
  .object({
    protocol: tenantAuthProviderProtocolSchema,
    label: z.string().trim().min(1).max(120),
    enabled: z.boolean().optional(),
    isDefault: z.boolean().optional(),
    configJson: z.string().trim().min(2).max(64000),
  })
  .superRefine((value, ctx) => {
    try {
      const parsed = JSON.parse(value.configJson) as unknown;

      if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["configJson"],
          message: "configJson must encode a JSON object",
        });
      }
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["configJson"],
        message: "configJson must be valid JSON",
      });
    }
  });

export const createTenantBreakGlassAccountRequestSchema = z.object({
  email: z.string().trim().email().max(320),
  sendEnrollmentEmail: z.boolean().optional(),
});

export const upsertTenantCanvasGradebookIntegrationRequestSchema = z.object({
  apiBaseUrl: z.string().url().max(2048),
  authorizationEndpoint: z.string().url().max(2048),
  tokenEndpoint: z.string().url().max(2048),
  clientId: z.string().trim().min(1).max(512),
  clientSecret: z.string().trim().min(1).max(2048),
  scope: z.string().trim().min(1).max(2048).optional(),
});

export const adminCanvasOAuthAuthorizeUrlRequestSchema = z.object({
  redirectUri: z.string().url().max(2048).optional(),
});

export const adminCanvasOAuthExchangeRequestSchema = z.object({
  code: z.string().trim().min(1).max(4096),
  state: z.string().trim().min(20).max(4096),
  redirectUri: z.string().url().max(2048).optional(),
});

export const tenantCanvasGradebookSnapshotQuerySchema = z.object({
  courseId: z.string().trim().min(1).max(255).optional(),
  learnerId: z.string().trim().min(1).max(255).optional(),
  assignmentId: z.string().trim().min(1).max(255).optional(),
});

export const tenantLmsConnectionProviderKindSchema = z.enum(["canvas", "sakai"]);

export const tenantLmsConnectionPathParamsSchema = tenantPathParamsSchema.extend({
  connectionId: resourceIdSchema,
});

export const upsertTenantLmsConnectionRequestSchema = z
  .object({
    displayName: z.string().trim().min(1).max(120),
    providerKind: tenantLmsConnectionProviderKindSchema,
    apiBaseUrl: z.string().url().max(2048),
    authorizationEndpoint: z.string().url().max(2048).optional(),
    tokenEndpoint: z.string().url().max(2048).optional(),
    clientId: z.string().trim().min(1).max(512).optional(),
    clientSecret: z.string().trim().min(1).max(2048).optional(),
    sakaiUsername: z.string().trim().min(1).max(512).optional(),
    sakaiPassword: z.string().trim().min(1).max(2048).optional(),
    scope: z.string().trim().min(1).max(2048).optional(),
    accessToken: z.string().trim().min(1).max(4096).optional(),
    refreshToken: z.string().trim().min(1).max(4096).optional(),
    accessTokenExpiresAt: isoTimestampSchema.optional(),
    refreshTokenExpiresAt: isoTimestampSchema.optional(),
    ltiIssuer: z.string().url().max(2048).optional(),
    ltiClientId: z.string().trim().min(1).max(512).optional(),
    ltiDeploymentId: z.string().trim().min(1).max(512).optional(),
  })
  .transform((request) => {
    const { sakaiUsername, sakaiPassword, ...normalizedRequest } = request;

    if (normalizedRequest.providerKind !== "sakai") {
      return normalizedRequest;
    }

    return {
      ...normalizedRequest,
      ...(sakaiUsername === undefined ? {} : { clientId: sakaiUsername }),
      ...(sakaiPassword === undefined ? {} : { clientSecret: sakaiPassword }),
    };
  });

export const tenantLmsConnectionCourseSearchQuerySchema = z.object({
  q: z.string().trim().min(1).max(255).optional(),
});

export const tenantLmsConnectionCoursePathParamsSchema = tenantLmsConnectionPathParamsSchema.extend(
  {
    courseId: z.string().trim().min(1).max(255),
  },
);

export const tenantLmsConnectionGradebookItemPathParamsSchema =
  tenantLmsConnectionCoursePathParamsSchema.extend({
    assignmentId: z.string().trim().min(1).max(255),
  });
// --- inferred types and parsers ---
export type CreateTenantOrgUnitRequest = z.infer<typeof createTenantOrgUnitRequestSchema>;

export type UpsertTenantMembershipOrgUnitScopeRequest = z.infer<
  typeof upsertTenantMembershipOrgUnitScopeRequestSchema
>;

export type CreateTenantMemberRequest = z.infer<typeof createTenantMemberRequestSchema>;

export type UpdateTenantMemberRoleRequest = z.infer<typeof updateTenantMemberRoleRequestSchema>;

export type CreateDelegatedIssuingAuthorityGrantRequest = z.infer<
  typeof createDelegatedIssuingAuthorityGrantRequestSchema
>;

export type RevokeDelegatedIssuingAuthorityGrantRequest = z.infer<
  typeof revokeDelegatedIssuingAuthorityGrantRequestSchema
>;

export type TransferBadgeTemplateOwnershipRequest = z.infer<
  typeof transferBadgeTemplateOwnershipRequestSchema
>;

export type CreateTenantApiKeyRequest = z.infer<typeof createTenantApiKeyRequestSchema>;

export type RevokeTenantApiKeyRequest = z.infer<typeof revokeTenantApiKeyRequestSchema>;

export type UpsertTenantAuthPolicyRequest = z.infer<typeof upsertTenantAuthPolicyRequestSchema>;

export type UpsertTenantAuthProviderRequest = z.infer<typeof upsertTenantAuthProviderRequestSchema>;

export type CreateTenantBreakGlassAccountRequest = z.infer<
  typeof createTenantBreakGlassAccountRequestSchema
>;

export type UpsertTenantCanvasGradebookIntegrationRequest = z.infer<
  typeof upsertTenantCanvasGradebookIntegrationRequestSchema
>;

export type TenantLmsConnectionProviderKind = z.infer<typeof tenantLmsConnectionProviderKindSchema>;

export type TenantLmsConnectionPathParams = z.infer<typeof tenantLmsConnectionPathParamsSchema>;

export type TenantLmsConnectionCoursePathParams = z.infer<
  typeof tenantLmsConnectionCoursePathParamsSchema
>;

export type TenantLmsConnectionGradebookItemPathParams = z.infer<
  typeof tenantLmsConnectionGradebookItemPathParamsSchema
>;

export type UpsertTenantLmsConnectionRequest = z.infer<
  typeof upsertTenantLmsConnectionRequestSchema
>;

export type TenantLmsConnectionCourseSearchQuery = z.infer<
  typeof tenantLmsConnectionCourseSearchQuerySchema
>;

export type AdminCanvasOAuthAuthorizeUrlRequest = z.infer<
  typeof adminCanvasOAuthAuthorizeUrlRequestSchema
>;

export type AdminCanvasOAuthExchangeRequest = z.infer<typeof adminCanvasOAuthExchangeRequestSchema>;

export type TenantCanvasGradebookSnapshotQuery = z.infer<
  typeof tenantCanvasGradebookSnapshotQuerySchema
>;

export const parseCreateTenantOrgUnitRequest = (input: unknown): CreateTenantOrgUnitRequest => {
  return createTenantOrgUnitRequestSchema.parse(input);
};

export const parseUpsertTenantMembershipOrgUnitScopeRequest = (
  input: unknown,
): UpsertTenantMembershipOrgUnitScopeRequest => {
  return upsertTenantMembershipOrgUnitScopeRequestSchema.parse(input);
};

export const parseCreateTenantMemberRequest = (input: unknown): CreateTenantMemberRequest => {
  return createTenantMemberRequestSchema.parse(input);
};

export const parseUpdateTenantMemberRoleRequest = (
  input: unknown,
): UpdateTenantMemberRoleRequest => {
  return updateTenantMemberRoleRequestSchema.parse(input);
};

export const parseCreateDelegatedIssuingAuthorityGrantRequest = (
  input: unknown,
): CreateDelegatedIssuingAuthorityGrantRequest => {
  return createDelegatedIssuingAuthorityGrantRequestSchema.parse(input);
};

export const parseRevokeDelegatedIssuingAuthorityGrantRequest = (
  input: unknown,
): RevokeDelegatedIssuingAuthorityGrantRequest => {
  return revokeDelegatedIssuingAuthorityGrantRequestSchema.parse(input);
};

export const parseTransferBadgeTemplateOwnershipRequest = (
  input: unknown,
): TransferBadgeTemplateOwnershipRequest => {
  return transferBadgeTemplateOwnershipRequestSchema.parse(input);
};

export const parseCreateTenantApiKeyRequest = (input: unknown): CreateTenantApiKeyRequest => {
  return createTenantApiKeyRequestSchema.parse(input);
};

export const parseRevokeTenantApiKeyRequest = (input: unknown): RevokeTenantApiKeyRequest => {
  return revokeTenantApiKeyRequestSchema.parse(input);
};

export const parseUpsertTenantAuthPolicyRequest = (
  input: unknown,
): UpsertTenantAuthPolicyRequest => {
  return upsertTenantAuthPolicyRequestSchema.parse(input);
};

export const parseUpsertTenantAuthProviderRequest = (
  input: unknown,
): UpsertTenantAuthProviderRequest => {
  return upsertTenantAuthProviderRequestSchema.parse(input);
};

export const parseCreateTenantBreakGlassAccountRequest = (
  input: unknown,
): CreateTenantBreakGlassAccountRequest => {
  return createTenantBreakGlassAccountRequestSchema.parse(input);
};

export const parseUpsertTenantCanvasGradebookIntegrationRequest = (
  input: unknown,
): UpsertTenantCanvasGradebookIntegrationRequest => {
  return upsertTenantCanvasGradebookIntegrationRequestSchema.parse(input);
};

export const parseAdminCanvasOAuthAuthorizeUrlRequest = (
  input: unknown,
): AdminCanvasOAuthAuthorizeUrlRequest => {
  return adminCanvasOAuthAuthorizeUrlRequestSchema.parse(input);
};

export const parseAdminCanvasOAuthExchangeRequest = (
  input: unknown,
): AdminCanvasOAuthExchangeRequest => {
  return adminCanvasOAuthExchangeRequestSchema.parse(input);
};

export const parseTenantCanvasGradebookSnapshotQuery = (
  input: unknown,
): TenantCanvasGradebookSnapshotQuery => {
  return tenantCanvasGradebookSnapshotQuerySchema.parse(input);
};

export const parseTenantLmsConnectionPathParams = (
  input: unknown,
): TenantLmsConnectionPathParams => {
  return tenantLmsConnectionPathParamsSchema.parse(input);
};

export const parseTenantLmsConnectionCoursePathParams = (
  input: unknown,
): TenantLmsConnectionCoursePathParams => {
  return tenantLmsConnectionCoursePathParamsSchema.parse(input);
};

export const parseTenantLmsConnectionGradebookItemPathParams = (
  input: unknown,
): TenantLmsConnectionGradebookItemPathParams => {
  return tenantLmsConnectionGradebookItemPathParamsSchema.parse(input);
};

export const parseUpsertTenantLmsConnectionRequest = (
  input: unknown,
): UpsertTenantLmsConnectionRequest => {
  return upsertTenantLmsConnectionRequestSchema.parse(input);
};

export const parseTenantLmsConnectionCourseSearchQuery = (
  input: unknown,
): TenantLmsConnectionCourseSearchQuery => {
  return tenantLmsConnectionCourseSearchQuerySchema.parse(input);
};
