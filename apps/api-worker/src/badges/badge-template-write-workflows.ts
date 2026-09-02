import {
  compareAndSetBadgeTemplateGovernanceMetadata,
  createAuditLog,
  createBadgeTemplate,
  runSqlTransaction,
  updateBadgeTemplate,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  isLtiInstructorPlacementEnabled,
  setLtiInstructorPlacementPolicy,
  type CreateBadgeTemplateRequest,
  type LtiInstructorPlacementPolicyRequest,
  type UpdateBadgeTemplateRequest,
} from "@credtrail/validation";
import { buildBadgeTemplateFieldChanges } from "./badge-template-audit-metadata";

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return value !== null && typeof value === "object" && !Array.isArray(value);
};

export const isBadgeTemplateSlugConflict = (error: unknown): boolean => {
  return (
    isRecord(error) &&
    error.code === "23505" &&
    error.constraint === "badge_templates_tenant_id_slug_key"
  );
};

export const createBadgeTemplateWithAudit = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    request: CreateBadgeTemplateRequest;
    actorUserId: string;
    membershipRole: TenantMembershipRole;
  },
): Promise<BadgeTemplateRecord> => {
  const template = await createBadgeTemplate(db, {
    tenantId: input.tenantId,
    slug: input.request.slug,
    title: input.request.title,
    description: input.request.description,
    criteriaUri: input.request.criteriaUri,
    ...(input.request.trustedCredentialMetadata === undefined
      ? {}
      : { trustedCredentialMetadataJson: JSON.stringify(input.request.trustedCredentialMetadata) }),
    ownerOrgUnitId: input.request.ownerOrgUnitId,
    createdByUserId: input.actorUserId,
  });

  await createAuditLog(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "badge_template.created",
    targetType: "badge_template",
    targetId: template.id,
    metadata: {
      role: input.membershipRole,
      slug: template.slug,
      title: template.title,
      ownerOrgUnitId: template.ownerOrgUnitId,
    },
  });

  return template;
};

export const updateBadgeTemplateWithAudit = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    badgeTemplateId: string;
    existingTemplate: BadgeTemplateRecord;
    request: UpdateBadgeTemplateRequest;
    actorUserId: string;
    membershipRole: TenantMembershipRole;
  },
): Promise<BadgeTemplateRecord | null> => {
  const template = await updateBadgeTemplate(db, {
    tenantId: input.tenantId,
    id: input.badgeTemplateId,
    slug: input.request.slug,
    title: input.request.title,
    description: input.request.description,
    criteriaUri: input.request.criteriaUri,
    ...(input.request.trustedCredentialMetadata === undefined
      ? {}
      : {
          trustedCredentialMetadataJson:
            input.request.trustedCredentialMetadata === null
              ? null
              : JSON.stringify(input.request.trustedCredentialMetadata),
        }),
  });

  if (template === null) {
    return null;
  }

  const changes = buildBadgeTemplateFieldChanges(input.existingTemplate, template, input.request);

  if (changes.length > 0) {
    await createAuditLog(db, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "badge_template.updated",
      targetType: "badge_template",
      targetId: template.id,
      metadata: {
        role: input.membershipRole,
        changes,
      },
    });
  }

  return template;
};

type UpdateBadgeTemplateLtiPlacementPolicyResult =
  | { readonly status: "updated"; readonly template: BadgeTemplateRecord }
  | { readonly status: "not_found" }
  | { readonly status: "invalid_existing_metadata" }
  | { readonly status: "conflict" }
  | { readonly status: "persistence_failed"; readonly cause: unknown };

/** Updates the governed LMS placement policy without exposing or replacing raw metadata. */
export const updateBadgeTemplateLtiPlacementPolicyWithAudit = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly badgeTemplateId: string;
    readonly existingTemplate: BadgeTemplateRecord;
    readonly request: LtiInstructorPlacementPolicyRequest;
    readonly actorUserId: string;
    readonly membershipRole: TenantMembershipRole;
  },
): Promise<UpdateBadgeTemplateLtiPlacementPolicyResult> => {
  const updatedMetadata = setLtiInstructorPlacementPolicy(
    input.existingTemplate.governanceMetadataJson,
    input.request.enabled,
  );

  if (updatedMetadata.status === "invalid_existing_metadata") {
    return updatedMetadata;
  }

  const wasEnabled = isLtiInstructorPlacementEnabled(input.existingTemplate.governanceMetadataJson);

  if (wasEnabled === input.request.enabled) {
    return { status: "updated", template: input.existingTemplate };
  }

  try {
    return await runSqlTransaction(db, async (transactionDb) => {
      const updateResult = await compareAndSetBadgeTemplateGovernanceMetadata(transactionDb, {
        tenantId: input.tenantId,
        id: input.badgeTemplateId,
        expectedGovernanceMetadataJson: input.existingTemplate.governanceMetadataJson,
        governanceMetadataJson: updatedMetadata.governanceMetadataJson,
      });

      if (updateResult.status !== "updated") {
        return updateResult;
      }

      await createAuditLog(transactionDb, {
        tenantId: input.tenantId,
        actorUserId: input.actorUserId,
        action: "badge_template.updated",
        targetType: "badge_template",
        targetId: updateResult.template.id,
        metadata: {
          role: input.membershipRole,
          changes: [
            {
              field: "ltiInstructorPlacement",
              from: wasEnabled ? "Allowed" : "Not allowed",
              to: input.request.enabled ? "Allowed" : "Not allowed",
            },
          ],
        },
      });

      return updateResult;
    });
  } catch (cause: unknown) {
    return { status: "persistence_failed", cause };
  }
};
