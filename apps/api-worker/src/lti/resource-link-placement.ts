import { upsertLtiResourceLinkPlacement, type SqlDatabase } from "@credtrail/db";
import { logLtiWarning } from "./log";

export type UpsertLtiLaunchResourceLinkPlacementResult =
  | {
      ok: true;
    }
  | {
      ok: false;
      reason: "missing_context_id" | "upsert_failed";
      detail?: string;
    };

export const upsertLtiLaunchResourceLinkPlacement = async (input: {
  db: SqlDatabase;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId: string | null;
  resourceLinkId: string;
  badgeTemplateId: string;
  createdByUserId: string;
}): Promise<UpsertLtiLaunchResourceLinkPlacementResult> => {
  if (input.contextId === null || input.contextId.trim().length === 0) {
    logLtiWarning("Skipping resource-link placement upsert because LMS context id is missing", {
      tenantId: input.tenantId,
      resourceLinkId: input.resourceLinkId,
      badgeTemplateId: input.badgeTemplateId,
    });

    return {
      ok: false,
      reason: "missing_context_id",
    };
  }

  try {
    await upsertLtiResourceLinkPlacement(input.db, {
      tenantId: input.tenantId,
      issuer: input.issuer,
      clientId: input.clientId,
      deploymentId: input.deploymentId,
      contextId: input.contextId,
      resourceLinkId: input.resourceLinkId,
      badgeTemplateId: input.badgeTemplateId,
      createdByUserId: input.createdByUserId,
    });

    return {
      ok: true,
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";

    logLtiWarning("Resource-link placement upsert failed", {
      tenantId: input.tenantId,
      contextId: input.contextId,
      resourceLinkId: input.resourceLinkId,
      badgeTemplateId: input.badgeTemplateId,
      detail,
    });

    return {
      ok: false,
      reason: "upsert_failed",
      detail,
    };
  }
};
