import { createAuditLog } from "./audit-logs.js";
import {
  prepareBadgeRuleSubmission,
  submitPreparedBadgeRuleVersionWithinTransaction,
} from "./badge-issuance-rule-submission.js";
import { deleteBadgeIssuanceRuleBuilderDraftForRule } from "./badge-issuance-rule-builder-drafts.js";
import { findBadgeTemplateById } from "./badge-templates.js";
import type {
  BadgeIssuanceRuleAuthoringOutcome,
  BadgeIssuanceRuleAuthoringResult,
  BadgeIssuanceRuleVersionRecord,
  CreateBadgeIssuanceRuleAuthoringInput,
  CreateBadgeIssuanceRuleResult,
  UpdateBadgeIssuanceRuleAuthoringInput,
} from "./badge-issuance-rule-types.js";
import {
  createBadgeIssuanceRuleFromLockedBuilderPromotion,
  createBadgeIssuanceRuleWithConnection,
  findBadgeIssuanceRuleBuilderPromotionReplay,
  lockBadgeIssuanceRuleBuilderPromotion,
  lockBadgeIssuanceRuleDraftUpdate,
  updateLockedBadgeIssuanceRuleDraft,
} from "./badge-issuance-rule-writes.js";
import { listBadgeIssuanceRuleVersionApprovalSteps } from "./badge-issuance-rule-reads.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

type AuthoringWriteStatus = "created" | "replayed" | "updated";

const versionOutcome = (
  version: BadgeIssuanceRuleVersionRecord,
): BadgeIssuanceRuleAuthoringOutcome | null => {
  switch (version.status) {
    case "draft":
      return "draft_saved";
    case "pending_approval":
      return "pending_approval";
    case "approved":
      return "approved";
    default:
      return null;
  }
};

const pendingApprovalStepNumber = async (
  db: SqlDatabase,
  draft: CreateBadgeIssuanceRuleResult,
): Promise<number | null> => {
  const steps = await listBadgeIssuanceRuleVersionApprovalSteps(db, {
    tenantId: draft.rule.tenantId,
    ruleId: draft.rule.id,
    versionId: draft.version.id,
  });

  return steps.find((step) => step.status === "pending")?.stepNumber ?? null;
};

const completeReplay = async (
  db: SqlDatabase,
  draft: CreateBadgeIssuanceRuleResult,
): Promise<BadgeIssuanceRuleAuthoringResult> => {
  const outcome = versionOutcome(draft.version);

  if (outcome === null) {
    return { status: "failed", reason: "replay_conflict" };
  }

  return {
    status: "completed",
    outcome,
    writeStatus: "replayed",
    rule: draft.rule,
    version: draft.version,
    pendingStepNumber:
      outcome === "pending_approval" ? await pendingApprovalStepNumber(db, draft) : null,
  };
};

/** Resolves an already-completed builder authoring command before external preparation work. */
export const findBadgeIssuanceRuleAuthoringReplay = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly builderDraftId: string;
    readonly actorUserId: string;
  },
): Promise<BadgeIssuanceRuleAuthoringResult | null> => {
  const replay = await findBadgeIssuanceRuleBuilderPromotionReplay(db, {
    tenantId: input.tenantId,
    builderDraftId: input.builderDraftId,
    builderUserId: input.actorUserId,
  });

  if (replay.status === "not_promoted") {
    return null;
  }

  if (replay.status === "unavailable") {
    return { status: "failed", reason: "unavailable" };
  }

  return completeReplay(db, replay.draft);
};

const recordAuthoringAudit = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly actorUserId: string;
    readonly actorRole: CreateBadgeIssuanceRuleAuthoringInput["actorRole"];
    readonly writeStatus: Exclude<AuthoringWriteStatus, "replayed">;
    readonly draft: CreateBadgeIssuanceRuleResult;
  },
): Promise<void> => {
  await createAuditLog(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: input.writeStatus === "created" ? "badge_rule.created" : "badge_rule.draft_updated",
    targetType: "badge_rule",
    targetId: input.draft.rule.id,
    metadata: {
      role: input.actorRole,
      versionId: input.draft.version.id,
      versionNumber: input.draft.version.versionNumber,
      status: input.draft.version.status,
      lmsConnectionId: input.draft.rule.lmsConnectionId,
      lmsProviderKind: input.draft.rule.lmsProviderKind,
    },
  });
};

const completeAuthoringWrite = async (
  db: SqlDatabase,
  input: {
    readonly action: CreateBadgeIssuanceRuleAuthoringInput["action"];
    readonly tenantId: string;
    readonly orgUnitId: string;
    readonly actorUserId: string;
    readonly actorRole: CreateBadgeIssuanceRuleAuthoringInput["actorRole"];
    readonly writeStatus: Exclude<AuthoringWriteStatus, "replayed">;
    readonly write: () => Promise<
      | {
          readonly status: "created";
          readonly draft: CreateBadgeIssuanceRuleResult;
        }
      | {
          readonly status: "unavailable";
        }
    >;
  },
): Promise<BadgeIssuanceRuleAuthoringResult> => {
  const preparation =
    input.action === "submit_for_approval"
      ? await prepareBadgeRuleSubmission(db, {
          tenantId: input.tenantId,
          orgUnitId: input.orgUnitId,
        })
      : null;

  if (preparation?.status === "failed") {
    return preparation;
  }

  const creation = await input.write();

  if (creation.status === "unavailable") {
    return { status: "failed", reason: "unavailable" };
  }

  const { draft } = creation;
  await recordAuthoringAudit(db, { ...input, draft });

  if (input.action === "save_draft") {
    return {
      status: "completed",
      outcome: "draft_saved",
      writeStatus: input.writeStatus,
      rule: draft.rule,
      version: draft.version,
      pendingStepNumber: null,
    };
  }

  if (preparation === null) {
    throw new Error("Badge rule submission preparation was not resolved");
  }

  const submission = await submitPreparedBadgeRuleVersionWithinTransaction(db, {
    draft,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    preparation,
  });

  return {
    status: "completed",
    outcome: submission.version.status === "approved" ? "approved" : "pending_approval",
    writeStatus: input.writeStatus,
    rule: draft.rule,
    version: submission.version,
    pendingStepNumber: submission.pendingStepNumber,
  };
};

/**
 * Creates and optionally submits a rule using an existing transaction.
 * Package-internal workflows use this primitive to compose a larger atomic command.
 */
export const createBadgeIssuanceRuleWithActionWithinTransaction = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleAuthoringInput,
): Promise<BadgeIssuanceRuleAuthoringResult> => {
  const promotion =
    input.builderDraftId === undefined
      ? null
      : await lockBadgeIssuanceRuleBuilderPromotion(db, {
          tenantId: input.tenantId,
          builderDraftId: input.builderDraftId,
          builderUserId: input.actorUserId,
        });

  if (promotion?.status === "replayed") {
    return completeReplay(db, promotion.draft);
  }

  if (promotion?.status === "unavailable") {
    return { status: "failed", reason: "unavailable" };
  }

  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Badge template "${input.badgeTemplateId}" not found for tenant "${input.tenantId}"`,
    );
  }

  const orgUnitId = input.orgUnitId ?? badgeTemplate.ownerOrgUnitId;
  const createInput = {
    tenantId: input.tenantId,
    name: input.name,
    description: input.description,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId,
    lmsProviderKind: input.lmsProviderKind,
    lmsConnectionId: input.lmsConnectionId,
    ruleJson: input.ruleJson,
    changeSummary: input.changeSummary,
    createdByUserId: input.actorUserId,
  };

  return completeAuthoringWrite(db, {
    action: input.action,
    tenantId: input.tenantId,
    orgUnitId,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    writeStatus: "created",
    write: () =>
      promotion === null
        ? createBadgeIssuanceRuleWithConnection(db, createInput).then((draft) => ({
            status: "created" as const,
            draft,
          }))
        : createBadgeIssuanceRuleFromLockedBuilderPromotion(db, {
            ...createInput,
            builderDraftId: promotion.builderDraftId,
            builderUserId: input.actorUserId,
            identity: promotion.identity,
          }),
  });
};

/** Creates a rule draft and optionally submits the same version as one atomic command. */
export const createBadgeIssuanceRuleWithAction = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleAuthoringInput,
): Promise<BadgeIssuanceRuleAuthoringResult> => {
  return runSqlTransaction(db, (transactionDb) =>
    createBadgeIssuanceRuleWithActionWithinTransaction(transactionDb, input),
  );
};

/** Updates a rule draft and optionally submits the new version as one atomic command. */
export const updateBadgeIssuanceRuleWithAction = async (
  db: SqlDatabase,
  input: UpdateBadgeIssuanceRuleAuthoringInput,
): Promise<BadgeIssuanceRuleAuthoringResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const locked = await lockBadgeIssuanceRuleDraftUpdate(transactionDb, input);

    if (locked.status !== "ready") {
      return { status: "failed", reason: locked.status };
    }

    const orgUnitId = input.orgUnitId ?? locked.rule.orgUnitId;
    const result = await completeAuthoringWrite(transactionDb, {
      action: input.action,
      tenantId: input.tenantId,
      orgUnitId,
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      writeStatus: "updated",
      write: async () => {
        const updated = await updateLockedBadgeIssuanceRuleDraft(transactionDb, {
          tenantId: input.tenantId,
          ruleId: input.ruleId,
          name: input.name,
          description: input.description,
          badgeTemplateId: input.badgeTemplateId,
          orgUnitId,
          lmsProviderKind: input.lmsProviderKind,
          lmsConnectionId: input.lmsConnectionId,
          ruleJson: input.ruleJson,
          changeSummary: input.changeSummary,
          createdByUserId: input.actorUserId,
          existingRule: locked.rule,
        });

        return {
          status: "created",
          draft: {
            rule: updated.rule,
            version: updated.version,
          },
        };
      },
    });

    if (result.status === "completed") {
      await deleteBadgeIssuanceRuleBuilderDraftForRule(transactionDb, {
        tenantId: input.tenantId,
        userId: input.actorUserId,
        ruleId: input.ruleId,
      });
    }

    return result;
  });
};
