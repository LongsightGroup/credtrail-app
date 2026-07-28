import { submitBadgeIssuanceRuleVersionForApprovalWithinTransaction } from "./badge-issuance-rule-approvals.js";
import type {
  BadgeIssuanceRuleAuthoringAction,
  BadgeIssuanceRuleAuthoringOutcome,
  BadgeIssuanceRuleAuthoringResult,
  BadgeIssuanceRuleVersionRecord,
  CreateBadgeIssuanceRuleAuthoringInput,
  CreateBadgeIssuanceRuleResult,
  UpdateBadgeIssuanceRuleAuthoringInput,
} from "./badge-issuance-rule-types.js";
import {
  createBadgeIssuanceRuleFromBuilderDraftWithinTransaction,
  createBadgeIssuanceRuleWithConnection,
  updateBadgeIssuanceRuleDraftWithinTransaction,
} from "./badge-issuance-rule-writes.js";
import { deleteBadgeIssuanceRuleBuilderDraftForRule } from "./badge-issuance-rule-builder-drafts.js";
import { listBadgeIssuanceRuleVersionApprovalSteps } from "./badge-issuance-rule-reads.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

const AUTHORING_SAVEPOINT = "badge_rule_authoring";

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

const rollbackAuthoring = async (db: SqlDatabase): Promise<void> => {
  await db.prepare(`ROLLBACK TO SAVEPOINT ${AUTHORING_SAVEPOINT}`).run();
};

const releaseAuthoring = async (db: SqlDatabase): Promise<void> => {
  await db.prepare(`RELEASE SAVEPOINT ${AUTHORING_SAVEPOINT}`).run();
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

const completeAuthoring = async (
  db: SqlDatabase,
  input: {
    readonly action: BadgeIssuanceRuleAuthoringAction;
    readonly actorUserId: string;
    readonly actorRole: CreateBadgeIssuanceRuleAuthoringInput["actorRole"];
    readonly writeStatus: "created" | "replayed" | "updated";
    readonly draft: CreateBadgeIssuanceRuleResult;
  },
): Promise<BadgeIssuanceRuleAuthoringResult> => {
  const replayedOutcome =
    input.writeStatus === "replayed" ? versionOutcome(input.draft.version) : null;

  if (input.writeStatus === "replayed") {
    if (replayedOutcome === null) {
      await releaseAuthoring(db);
      return { status: "replay_conflict" };
    }

    const pendingStepNumber =
      replayedOutcome === "pending_approval"
        ? await pendingApprovalStepNumber(db, input.draft)
        : null;
    await releaseAuthoring(db);
    return {
      status: "completed",
      outcome: replayedOutcome,
      writeStatus: input.writeStatus,
      rule: input.draft.rule,
      version: input.draft.version,
      pendingStepNumber,
    };
  }

  if (input.action === "save_draft") {
    await releaseAuthoring(db);
    return {
      status: "completed",
      outcome: "draft_saved",
      writeStatus: input.writeStatus,
      rule: input.draft.rule,
      version: input.draft.version,
      pendingStepNumber: null,
    };
  }

  const submission = await submitBadgeIssuanceRuleVersionForApprovalWithinTransaction(db, {
    tenantId: input.draft.rule.tenantId,
    ruleId: input.draft.rule.id,
    versionId: input.draft.version.id,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
  });

  if (submission.status !== "submitted") {
    await rollbackAuthoring(db);
    return submission;
  }

  const outcome = versionOutcome(submission.version);

  if (outcome !== "pending_approval" && outcome !== "approved") {
    throw new Error(
      `Submitted badge rule version "${submission.version.id}" has status "${submission.version.status}"`,
    );
  }

  await releaseAuthoring(db);
  return {
    status: "completed",
    outcome,
    writeStatus: input.writeStatus,
    rule: input.draft.rule,
    version: submission.version,
    pendingStepNumber: submission.pendingStepNumber,
  };
};

/** Creates a rule draft and optionally submits the same version as one atomic command. */
export const createBadgeIssuanceRuleWithAction = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleAuthoringInput,
): Promise<BadgeIssuanceRuleAuthoringResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    await transactionDb.prepare(`SAVEPOINT ${AUTHORING_SAVEPOINT}`).run();
    const createInput = {
      tenantId: input.tenantId,
      name: input.name,
      description: input.description,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
      lmsProviderKind: input.lmsProviderKind,
      lmsConnectionId: input.lmsConnectionId,
      ruleJson: input.ruleJson,
      changeSummary: input.changeSummary,
      createdByUserId: input.actorUserId,
    };
    const creation =
      input.builderDraftId === undefined
        ? {
            status: "created" as const,
            draft: await createBadgeIssuanceRuleWithConnection(transactionDb, createInput),
          }
        : await createBadgeIssuanceRuleFromBuilderDraftWithinTransaction(transactionDb, {
            ...createInput,
            builderDraftId: input.builderDraftId,
            builderUserId: input.actorUserId,
          });

    if (creation.status === "unavailable") {
      await rollbackAuthoring(transactionDb);
      return creation;
    }

    return completeAuthoring(transactionDb, {
      action: input.action,
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      writeStatus: creation.status,
      draft: creation.draft,
    });
  });
};

/** Updates a rule draft and optionally submits the new version as one atomic command. */
export const updateBadgeIssuanceRuleWithAction = async (
  db: SqlDatabase,
  input: UpdateBadgeIssuanceRuleAuthoringInput,
): Promise<BadgeIssuanceRuleAuthoringResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    await transactionDb.prepare(`SAVEPOINT ${AUTHORING_SAVEPOINT}`).run();
    const updated = await updateBadgeIssuanceRuleDraftWithinTransaction(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      name: input.name,
      description: input.description,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
      lmsProviderKind: input.lmsProviderKind,
      lmsConnectionId: input.lmsConnectionId,
      ruleJson: input.ruleJson,
      changeSummary: input.changeSummary,
      createdByUserId: input.actorUserId,
    });

    if (updated.status !== "updated") {
      await rollbackAuthoring(transactionDb);
      return updated;
    }

    const result = await completeAuthoring(transactionDb, {
      action: input.action,
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      writeStatus: "updated",
      draft: {
        rule: updated.rule,
        version: updated.version,
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
