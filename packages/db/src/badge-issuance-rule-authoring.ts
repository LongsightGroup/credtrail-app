import { createAuditLog } from "./audit-logs.js";
import {
  prepareBadgeRuleSubmission,
  submitPreparedBadgeRuleVersionWithinTransaction,
} from "./badge-issuance-rule-submission.js";
import { deleteBadgeIssuanceRuleBuilderDraftForRule } from "./badge-issuance-rule-builder-drafts.js";
import { badgeIssuanceRuleIdentityForBuilderDraft } from "./badge-issuance-rule-builder-identity.js";
import { findBadgeTemplateById, type BadgeTemplateRecord } from "./badge-templates.js";
import { badgeTemplateArtworkUsesManagedReference } from "./badge-template-artwork-policy.js";
import { listBadgeTemplateRuleUsages } from "./badge-template-rule-usage.js";
import {
  badgeAchievementSnapshotFromTemplate,
  badgeAchievementSnapshotsEqual,
} from "./badge-issuance-rule-achievement-snapshot.js";
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
  createBadgeIssuanceRuleFromLockedTemplate,
  findBadgeIssuanceRuleBuilderPromotionReplay,
  lockBadgeIssuanceRuleBuilderPromotion,
  lockBadgeIssuanceRuleDraftUpdate,
  updateLockedBadgeIssuanceRuleDraft,
} from "./badge-issuance-rule-writes.js";
import { listBadgeIssuanceRuleVersionApprovalSteps } from "./badge-issuance-rule-approval-reads.js";
import { findBadgeIssuanceRuleById } from "./badge-issuance-rule-reads.js";
import { findBadgeIssuanceRuleVersionById } from "./badge-issuance-rule-version-reads.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

type AuthoringWriteStatus = "created" | "replayed" | "updated";

const lockBadgeTemplateForRuleAuthoring = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly badgeTemplateId: string;
  },
): Promise<boolean> => {
  const row = await db
    .prepare(
      `
      SELECT id
      FROM badge_templates
      WHERE tenant_id = ?
        AND id = ?
      FOR UPDATE
    `,
    )
    .bind(input.tenantId, input.badgeTemplateId)
    .first<{ readonly id: string }>();

  return row !== null;
};

const enforceBadgeTemplateReusePolicy = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly badgeTemplateId: string;
    readonly expectedBadgeTemplateRevision: CreateBadgeIssuanceRuleAuthoringInput["expectedBadgeTemplateRevision"];
    readonly badgeTemplateReuseAcknowledged: boolean;
    readonly excludingRuleId?: string | undefined;
  },
): Promise<
  | {
      readonly status: "accepted";
      readonly reusedRuleCount: number;
      readonly badgeTemplate: BadgeTemplateRecord;
    }
  | {
      readonly status: "rejected";
      readonly reason:
        | "template_changed"
        | "template_artwork_not_immutable"
        | "template_reuse_confirmation_required";
    }
> => {
  const templateExists = await lockBadgeTemplateForRuleAuthoring(db, input);

  if (!templateExists) {
    throw new Error(
      `Badge template "${input.badgeTemplateId}" not found for tenant "${input.tenantId}"`,
    );
  }

  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Locked badge template "${input.badgeTemplateId}" could not be reloaded for tenant "${input.tenantId}"`,
    );
  }

  if (!badgeTemplateArtworkUsesManagedReference(badgeTemplate)) {
    return { status: "rejected", reason: "template_artwork_not_immutable" };
  }

  if (
    badgeTemplate.updatedAt !== input.expectedBadgeTemplateRevision.updatedAt ||
    !badgeAchievementSnapshotsEqual(
      badgeAchievementSnapshotFromTemplate(badgeTemplate),
      input.expectedBadgeTemplateRevision.achievementSnapshot,
    )
  ) {
    return { status: "rejected", reason: "template_changed" };
  }

  const usages = await listBadgeTemplateRuleUsages(db, {
    tenantId: input.tenantId,
    badgeTemplateIds: [input.badgeTemplateId],
    ...(input.excludingRuleId === undefined ? {} : { excludingRuleId: input.excludingRuleId }),
  });

  if (usages.length > 0 && !input.badgeTemplateReuseAcknowledged) {
    return { status: "rejected", reason: "template_reuse_confirmation_required" };
  }

  return { status: "accepted", reusedRuleCount: usages.length, badgeTemplate };
};

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
    readonly ruleId?: string | undefined;
  },
): Promise<BadgeIssuanceRuleAuthoringResult | null> => {
  if (input.ruleId !== undefined) {
    const identity = await badgeIssuanceRuleIdentityForBuilderDraft(
      input.tenantId,
      input.builderDraftId,
    );
    const persistedIdentity = await db
      .prepare(
        `
        SELECT
          rule_id AS ruleId,
          created_by_user_id AS createdByUserId
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, identity.versionId)
      .first<{ readonly ruleId: string; readonly createdByUserId: string | null }>();

    if (persistedIdentity === null) {
      return null;
    }

    if (
      persistedIdentity.ruleId !== input.ruleId ||
      persistedIdentity.createdByUserId !== input.actorUserId
    ) {
      return { status: "failed", reason: "unavailable" };
    }

    const rule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

    if (rule === null) {
      throw new Error(`Authored badge rule "${input.ruleId}" could not be reloaded`);
    }

    const version = await findBadgeIssuanceRuleVersionById(db, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: identity.versionId,
    });

    if (version === null) {
      throw new Error(`Authored badge rule version "${identity.versionId}" could not be reloaded`);
    }

    return completeReplay(db, { rule, version });
  }

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
    readonly badgeTemplateReuseAcknowledged: boolean;
    readonly reusedRuleCount: number;
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
      badgeTemplateReuseAcknowledged: input.badgeTemplateReuseAcknowledged,
      reusedRuleCount: input.reusedRuleCount,
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
    readonly badgeTemplateReuseAcknowledged: boolean;
    readonly reusedRuleCount: number;
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

  const reusePolicy = await enforceBadgeTemplateReusePolicy(db, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    expectedBadgeTemplateRevision: input.expectedBadgeTemplateRevision,
    badgeTemplateReuseAcknowledged: input.badgeTemplateReuseAcknowledged,
  });

  if (reusePolicy.status === "rejected") {
    return { status: "failed", reason: reusePolicy.reason };
  }

  const badgeTemplate = reusePolicy.badgeTemplate;

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
    badgeTemplateReuseAcknowledged: input.badgeTemplateReuseAcknowledged,
    reusedRuleCount: reusePolicy.reusedRuleCount,
    write: () =>
      promotion === null
        ? createBadgeIssuanceRuleFromLockedTemplate(db, createInput, badgeTemplate).then(
            (draft) => ({
              status: "created" as const,
              draft,
            }),
          )
        : createBadgeIssuanceRuleFromLockedBuilderPromotion(db, {
            ...createInput,
            builderDraftId: promotion.builderDraftId,
            builderUserId: input.actorUserId,
            identity: promotion.identity,
            badgeTemplate,
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
    const authoringIdentity =
      input.builderDraftId === undefined
        ? null
        : await badgeIssuanceRuleIdentityForBuilderDraft(input.tenantId, input.builderDraftId);

    if (input.builderDraftId !== undefined) {
      await transactionDb
        .prepare("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")
        .bind(`${input.tenantId}:${input.builderDraftId}`)
        .run();
      const replay = await findBadgeIssuanceRuleAuthoringReplay(transactionDb, {
        tenantId: input.tenantId,
        builderDraftId: input.builderDraftId,
        actorUserId: input.actorUserId,
        ruleId: input.ruleId,
      });

      if (replay !== null) {
        return replay;
      }
    }

    const locked = await lockBadgeIssuanceRuleDraftUpdate(transactionDb, input);

    if (locked.status !== "ready") {
      return { status: "failed", reason: locked.status };
    }

    const reusePolicy = await enforceBadgeTemplateReusePolicy(transactionDb, {
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
      expectedBadgeTemplateRevision: input.expectedBadgeTemplateRevision,
      badgeTemplateReuseAcknowledged: input.badgeTemplateReuseAcknowledged,
      excludingRuleId: input.ruleId,
    });

    if (reusePolicy.status === "rejected") {
      return { status: "failed", reason: reusePolicy.reason };
    }

    const orgUnitId = input.orgUnitId ?? locked.rule.orgUnitId;
    const result = await completeAuthoringWrite(transactionDb, {
      action: input.action,
      tenantId: input.tenantId,
      orgUnitId,
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      writeStatus: "updated",
      badgeTemplateReuseAcknowledged: input.badgeTemplateReuseAcknowledged,
      reusedRuleCount: reusePolicy.reusedRuleCount,
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
          badgeTemplate: reusePolicy.badgeTemplate,
          ...(authoringIdentity === null ? {} : { versionId: authoringIdentity.versionId }),
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
