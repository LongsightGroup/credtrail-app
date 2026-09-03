import {
  createBadgeIssuanceRuleWithAction,
  findBadgeTemplateById,
  findBadgeIssuanceRuleAuthoringReplay,
  updateBadgeIssuanceRuleWithAction,
  type BadgeIssuanceRuleAuthoringResult,
  type BadgeIssuanceRuleLmsProviderKind,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import {
  parseBadgeIssuanceRuleDefinition,
  type BadgeIssuanceRuleDefinition,
  type CreateBadgeIssuanceRuleRequest,
  type UpdateBadgeIssuanceRuleDraftRequest,
} from "@credtrail/validation";
import { resolveExpectedBadgeTemplateRevision } from "./badge-achievement-snapshot";

type CompletedBadgeRuleAuthoring = Extract<
  BadgeIssuanceRuleAuthoringResult,
  { readonly status: "completed" }
>;

export type PreparedBadgeRuleAuthoringResult =
  | (CompletedBadgeRuleAuthoring & {
      readonly definition: BadgeIssuanceRuleDefinition;
    })
  | {
      readonly status: "failed";
      readonly reason:
        | Extract<BadgeIssuanceRuleAuthoringResult, { readonly status: "failed" }>["reason"]
        | "template_artwork_unavailable";
    };

export type PreparedBadgeRuleAuthoringFailureReason = Extract<
  PreparedBadgeRuleAuthoringResult,
  { readonly status: "failed" }
>["reason"];

const nonEmptyTrimmed = (value: string | undefined): string | undefined => {
  const trimmed = value?.trim();
  return trimmed === undefined || trimmed.length === 0 ? undefined : trimmed;
};

const withPersistedDefinition = (
  authored: BadgeIssuanceRuleAuthoringResult,
): PreparedBadgeRuleAuthoringResult => {
  if (authored.status === "failed") {
    return authored;
  }

  return {
    ...authored,
    definition: parseBadgeIssuanceRuleDefinition(JSON.parse(authored.version.ruleJson)),
  };
};

/** Finds a completed create command before LMS preparation so transport retries stay replayable. */
export const findPreparedBadgeRuleReplay = async (input: {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly actorUserId: string;
  readonly builderDraftId: string;
  readonly ruleId?: string | undefined;
}): Promise<PreparedBadgeRuleAuthoringResult | null> => {
  const replay = await findBadgeIssuanceRuleAuthoringReplay(input.db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    builderDraftId: input.builderDraftId,
    ruleId: input.ruleId,
  });
  return replay === null ? null : withPersistedDefinition(replay);
};

/** Persists one prepared badge-rule authoring command. */
export const authorPreparedBadgeRule = async (
  input: {
    readonly db: SqlDatabase;
    readonly store: ImmutableCredentialStore;
    readonly publicAppOrigin: string;
    readonly tenantId: string;
    readonly actorUserId: string;
    readonly actorRole: TenantMembershipRole;
    readonly lmsConnection: {
      readonly id: string;
      readonly providerKind: BadgeIssuanceRuleLmsProviderKind;
    };
    readonly ruleJson: string;
  } & (
    | {
        readonly kind: "create";
        readonly request: CreateBadgeIssuanceRuleRequest;
      }
    | {
        readonly kind: "update";
        readonly ruleId: string;
        readonly request: UpdateBadgeIssuanceRuleDraftRequest;
      }
  ),
): Promise<PreparedBadgeRuleAuthoringResult> => {
  const badgeTemplate = await findBadgeTemplateById(
    input.db,
    input.tenantId,
    input.request.badgeTemplateId,
  );

  const expectedBadgeTemplateRevisionResult =
    badgeTemplate === null
      ? null
      : await resolveExpectedBadgeTemplateRevision({
          store: input.store,
          publicAppOrigin: input.publicAppOrigin,
          template: badgeTemplate,
        });

  if (expectedBadgeTemplateRevisionResult?.status === "storage_unavailable") {
    return { status: "failed", reason: "template_artwork_unavailable" };
  }

  if (badgeTemplate === null || expectedBadgeTemplateRevisionResult?.status !== "ready") {
    return { status: "failed", reason: "template_artwork_not_immutable" };
  }

  const expectedBadgeTemplateRevision = expectedBadgeTemplateRevisionResult.revision;

  const authored =
    input.kind === "create"
      ? await createBadgeIssuanceRuleWithAction(input.db, {
          tenantId: input.tenantId,
          name: input.request.name,
          description: input.request.description,
          badgeTemplateId: input.request.badgeTemplateId,
          expectedBadgeTemplateRevision,
          badgeTemplateReuseAcknowledged: input.request.badgeTemplateReuseAcknowledged,
          lmsProviderKind: input.lmsConnection.providerKind,
          lmsConnectionId: input.lmsConnection.id,
          ruleJson: input.ruleJson,
          changeSummary: input.request.changeSummary,
          action: input.request.action,
          actorUserId: input.actorUserId,
          actorRole: input.actorRole,
          builderDraftId: input.request.builderDraftId,
        })
      : await updateBadgeIssuanceRuleWithAction(input.db, {
          tenantId: input.tenantId,
          ruleId: input.ruleId,
          name: input.request.name,
          description: nonEmptyTrimmed(input.request.description),
          badgeTemplateId: input.request.badgeTemplateId,
          expectedBadgeTemplateRevision,
          badgeTemplateReuseAcknowledged: input.request.badgeTemplateReuseAcknowledged,
          lmsProviderKind: input.lmsConnection.providerKind,
          lmsConnectionId: input.lmsConnection.id,
          ruleJson: input.ruleJson,
          changeSummary: input.request.changeSummary,
          action: input.request.action,
          actorUserId: input.actorUserId,
          actorRole: input.actorRole,
          builderDraftId: input.request.builderDraftId,
        });

  if (authored.status === "failed") {
    return authored;
  }

  return {
    ...authored,
    definition:
      input.kind === "create" && authored.writeStatus === "replayed"
        ? parseBadgeIssuanceRuleDefinition(JSON.parse(authored.version.ruleJson))
        : input.request.definition,
  };
};
