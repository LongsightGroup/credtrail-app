import {
  createBadgeIssuanceRuleWithAction,
  findBadgeIssuanceRuleAuthoringReplay,
  updateBadgeIssuanceRuleWithAction,
  type BadgeIssuanceRuleAuthoringResult,
  type BadgeIssuanceRuleLmsProviderKind,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinition,
  type BadgeIssuanceRuleDefinition,
  type CreateBadgeIssuanceRuleRequest,
  type UpdateBadgeIssuanceRuleDraftRequest,
} from "@credtrail/validation";

type CompletedBadgeRuleAuthoring = Extract<
  BadgeIssuanceRuleAuthoringResult,
  { readonly status: "completed" }
>;

export type PreparedBadgeRuleAuthoringResult =
  | (CompletedBadgeRuleAuthoring & {
      readonly definition: BadgeIssuanceRuleDefinition;
    })
  | Extract<BadgeIssuanceRuleAuthoringResult, { readonly status: "failed" }>;

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
}): Promise<PreparedBadgeRuleAuthoringResult | null> => {
  const replay = await findBadgeIssuanceRuleAuthoringReplay(input.db, input);
  return replay === null ? null : withPersistedDefinition(replay);
};

/** Persists one prepared badge-rule authoring command. */
export const authorPreparedBadgeRule = async (
  input: {
    readonly db: SqlDatabase;
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
  const authored =
    input.kind === "create"
      ? await createBadgeIssuanceRuleWithAction(input.db, {
          tenantId: input.tenantId,
          name: input.request.name,
          description: input.request.description,
          badgeTemplateId: input.request.badgeTemplateId,
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
          lmsProviderKind: input.lmsConnection.providerKind,
          lmsConnectionId: input.lmsConnection.id,
          ruleJson: input.ruleJson,
          changeSummary: input.request.changeSummary,
          action: input.request.action,
          actorUserId: input.actorUserId,
          actorRole: input.actorRole,
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
