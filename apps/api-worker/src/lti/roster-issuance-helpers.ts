import {
  listAssertionsByIdempotencyKeys,
  listAssertionLifecycleStatesByAssertionIds,
  type AssertionLifecycleState,
  type SqlDatabase,
} from "@credtrail/db";
import type { LTISession } from "@lti-tool/core";
import type { LtiIssuanceActionPayload } from "./issuance-action-token";
import type { LtiNrpsMember } from "./nrps";
import type { LtiRosterIssuanceResultEntry } from "./view-models";
import { asNonEmptyString } from "../utils/value-parsers";

interface LtiRosterIssuedBadgeState {
  assertionId: string;
  issuedAt: string;
  lifecycleState: AssertionLifecycleState | null;
}

type LtiIssuanceIdempotencyKeyContext = Pick<
  LtiIssuanceActionPayload,
  "issuer" | "clientId" | "deploymentId" | "contextId" | "resourceLinkId" | "badgeTemplateId"
>;

type LtiRosterIssuanceLookupContext = LtiIssuanceIdempotencyKeyContext &
  Pick<LtiIssuanceActionPayload, "tenantId">;

interface LtiIssuanceIdempotencyKeyPrefix {
  value: string;
}

export const selectedLearnerUserIdsFromForm = (form: FormData): string[] => {
  const selected = form
    .getAll("learner_user_id")
    .map((entry) => asNonEmptyString(entry))
    .filter((entry): entry is string => entry !== null);

  return Array.from(new Set(selected));
};

export const ltiSessionMatchesIssuanceAction = (
  ltiSession: LTISession,
  action: LtiIssuanceActionPayload,
): boolean => {
  return (
    ltiSession.id === action.ltiSessionId &&
    ltiSession.platform.issuer === action.issuer &&
    ltiSession.platform.clientId === action.clientId &&
    ltiSession.platform.deploymentId === action.deploymentId &&
    ltiSession.context.id === action.contextId &&
    ltiSession.resourceLink?.id === action.resourceLinkId
  );
};

export const ltiIssuanceIdempotencyKeyPrefix = (
  action: LtiIssuanceIdempotencyKeyContext,
): LtiIssuanceIdempotencyKeyPrefix => {
  return {
    value: [
      action.issuer,
      action.clientId,
      action.deploymentId,
      action.contextId,
      action.resourceLinkId,
      action.badgeTemplateId,
    ].join("|"),
  };
};

export const ltiIssuanceIdempotencyKeyFromPrefix = async (
  sha256Hex: (value: string) => Promise<string>,
  prefix: LtiIssuanceIdempotencyKeyPrefix,
  learnerUserId: string,
): Promise<string> => {
  const digest = await sha256Hex(`${prefix.value}|${learnerUserId}`);

  return `lti:${digest}`;
};

export const skippedLtiIssuanceResult = (
  member: Pick<LtiNrpsMember, "userId" | "displayName" | "email">,
  message: string,
): LtiRosterIssuanceResultEntry => {
  return {
    userId: member.userId,
    displayName: member.displayName,
    email: member.email,
    status: "skipped",
    message,
    assertionId: null,
  };
};

export const ltiRosterIssuedBadgeStatesByUserId = async (input: {
  db: SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  action: LtiRosterIssuanceLookupContext;
  learnerMembers: readonly LtiNrpsMember[];
}): Promise<Map<string, LtiRosterIssuedBadgeState>> => {
  const statesByUserId = new Map<string, LtiRosterIssuedBadgeState>();
  const idempotencyKeyPrefix = ltiIssuanceIdempotencyKeyPrefix(input.action);
  const keyedMembers = await Promise.all(
    input.learnerMembers.map(async (member) => {
      const idempotencyKey = await ltiIssuanceIdempotencyKeyFromPrefix(
        input.sha256Hex,
        idempotencyKeyPrefix,
        member.userId,
      );

      return {
        member,
        idempotencyKey,
      };
    }),
  );
  const assertions = await listAssertionsByIdempotencyKeys(input.db, {
    tenantId: input.action.tenantId,
    idempotencyKeys: keyedMembers.map((keyedMember) => keyedMember.idempotencyKey),
  });
  const assertionsByIdempotencyKey = new Map(
    assertions.map((assertion) => [assertion.idempotencyKey, assertion]),
  );
  const lifecycleStates = await listAssertionLifecycleStatesByAssertionIds(input.db, {
    tenantId: input.action.tenantId,
    assertionIds: assertions.map((assertion) => assertion.id),
  });
  const lifecycleStatesByAssertionId = new Map(
    lifecycleStates.map((lifecycle) => [lifecycle.assertionId, lifecycle]),
  );

  for (const keyedMember of keyedMembers) {
    const assertion = assertionsByIdempotencyKey.get(keyedMember.idempotencyKey) ?? null;

    if (assertion === null) {
      continue;
    }

    const lifecycle = lifecycleStatesByAssertionId.get(assertion.id);

    statesByUserId.set(keyedMember.member.userId, {
      assertionId: assertion.id,
      issuedAt: assertion.issuedAt,
      lifecycleState: lifecycle?.state ?? null,
    });
  }

  return statesByUserId;
};
