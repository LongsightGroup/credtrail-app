import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import type { LtiNrpsMember } from "./nrps";
import type { LtiRosterEligibilityResult } from "./roster-eligibility";
import {
  ltiIssuanceIdempotencyKeyFromPrefix,
  type LtiIssuanceIdempotencyKeyPrefix,
} from "./roster-issuance-helpers";

export const buildLtiRosterIssueBadgeRequest = async (input: {
  readonly member: LtiNrpsMember & { readonly email: string };
  readonly eligibility: LtiRosterEligibilityResult;
  readonly idempotencyKeyPrefix: LtiIssuanceIdempotencyKeyPrefix;
  readonly sha256Hex: (value: string) => Promise<string>;
}): Promise<DirectIssueBadgeRequest> => {
  if (input.eligibility.issuanceProvenance === undefined) {
    throw new Error("Eligible roster issuance requires provenance context");
  }

  return {
    recipientIdentity: input.member.email,
    recipientIdentityType: "email",
    ...(input.member.displayName === null
      ? {}
      : { recipientDisplayName: input.member.displayName }),
    ...(input.member.lisPersonSourcedId === undefined
      ? {}
      : {
          recipientIdentifiers: [
            {
              identifierType: "sourcedId",
              identifier: input.member.lisPersonSourcedId,
            },
          ],
        }),
    idempotencyKey: await ltiIssuanceIdempotencyKeyFromPrefix(
      input.sha256Hex,
      input.idempotencyKeyPrefix,
      input.member.userId,
    ),
    achievementSource: {
      kind: "rule_version",
      provenance: {
        source: "lti_roster",
        ruleId: input.eligibility.issuanceProvenance.ruleId,
        versionId: input.eligibility.issuanceProvenance.versionId,
        provenanceJson: input.eligibility.issuanceProvenance.provenanceJson,
      },
    },
  };
};
