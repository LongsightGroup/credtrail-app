import {
  ensureTenantMembership,
  findLearnerProfileByIdentity,
  moveLearnerIdentityAliasToProfile,
  resolveLearnerProfileFromSaml,
  upsertUserByEmail,
  type LearnerProfileRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { LTI13JwtPayload as LtiLaunchClaims } from "@longsightgroup/lti-tool";
import {
  ltiDisplayNameFromClaims,
  ltiEmailFromClaims,
  ltiFederatedSubjectIdentity,
  ltiSourcedIdFromClaims,
  ltiSyntheticEmail,
} from "./lti-helpers";

export interface LinkedLtiLaunchAccount {
  learnerProfileId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
}

export const linkLtiLaunchAccount = async (input: {
  db: SqlDatabase;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  sha256Hex: (value: string) => Promise<string>;
}): Promise<LinkedLtiLaunchAccount> => {
  const federatedSubject = ltiFederatedSubjectIdentity(
    input.launchClaims.iss,
    input.launchClaims.sub,
  );
  const displayName = ltiDisplayNameFromClaims(input.launchClaims);
  const claimedEmail = ltiEmailFromClaims(input.launchClaims);
  const existingEmailProfile =
    claimedEmail === null
      ? null
      : await findLearnerProfileByIdentity(input.db, {
          tenantId: input.tenantId,
          identityType: "email",
          identityValue: claimedEmail,
        });
  let learnerProfile: LearnerProfileRecord;
  let resolvedLearnerProfileStrategy: "saml_subject" | "verified_email" | "created" | null = null;

  if (existingEmailProfile !== null) {
    learnerProfile = existingEmailProfile;
  } else {
    const resolvedLearnerProfileResult = await resolveLearnerProfileFromSaml(input.db, {
      tenantId: input.tenantId,
      samlSubject: federatedSubject,
      ...(claimedEmail === null ? {} : { email: claimedEmail }),
      ...(displayName === undefined ? {} : { displayName }),
    });
    learnerProfile = resolvedLearnerProfileResult.profile;
    resolvedLearnerProfileStrategy = resolvedLearnerProfileResult.strategy;
  }

  if (claimedEmail !== null) {
    if (existingEmailProfile === null && resolvedLearnerProfileStrategy === "saml_subject") {
      await moveLearnerIdentityAliasToProfile(input.db, {
        tenantId: input.tenantId,
        learnerProfileId: learnerProfile.id,
        identityType: "email",
        identityValue: claimedEmail,
        isPrimary: false,
        isVerified: true,
      });
    }
  }

  await moveLearnerIdentityAliasToProfile(input.db, {
    tenantId: input.tenantId,
    learnerProfileId: learnerProfile.id,
    identityType: "saml_subject",
    identityValue: federatedSubject,
    isPrimary: claimedEmail === null,
    isVerified: true,
  });

  const sourcedId = ltiSourcedIdFromClaims(input.launchClaims);

  if (sourcedId !== null) {
    await moveLearnerIdentityAliasToProfile(input.db, {
      tenantId: input.tenantId,
      learnerProfileId: learnerProfile.id,
      identityType: "sourced_id",
      identityValue: sourcedId,
      isPrimary: false,
      isVerified: true,
    });
  }

  const user = await upsertUserByEmail(
    input.db,
    claimedEmail ?? (await ltiSyntheticEmail(input.tenantId, federatedSubject, input.sha256Hex)),
  );
  const membershipResult = await ensureTenantMembership(input.db, input.tenantId, user.id);

  return {
    learnerProfileId: learnerProfile.id,
    userId: user.id,
    membershipRole: membershipResult.membership.role,
  };
};
