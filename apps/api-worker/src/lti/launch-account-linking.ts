import {
  addLearnerIdentityAlias,
  ensureTenantMembership,
  findLearnerProfileByIdentity,
  resolveLearnerProfileFromSaml,
  upsertUserByEmail,
  type LearnerProfileRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { LtiLaunchClaims, LtiRoleKind } from "@credtrail/lti";
import {
  ltiDisplayNameFromClaims,
  ltiEmailFromClaims,
  ltiFederatedSubjectIdentity,
  ltiMembershipRoleFromRoleKind,
  ltiSourcedIdFromClaims,
  ltiSyntheticEmail,
} from "./lti-helpers";
import { logLtiWarning } from "./log";

export interface LinkedLtiLaunchAccount {
  learnerProfileId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
}

const addLtiIdentityAliasIfAvailable = async (input: {
  db: SqlDatabase;
  tenantId: string;
  learnerProfile: LearnerProfileRecord;
  identityType: "saml_subject" | "sourced_id";
  identityValue: string;
  isPrimary: boolean;
}): Promise<void> => {
  const existingProfile = await findLearnerProfileByIdentity(input.db, {
    tenantId: input.tenantId,
    identityType: input.identityType,
    identityValue: input.identityValue,
  });

  if (existingProfile === null) {
    await addLearnerIdentityAlias(input.db, {
      tenantId: input.tenantId,
      learnerProfileId: input.learnerProfile.id,
      identityType: input.identityType,
      identityValue: input.identityValue,
      isPrimary: input.isPrimary,
      isVerified: true,
    });
    return;
  }

  if (existingProfile.id === input.learnerProfile.id) {
    return;
  }

  logLtiWarning("LTI identity alias is already linked to a different learner profile", {
    tenantId: input.tenantId,
    identityType: input.identityType,
    selectedLearnerProfileId: input.learnerProfile.id,
    existingLearnerProfileId: existingProfile.id,
  });
};

export const linkLtiLaunchAccount = async (input: {
  db: SqlDatabase;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  roleKind: LtiRoleKind;
  sha256Hex: (value: string) => Promise<string>;
  upsertTenantMembershipRole: (
    db: SqlDatabase,
    input: {
      tenantId: string;
      userId: string;
      role: TenantMembershipRole;
    },
  ) => Promise<{
    membership: {
      role: TenantMembershipRole;
    };
  }>;
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
      await addLearnerIdentityAlias(input.db, {
        tenantId: input.tenantId,
        learnerProfileId: learnerProfile.id,
        identityType: "email",
        identityValue: claimedEmail,
        isPrimary: false,
        isVerified: true,
      });
    }
  }

  await addLtiIdentityAliasIfAvailable({
    db: input.db,
    tenantId: input.tenantId,
    learnerProfile,
    identityType: "saml_subject",
    identityValue: federatedSubject,
    isPrimary: claimedEmail === null,
  });

  const sourcedId = ltiSourcedIdFromClaims(input.launchClaims);

  if (sourcedId !== null) {
    await addLtiIdentityAliasIfAvailable({
      db: input.db,
      tenantId: input.tenantId,
      learnerProfile,
      identityType: "sourced_id",
      identityValue: sourcedId,
      isPrimary: false,
    });
  }

  const user = await upsertUserByEmail(
    input.db,
    claimedEmail ?? (await ltiSyntheticEmail(input.tenantId, federatedSubject, input.sha256Hex)),
  );
  const membershipResult = await ensureTenantMembership(input.db, input.tenantId, user.id);
  let membershipRole = membershipResult.membership.role;
  const desiredRole = ltiMembershipRoleFromRoleKind(input.roleKind);

  if (desiredRole === "issuer" && membershipRole === "viewer") {
    const promotedMembership = await input.upsertTenantMembershipRole(input.db, {
      tenantId: input.tenantId,
      userId: user.id,
      role: desiredRole,
    });
    membershipRole = promotedMembership.membership.role;
  }

  return {
    learnerProfileId: learnerProfile.id,
    userId: user.id,
    membershipRole,
  };
};
