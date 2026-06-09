import {
  createDidWeb,
  createTenantScopedId,
  getImmutableCredentialObject,
  logWarn,
  storeImmutableCredentialObject,
  type ImmutableCredentialStore,
  type JsonObject,
  type ObservabilityContext,
} from "@credtrail/core-domain";
import {
  createAssertion,
  createAuditLog,
  findAssertionByIdempotencyKey,
  findBadgeTemplateById,
  findTenantById,
  listLearnerIdentitiesByProfile,
  nextAssertionStatusListIndex,
  resolveAssertionLifecycleState,
  resolveLearnerProfileForIdentity,
  type AssertionLifecycleState,
  type AssertionRecord,
  type RecipientIdentifierType,
  type ResolveAssertionLifecycleStateResult,
  type SqlDatabase,
} from "@credtrail/db";
import type { SendIssuanceEmailNotificationInput } from "../notifications/send-issuance-email";
import type {
  SignCredentialForDidInput,
  SignCredentialForDidResult,
} from "../signing/credential-signer";
import { asJsonObject } from "../utils/value-parsers";
import {
  credentialStatusForAssertion,
  revocationStatusListUrlForTenant,
} from "./revocation-status";
import {
  recipientIdentifiersForIssueRequest,
  type DirectIssueBadgeRequest,
} from "./recipient-identifiers";
import {
  parseTrustEdCredentialMetadataJsonResult,
  type TrustEdCredentialMetadataParseResult,
} from "./trusted-credential-metadata";
import {
  emptyTrustEdOb3Projection,
  projectTrustEdMetadataToOb3,
  type TrustEdCredentialOb3Projection,
} from "./trusted-credential-ob3-projection";

interface IssueBadgeBindings {
  BADGE_OBJECTS: ImmutableCredentialStore;
  PLATFORM_DOMAIN: string;
  EMAIL?: SendEmail | undefined;
  ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED?: string | undefined;
  TRANSACTIONAL_EMAIL_FROM_ADDRESS?: string | undefined;
  TRANSACTIONAL_EMAIL_FROM_NAME?: string | undefined;
}

const canonicalCredentialBaseUrl = (bindings: IssueBadgeBindings, requestUrl: string): string => {
  const requestBaseUrl = new URL(requestUrl);
  const platformDomain = bindings.PLATFORM_DOMAIN.trim();

  if (
    platformDomain.length === 0 ||
    platformDomain === "localhost" ||
    platformDomain.startsWith("localhost:") ||
    platformDomain === requestBaseUrl.host
  ) {
    return requestBaseUrl.origin;
  }

  return `https://${platformDomain}`;
};

const issuerUrlFromTenantDomain = (issuerDomain: string): string | undefined => {
  const trimmedDomain = issuerDomain.trim();

  if (trimmedDomain.length === 0) {
    return undefined;
  }

  return `https://${trimmedDomain}`;
};

interface IssueBadgeHttpErrorPayload {
  error: string;
  did?: string | undefined;
}

type IssueBadgeHttpErrorStatusCode = 400 | 404 | 409 | 422 | 500 | 502;

type IssueBadgeHttpErrorClass = new (
  statusCode: IssueBadgeHttpErrorStatusCode,
  payload: IssueBadgeHttpErrorPayload,
) => Error;

export interface DirectIssueBadgeOptions {
  recipientDisplayName?: string;
  issuerName?: string;
  issuerUrl?: string;
  issuerImageUri?: string;
}

export interface DirectIssueBadgeResult {
  status: "issued" | "already_issued";
  tenantId: string;
  assertionId: string;
  idempotencyKey: string;
  vcR2Key: string;
  credential: JsonObject;
}

interface CreateIssueBadgeForTenantInput<
  ContextType extends { env: BindingsType; req: { url: string } },
  BindingsType extends IssueBadgeBindings,
> {
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
  signCredentialForDid: (
    request: SignCredentialForDidInput<ContextType>,
  ) => Promise<SignCredentialForDidResult>;
  sendIssuanceEmailNotification: (input: SendIssuanceEmailNotificationInput) => Promise<void>;
  observabilityContext: (bindings: BindingsType) => ObservabilityContext;
  publicBadgePathForAssertion: (assertion: AssertionRecord) => string;
  HttpErrorResponseClass: IssueBadgeHttpErrorClass;
}

const assertionLifecycleBlockMessage = (
  assertionId: string,
  lifecycle: ResolveAssertionLifecycleStateResult,
): string => {
  const stateLabel = lifecycle.state;
  const reasonDetail = lifecycle.reason ?? lifecycle.reasonCode;
  const reasonSuffix =
    reasonDetail === null ? "" : ` Reason: ${reasonDetail.replace(/\s+/g, " ").trim()}.`;

  return `Issuance blocked by lifecycle policy: assertion ${assertionId} is ${stateLabel}.${reasonSuffix}`;
};

const isIssuableAssertionLifecycleState = (state: AssertionLifecycleState): boolean => {
  return state === "active";
};

const issuanceEmailNotificationsEnabled = (bindings: IssueBadgeBindings): boolean => {
  return bindings.ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED?.trim().toLowerCase() === "true";
};

const VC_DATA_MODEL_V2_CONTEXT_URL = "https://www.w3.org/ns/credentials/v2";
const OB3_CONTEXT_URL = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json";
const VC_STATUS_LIST_CONTEXT_URL = "https://www.w3.org/ns/credentials/status/v1";
const CREDTRAIL_TRUSTED_CREDENTIAL_CONTEXT_URL = "https://credtrail.org/ns/trusted-credential/v1";

const ob3IdentityTypeFromRecipientIdentifierType = (
  recipientIdentifierType: RecipientIdentifierType,
): string => {
  switch (recipientIdentifierType) {
    case "emailAddress":
      return "emailAddress";
    case "sourcedId":
      return "sourcedId";
    case "nationalIdentityNumber":
      return "nationalIdentityNumber";
    case "studentId":
      return "ext:studentId";
    case "did":
      return "ext:did";
  }
};

const projectTrustEdMetadataForIssuance = (
  metadataResult: TrustEdCredentialMetadataParseResult,
): TrustEdCredentialOb3Projection => {
  return metadataResult.status === "valid"
    ? projectTrustEdMetadataToOb3(metadataResult.metadata)
    : emptyTrustEdOb3Projection();
};

const trustEdProjectionHasExtensionTerms = (
  projection: TrustEdCredentialOb3Projection,
): boolean => {
  return (
    Object.keys(projection.achievement).length > 0 || Object.keys(projection.subject).length > 0
  );
};

const criteriaForIssuedAchievement = (
  templateCriteriaUri: string | null,
  projectedCriteria: unknown,
): JsonObject | null => {
  const projectedCriteriaObject = asJsonObject(projectedCriteria);

  if (projectedCriteriaObject === null && templateCriteriaUri === null) {
    return null;
  }

  const criteria: JsonObject =
    projectedCriteriaObject === null ? {} : { ...projectedCriteriaObject };

  if (criteria.type === undefined) {
    criteria.type = "Criteria";
  }

  if (criteria.id === undefined && templateCriteriaUri !== null) {
    criteria.id = templateCriteriaUri;
  }

  return criteria;
};

export const createIssueBadgeForTenant = <
  ContextType extends { env: BindingsType; req: { url: string } },
  BindingsType extends IssueBadgeBindings,
>(
  input: CreateIssueBadgeForTenantInput<ContextType, BindingsType>,
) => {
  return async (
    context: ContextType,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
    options?: DirectIssueBadgeOptions,
  ): Promise<DirectIssueBadgeResult> => {
    const db = input.resolveDatabase(context.env);
    const badgeTemplate = await findBadgeTemplateById(db, tenantId, request.badgeTemplateId);
    const tenant = await findTenantById(db, tenantId);

    if (badgeTemplate === null) {
      throw new input.HttpErrorResponseClass(404, {
        error: "Badge template not found",
      });
    }

    if (tenant === null) {
      throw new input.HttpErrorResponseClass(404, {
        error: "Tenant not found",
      });
    }

    if (badgeTemplate.isArchived) {
      throw new input.HttpErrorResponseClass(409, {
        error: "Badge template is archived",
      });
    }

    const idempotencyKey = request.idempotencyKey ?? crypto.randomUUID();
    const existingAssertion = await findAssertionByIdempotencyKey(db, tenantId, idempotencyKey);

    if (existingAssertion !== null) {
      const existingLifecycle = await resolveAssertionLifecycleState(
        db,
        tenantId,
        existingAssertion.id,
      );

      if (existingLifecycle === null) {
        throw new Error(`Existing assertion "${existingAssertion.id}" could not be resolved`);
      }

      if (!isIssuableAssertionLifecycleState(existingLifecycle.state)) {
        throw new input.HttpErrorResponseClass(409, {
          error: assertionLifecycleBlockMessage(existingAssertion.id, existingLifecycle),
        });
      }

      const existingCredential = await getImmutableCredentialObject(context.env.BADGE_OBJECTS, {
        tenantId,
        assertionId: existingAssertion.id,
      });

      if (existingCredential === null) {
        throw new Error(
          `Existing assertion "${existingAssertion.id}" is missing its immutable credential object`,
        );
      }

      return {
        status: "already_issued",
        tenantId,
        assertionId: existingAssertion.id,
        idempotencyKey: existingAssertion.idempotencyKey,
        vcR2Key: existingAssertion.vcR2Key,
        credential: existingCredential,
      };
    }

    const issuerDid = createDidWeb({
      host: context.env.PLATFORM_DOMAIN,
      pathSegments: [tenantId],
    });

    const requestBaseUrl = new URL(context.req.url);
    const credentialBaseUrl = canonicalCredentialBaseUrl(context.env, context.req.url);
    const recipientDisplayName = options?.recipientDisplayName ?? request.recipientDisplayName;
    const learnerProfile = await resolveLearnerProfileForIdentity(db, {
      tenantId,
      identityType: request.recipientIdentityType,
      identityValue: request.recipientIdentity,
      ...(recipientDisplayName === undefined ? {} : { displayName: recipientDisplayName }),
    });
    const issuedAt = new Date().toISOString();
    const assertionId = createTenantScopedId(tenantId);
    const statusListIndex = await nextAssertionStatusListIndex(db, tenantId);
    const statusListCredentialUrl = revocationStatusListUrlForTenant(credentialBaseUrl, tenantId);
    const learnerIdentities = await listLearnerIdentitiesByProfile(db, tenantId, learnerProfile.id);
    const learnerDidSubjectId =
      learnerIdentities.find((identity) => identity.identityType === "did")?.identityValue ??
      learnerProfile.subjectId;
    const recipientIdentifiers = recipientIdentifiersForIssueRequest(
      request,
      learnerProfile.id,
      learnerIdentities,
    );
    const credentialSubjectIdentifiers: JsonObject[] = recipientIdentifiers.map((entry) => {
      return {
        type: "IdentityObject",
        hashed: false,
        identityHash: entry.identifierValue,
        identityType: ob3IdentityTypeFromRecipientIdentifierType(entry.identifierType),
      };
    });
    const issuerUrl = options?.issuerUrl ?? issuerUrlFromTenantDomain(tenant.issuerDomain);
    const issuerImageUri = options?.issuerImageUri ?? request.issuerImageUri;
    const issuer = {
      id: issuerDid,
      type: "Profile",
      name: options?.issuerName ?? tenant.displayName,
      ...(issuerUrl === undefined ? {} : { url: issuerUrl }),
      ...(issuerImageUri === undefined
        ? {}
        : {
            image: {
              id: issuerImageUri,
              type: "Image",
              caption: `${options?.issuerName ?? tenant.displayName} logo`,
            },
          }),
    };
    const trustEdMetadataResult = parseTrustEdCredentialMetadataJsonResult(
      badgeTemplate.trustedCredentialMetadataJson,
    );
    const trustEdProjection = projectTrustEdMetadataForIssuance(trustEdMetadataResult);
    const criteria = criteriaForIssuedAchievement(
      badgeTemplate.criteriaUri,
      trustEdProjection.achievement.criteria,
    );

    if (trustEdMetadataResult.status === "invalid") {
      logWarn(input.observabilityContext(context.env), "trusted_credential_metadata_invalid", {
        tenantId,
        badgeTemplateId: badgeTemplate.id,
        detail: trustEdMetadataResult.error,
      });
    }

    const signedCredentialResult = await input.signCredentialForDid({
      context,
      did: issuerDid,
      proofType: "DataIntegrityProof",
      cryptosuite: "eddsa-rdfc-2022",
      createdAt: issuedAt,
      missingPrivateKeyError:
        "Tenant DID is missing private signing key material and no remote signer is configured",
      ed25519KeyRequirementError: "Tenant issuance requires an Ed25519 private key",
      credential: {
        "@context": trustEdProjectionHasExtensionTerms(trustEdProjection)
          ? [
              VC_DATA_MODEL_V2_CONTEXT_URL,
              OB3_CONTEXT_URL,
              VC_STATUS_LIST_CONTEXT_URL,
              CREDTRAIL_TRUSTED_CREDENTIAL_CONTEXT_URL,
            ]
          : [VC_DATA_MODEL_V2_CONTEXT_URL, OB3_CONTEXT_URL, VC_STATUS_LIST_CONTEXT_URL],
        id: `urn:credtrail:assertion:${encodeURIComponent(assertionId)}`,
        type: ["VerifiableCredential", "OpenBadgeCredential"],
        name: badgeTemplate.title,
        issuer,
        validFrom: issuedAt,
        credentialStatus: credentialStatusForAssertion(statusListCredentialUrl, statusListIndex),
        credentialSubject: {
          id: learnerDidSubjectId,
          type: ["AchievementSubject"],
          ...(learnerProfile.displayName === null ? {} : { name: learnerProfile.displayName }),
          identifier: credentialSubjectIdentifiers,
          achievement: {
            id: `urn:credtrail:badge-template:${encodeURIComponent(badgeTemplate.id)}`,
            type: ["Achievement"],
            name: badgeTemplate.title,
            ...(badgeTemplate.description === null
              ? {}
              : { description: badgeTemplate.description }),
            ...(badgeTemplate.imageUri === null
              ? {}
              : {
                  image: {
                    id: badgeTemplate.imageUri,
                    type: "Image",
                  },
                }),
            ...trustEdProjection.achievement,
            ...(criteria === null ? {} : { criteria }),
          },
          ...trustEdProjection.subject,
        },
      },
    });

    if (signedCredentialResult.status !== "ok") {
      throw new input.HttpErrorResponseClass(signedCredentialResult.statusCode, {
        error: signedCredentialResult.error,
        did: issuerDid,
      });
    }

    const signedCredential = signedCredentialResult.credential;

    const stored = await storeImmutableCredentialObject(context.env.BADGE_OBJECTS, {
      tenantId,
      assertionId,
      credential: signedCredential,
    });

    const createdAssertion = await createAssertion(db, {
      id: assertionId,
      tenantId,
      learnerProfileId: learnerProfile.id,
      badgeTemplateId: badgeTemplate.id,
      recipientIdentity: request.recipientIdentity,
      recipientIdentityType: request.recipientIdentityType,
      vcR2Key: stored.key,
      statusListIndex,
      idempotencyKey,
      issuedAt,
      recipientIdentifiers,
      ...(issuedByUserId === undefined ? {} : { issuedByUserId }),
    });

    await createAuditLog(db, {
      tenantId,
      ...(issuedByUserId === undefined ? {} : { actorUserId: issuedByUserId }),
      action: "assertion.issued",
      targetType: "assertion",
      targetId: createdAssertion.id,
      metadata: {
        assertionPublicId: createdAssertion.publicId,
        badgeTemplateId: createdAssertion.badgeTemplateId,
        recipientIdentity: createdAssertion.recipientIdentity,
        recipientIdentityType: createdAssertion.recipientIdentityType,
        issuedAt: createdAssertion.issuedAt,
      },
    });

    if (
      request.recipientIdentityType === "email" &&
      issuanceEmailNotificationsEnabled(context.env)
    ) {
      const recipientEmail = request.recipientIdentity.trim().toLowerCase();
      const publicBadgePath = input.publicBadgePathForAssertion(createdAssertion);
      const verificationPath = `${publicBadgePath}/verification`;
      const credentialDownloadPath = `${publicBadgePath}/download`;

      try {
        await input.sendIssuanceEmailNotification({
          emailBinding: context.env.EMAIL,
          fromEmail: context.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
          fromName: context.env.TRANSACTIONAL_EMAIL_FROM_NAME,
          recipientEmail,
          badgeTitle: badgeTemplate.title,
          assertionId,
          tenantId,
          issuedAtIso: issuedAt,
          publicBadgeUrl: new URL(publicBadgePath, requestBaseUrl).toString(),
          verificationUrl: new URL(verificationPath, requestBaseUrl).toString(),
          credentialDownloadUrl: new URL(credentialDownloadPath, requestBaseUrl).toString(),
        });
      } catch (error: unknown) {
        logWarn(input.observabilityContext(context.env), "issuance_email_notification_failed", {
          assertionId,
          tenantId,
          recipientEmail,
          detail: error instanceof Error ? error.message : "Unknown email notification error",
        });
      }
    }

    return {
      status: "issued",
      tenantId,
      assertionId,
      idempotencyKey,
      vcR2Key: stored.key,
      credential: signedCredential,
    };
  };
};
