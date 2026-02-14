import {
  createDidWeb,
  createTenantScopedId,
  getImmutableCredentialObject,
  logWarn,
  storeImmutableCredentialObject,
  type JsonObject,
  type ObservabilityContext,
} from '@credtrail/core-domain';
import {
  createAssertion,
  createAuditLog,
  findAssertionByIdempotencyKey,
  findBadgeTemplateById,
  listLearnerIdentitiesByProfile,
  nextAssertionStatusListIndex,
  resolveLearnerProfileForIdentity,
  type AssertionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import type { SendIssuanceEmailNotificationInput } from '../notifications/send-issuance-email';
import type { SignCredentialForDidInput, SignCredentialForDidResult } from '../signing/credential-signer';
import {
  credentialStatusForAssertion,
  revocationStatusListUrlForTenant,
} from './revocation-status';
import {
  recipientIdentifiersForIssueRequest,
  type DirectIssueBadgeRequest,
} from './recipient-identifiers';

interface IssueBadgeBindings {
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  MAILTRAP_API_TOKEN?: string | undefined;
  MAILTRAP_INBOX_ID?: string | undefined;
  MAILTRAP_API_BASE_URL?: string | undefined;
  MAILTRAP_FROM_EMAIL?: string | undefined;
  MAILTRAP_FROM_NAME?: string | undefined;
}

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
}

export interface DirectIssueBadgeResult {
  status: 'issued' | 'already_issued';
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

    if (badgeTemplate === null) {
      throw new input.HttpErrorResponseClass(404, {
        error: 'Badge template not found',
      });
    }

    if (badgeTemplate.isArchived) {
      throw new input.HttpErrorResponseClass(409, {
        error: 'Badge template is archived',
      });
    }

    const idempotencyKey = request.idempotencyKey ?? crypto.randomUUID();
    const existingAssertion = await findAssertionByIdempotencyKey(db, tenantId, idempotencyKey);

    if (existingAssertion !== null) {
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
        status: 'already_issued',
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
    const learnerProfile = await resolveLearnerProfileForIdentity(db, {
      tenantId,
      identityType: request.recipientIdentityType,
      identityValue: request.recipientIdentity,
      ...(options?.recipientDisplayName === undefined
        ? {}
        : { displayName: options.recipientDisplayName }),
    });
    const issuedAt = new Date().toISOString();
    const assertionId = createTenantScopedId(tenantId);
    const statusListIndex = await nextAssertionStatusListIndex(db, tenantId);
    const statusListCredentialUrl = revocationStatusListUrlForTenant(
      requestBaseUrl.toString(),
      tenantId,
    );
    const learnerIdentities = await listLearnerIdentitiesByProfile(db, tenantId, learnerProfile.id);
    const learnerDidSubjectId =
      learnerIdentities.find((identity) => identity.identityType === 'did')?.identityValue ??
      learnerProfile.subjectId;
    const recipientIdentifiers = recipientIdentifiersForIssueRequest(
      request,
      learnerProfile.id,
      learnerIdentities,
    );
    const credentialSubjectIdentifiers: JsonObject[] = recipientIdentifiers.map((entry) => {
      return {
        type: entry.identifierType,
        identifier: entry.identifierValue,
      };
    });
    const issuer =
      options?.issuerName === undefined
        ? issuerDid
        : {
            id: issuerDid,
            name: options.issuerName,
            ...(options.issuerUrl === undefined ? {} : { url: options.issuerUrl }),
          };
    const signedCredentialResult = await input.signCredentialForDid({
      context,
      did: issuerDid,
      proofType: 'Ed25519Signature2020',
      createdAt: issuedAt,
      missingPrivateKeyError:
        'Tenant DID is missing private signing key material and no remote signer is configured',
      ed25519KeyRequirementError: 'Tenant issuance requires an Ed25519 private key',
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: `urn:credtrail:assertion:${encodeURIComponent(assertionId)}`,
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer,
        validFrom: issuedAt,
        credentialStatus: credentialStatusForAssertion(statusListCredentialUrl, statusListIndex),
        credentialSubject: {
          id: learnerDidSubjectId,
          identifier: credentialSubjectIdentifiers,
          achievement: {
            id: `urn:credtrail:badge-template:${encodeURIComponent(badgeTemplate.id)}`,
            type: ['Achievement'],
            name: badgeTemplate.title,
            ...(badgeTemplate.description === null ? {} : { description: badgeTemplate.description }),
            ...(badgeTemplate.criteriaUri === null
              ? {}
              : {
                  criteria: {
                    id: badgeTemplate.criteriaUri,
                    type: 'Criteria',
                  },
                }),
            ...(badgeTemplate.imageUri === null
              ? {}
              : {
                  image: {
                    id: badgeTemplate.imageUri,
                    type: 'Image',
                  },
                }),
          },
        },
      },
    });

    if (signedCredentialResult.status !== 'ok') {
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
      action: 'assertion.issued',
      targetType: 'assertion',
      targetId: createdAssertion.id,
      metadata: {
        assertionPublicId: createdAssertion.publicId,
        badgeTemplateId: createdAssertion.badgeTemplateId,
        recipientIdentity: createdAssertion.recipientIdentity,
        recipientIdentityType: createdAssertion.recipientIdentityType,
        issuedAt: createdAssertion.issuedAt,
      },
    });

    if (request.recipientIdentityType === 'email') {
      const recipientEmail = request.recipientIdentity.trim().toLowerCase();
      const publicBadgePath = input.publicBadgePathForAssertion(createdAssertion);
      const verificationPath = `/credentials/v1/${encodeURIComponent(assertionId)}`;
      const credentialDownloadPath = `/credentials/v1/${encodeURIComponent(assertionId)}/download`;

      try {
        await input.sendIssuanceEmailNotification({
          mailtrapApiToken: context.env.MAILTRAP_API_TOKEN,
          mailtrapInboxId: context.env.MAILTRAP_INBOX_ID,
          mailtrapApiBaseUrl: context.env.MAILTRAP_API_BASE_URL,
          mailtrapFromEmail: context.env.MAILTRAP_FROM_EMAIL,
          mailtrapFromName: context.env.MAILTRAP_FROM_NAME,
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
        logWarn(input.observabilityContext(context.env), 'issuance_email_notification_failed', {
          assertionId,
          tenantId,
          recipientEmail,
          detail: error instanceof Error ? error.message : 'Unknown email notification error',
        });
      }
    }

    return {
      status: 'issued',
      tenantId,
      assertionId,
      idempotencyKey,
      vcR2Key: stored.key,
      credential: signedCredential,
    };
  };
};
