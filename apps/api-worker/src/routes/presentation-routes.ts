import {
  signCredentialWithEd25519Signature2020,
  type Ed25519PrivateJwk,
  type JsonObject,
} from '@credtrail/core-domain';
import {
  findAssertionById,
  listLearnerBadgeSummaries,
  type AssertionRecord,
  type SessionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import type { Hono } from 'hono';
import { parsePresentationCreateRequest, parsePresentationVerifyRequest } from '@credtrail/validation';
import type { AppBindings, AppContext, AppEnv } from '../app';

interface PresentationHolderProofSummary {
  status: 'valid' | 'invalid' | 'unchecked';
}

interface PresentationCredentialVerificationResult {
  status: 'valid' | 'invalid' | 'unchecked';
}

interface RegisterPresentationRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveSessionFromCookie: (context: AppContext) => Promise<SessionRecord | null>;
  parseTenantScopedCredentialId: (
    credentialId: string,
  ) => {
    tenantId: string;
    resourceId: string;
  } | null;
  loadCredentialForAssertion: (store: R2Bucket, assertion: AssertionRecord) => Promise<JsonObject>;
  ed25519PublicJwkFromDidKey: (did: string) => {
    kty: 'OKP';
    crv: 'Ed25519';
    x: string;
    kid?: string | undefined;
  } | null;
  didKeyVerificationMethod: (did: string) => string | null;
  asJsonObject: (value: unknown) => JsonObject | null;
  asNonEmptyString: (value: unknown) => string | null;
  normalizedStringValues: (value: unknown) => string[];
  collectContextUrls: (value: unknown, output: string[]) => void;
  verifiableCredentialObjectsFromPresentation: (presentation: JsonObject) => JsonObject[] | null;
  verifyPresentationHolderProofSummary: (
    context: AppContext,
    presentation: JsonObject,
    holderDid: string,
  ) => Promise<PresentationHolderProofSummary>;
  verifyCredentialInPresentation: (input: {
    context: AppContext;
    credential: JsonObject;
    holderDid: string;
    checkedAt: string;
  }) => Promise<PresentationCredentialVerificationResult>;
  VC_DATA_MODEL_CONTEXT_URL: string;
}

export const registerPresentationRoutes = (input: RegisterPresentationRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    resolveSessionFromCookie,
    parseTenantScopedCredentialId,
    loadCredentialForAssertion,
    ed25519PublicJwkFromDidKey,
    didKeyVerificationMethod,
    asJsonObject,
    asNonEmptyString,
    normalizedStringValues,
    collectContextUrls,
    verifiableCredentialObjectsFromPresentation,
    verifyPresentationHolderProofSummary,
    verifyCredentialInPresentation,
    VC_DATA_MODEL_CONTEXT_URL,
  } = input;

  app.post('/v1/presentations/create', async (c): Promise<Response> => {
    const session = await resolveSessionFromCookie(c);

    if (session === null) {
      return c.json(
        {
          error: 'Not authenticated',
        },
        401,
      );
    }

    let request: ReturnType<typeof parsePresentationCreateRequest>;

    try {
      request = parsePresentationCreateRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: 'Invalid presentation create request payload',
        },
        400,
      );
    }

    if (!request.holderDid.startsWith('did:key:')) {
      return c.json(
        {
          error: 'Presentation creation currently supports did:key holder DIDs only',
        },
        422,
      );
    }

    const expectedHolderPublicJwk = ed25519PublicJwkFromDidKey(request.holderDid);

    if (expectedHolderPublicJwk === null) {
      return c.json(
        {
          error: 'holderDid is not a valid did:key identifier',
        },
        422,
      );
    }

    if (request.holderPrivateJwk.x !== expectedHolderPublicJwk.x) {
      return c.json(
        {
          error: 'holderPrivateJwk does not match holderDid public key',
        },
        422,
      );
    }

    const holderPrivateJwk: Ed25519PrivateJwk = {
      kty: request.holderPrivateJwk.kty,
      crv: request.holderPrivateJwk.crv,
      x: request.holderPrivateJwk.x,
      d: request.holderPrivateJwk.d,
      ...(request.holderPrivateJwk.kid === undefined ? {} : { kid: request.holderPrivateJwk.kid }),
    };
    const db = resolveDatabase(c.env);
    const learnerBadges = await listLearnerBadgeSummaries(db, {
      tenantId: session.tenantId,
      userId: session.userId,
    });
    const learnerAssertionIds = new Set<string>(learnerBadges.map((badge) => badge.assertionId));
    const selectedCredentials: JsonObject[] = [];

    for (const credentialId of request.credentialIds) {
      const tenantScopedCredentialId = parseTenantScopedCredentialId(credentialId);

      if (tenantScopedCredentialId?.tenantId !== session.tenantId) {
        return c.json(
          {
            error:
              'credentialIds must contain tenant-scoped assertion identifiers for the active session tenant',
            credentialId,
          },
          422,
        );
      }

      if (!learnerAssertionIds.has(credentialId)) {
        return c.json(
          {
            error: 'Credential is not accessible for the authenticated learner account',
            credentialId,
          },
          403,
        );
      }

      const assertion = await findAssertionById(db, session.tenantId, credentialId);

      if (assertion === null) {
        return c.json(
          {
            error: 'Credential not found',
            credentialId,
          },
          404,
        );
      }

      const credential = await loadCredentialForAssertion(c.env.BADGE_OBJECTS, assertion);
      const credentialSubject = asJsonObject(credential.credentialSubject);
      const subjectId = asNonEmptyString(credentialSubject?.id);

      if (subjectId !== request.holderDid) {
        return c.json(
          {
            error: 'Credential subject DID does not match requested presentation holder DID',
            credentialId,
            subjectId,
          },
          422,
        );
      }

      selectedCredentials.push(credential);
    }

    const verificationMethod = didKeyVerificationMethod(request.holderDid);

    if (verificationMethod === null) {
      return c.json(
        {
          error: 'Unable to resolve holder verification method from holder DID',
        },
        422,
      );
    }

    const presentation = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': [VC_DATA_MODEL_CONTEXT_URL],
        type: ['VerifiablePresentation'],
        holder: request.holderDid,
        verifiableCredential: selectedCredentials,
      },
      privateJwk: holderPrivateJwk,
      verificationMethod,
    });

    c.header('Cache-Control', 'no-store');

    return c.json({
      holderDid: request.holderDid,
      verificationMethod,
      credentialCount: selectedCredentials.length,
      presentation,
    });
  });

  app.post('/v1/presentations/verify', async (c): Promise<Response> => {
    let request: ReturnType<typeof parsePresentationVerifyRequest>;

    try {
      request = parsePresentationVerifyRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: 'Invalid presentation verification request payload',
        },
        400,
      );
    }

    const presentation = request.presentation;
    const holderDid = asNonEmptyString(presentation.holder);
    const presentationTypes = normalizedStringValues(presentation.type);
    const contextUrls: string[] = [];
    collectContextUrls(presentation['@context'], contextUrls);
    const credentials = verifiableCredentialObjectsFromPresentation(presentation);

    if (
      holderDid === null ||
      !presentationTypes.includes('VerifiablePresentation') ||
      !contextUrls.includes(VC_DATA_MODEL_CONTEXT_URL) ||
      credentials === null ||
      credentials.length === 0
    ) {
      return c.json(
        {
          error:
            'Payload must be a VerifiablePresentation with holder DID and at least one verifiableCredential',
        },
        400,
      );
    }

    const checkedAt = new Date().toISOString();
    const holderProof = await verifyPresentationHolderProofSummary(c, presentation, holderDid);
    const credentialResults: PresentationCredentialVerificationResult[] = [];

    for (const credential of credentials) {
      credentialResults.push(
        await verifyCredentialInPresentation({
          context: c,
          credential,
          holderDid,
          checkedAt,
        }),
      );
    }

    const status: 'valid' | 'invalid' =
      holderProof.status === 'valid' && credentialResults.every((entry) => entry.status === 'valid')
        ? 'valid'
        : 'invalid';

    c.header('Cache-Control', 'no-store');

    return c.json({
      status,
      checkedAt,
      holder: {
        did: holderDid,
        proof: holderProof,
      },
      credentialCount: credentialResults.length,
      credentials: credentialResults,
    });
  });
};
