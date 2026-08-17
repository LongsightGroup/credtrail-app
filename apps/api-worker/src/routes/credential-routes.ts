import {
  createDidWeb,
  type ImmutableCredentialStore,
  type JsonObject,
} from "@credtrail/core-domain";
import {
  listAssertionStatusListEntries,
  recordAssertionEngagementEvent,
  type SqlDatabase,
} from "@credtrail/db";
import { parseCredentialPathParams, parseTenantPathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import { canonicalAppRequestUrl } from "../http/canonical-app-url";
import type { PublicResourceNetwork } from "../http/public-resource-network";
import { VC_JSON_LD_CONTENT_TYPE } from "../http/vc-media-types";

interface VerificationAssertion {
  id: string;
  tenantId: string;
  issuedAt: string;
  revokedAt: string | null;
  statusListIndex: number | null;
}

interface AssertionLifecycleSummary {
  state: "active" | "suspended" | "revoked" | "expired";
  source: "lifecycle_event" | "assertion_revocation" | "default_active";
  reasonCode: string | null;
  reason: string | null;
  transitionedAt: string | null;
  revokedAt: string | null;
}

interface VerificationViewModel<
  AssertionValue extends VerificationAssertion,
  CredentialValue extends JsonObject,
> {
  assertion: AssertionValue;
  credential: CredentialValue;
  recipientDisplayName: string | null;
  lifecycle: AssertionLifecycleSummary;
}

type VerificationLookupResult<
  AssertionValue extends VerificationAssertion,
  CredentialValue extends JsonObject,
> =
  | {
      status: "invalid_id";
    }
  | {
      status: "not_found";
    }
  | {
      status: "ok";
      value: VerificationViewModel<AssertionValue, CredentialValue>;
    };

interface CredentialStatusListReference extends JsonObject {
  id: string;
  type: string;
  statusPurpose: "revocation";
  statusListIndex: string;
  statusListCredential: string;
}

interface CredentialVerificationChecksSummary {
  credentialStatus: {
    status: "valid" | "invalid" | "unchecked";
    revoked: boolean | null;
  };
}

interface CredentialLifecycleVerificationSummary {
  state: "active" | "suspended" | "expired" | "revoked";
  reason: string | null;
  checkedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

interface AchievementDetails {
  imageUri: string | null;
}

interface BadgePdfDocumentInput {
  badgeName: string;
  recipientName: string;
  recipientIdentifier: string;
  issuerName: string;
  issuedAt: string;
  status: "Verified" | "Suspended" | "Revoked" | "Expired";
  assertionId: string;
  credentialId: string;
  publicBadgeUrl: string;
  verificationUrl: string;
  ob3JsonUrl: string;
  badgeImageUrl: string | null;
  revokedAt?: string;
}

const publicRequestUrl = (c: AppContext): string => {
  return canonicalAppRequestUrl(c.env.PUBLIC_APP_ORIGIN, c.req.url);
};

interface SigningEntry {
  privateJwk?:
    | {
        kty: string;
      }
    | undefined;
}

interface BuildRevocationStatusListCredentialInput {
  requestUrl: string;
  tenantId: string;
  issuerDid: string;
  statusEntries: readonly {
    statusListIndex: number;
    revoked: boolean;
  }[];
}

interface SignCredentialForDidResult {
  status: "ok" | "error";
  statusCode?: 400 | 404 | 422 | 500 | 502;
  error?: string;
  credential?: JsonObject;
}

interface RegisterCredentialRoutesInput<
  AssertionValue extends VerificationAssertion,
  CredentialValue extends JsonObject,
> {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  loadVerificationViewModel: (
    db: SqlDatabase,
    store: ImmutableCredentialStore,
    credentialId: string,
  ) => Promise<VerificationLookupResult<AssertionValue, CredentialValue>>;
  loadPublicBadgeViewModel: (
    db: SqlDatabase,
    store: ImmutableCredentialStore,
    badgeIdentifier: string,
  ) => Promise<
    | {
        status: "not_found";
      }
    | {
        status: "ok";
        value: VerificationViewModel<AssertionValue, CredentialValue>;
      }
  >;
  credentialStatusForAssertion: (
    statusListCredential: string,
    statusListIndex: number,
  ) => CredentialStatusListReference;
  revocationStatusListUrlForTenant: (requestUrl: string, tenantId: string) => string;
  summarizeCredentialVerificationChecks: (input: {
    context: AppContext;
    credential: CredentialValue;
    checkedAt: string;
    expectedStatusList: CredentialStatusListReference | null;
  }) => Promise<CredentialVerificationChecksSummary>;
  summarizeCredentialLifecycleVerification: (
    credential: CredentialValue,
    revokedAt: string | null,
    checkedAt: string,
  ) => CredentialLifecycleVerificationSummary;
  verifyCredentialProofSummary: (
    context: AppContext,
    credential: CredentialValue,
  ) => Promise<unknown>;
  credentialDownloadFilename: (assertionId: string) => string;
  publicBadgePathForAssertion: (assertion: AssertionValue) => string;
  asString: (value: unknown) => string | null;
  achievementDetailsFromCredential: (credential: CredentialValue) => AchievementDetails;
  recipientDisplayNameFromAssertion: (assertion: AssertionValue) => string | null;
  recipientFromCredential: (credential: CredentialValue) => string;
  badgeNameFromCredential: (credential: CredentialValue) => string;
  issuerNameFromCredential: (credential: CredentialValue) => string;
  formatIsoTimestamp: (timestampIso: string) => string;
  renderBadgePdfDocument: (
    input: BadgePdfDocumentInput,
    options: {
      readonly publicResourceNetwork: PublicResourceNetwork;
      readonly signal?: AbortSignal;
    },
  ) => Promise<Uint8Array>;
  resolvePublicResourceNetwork: (bindings: AppBindings) => PublicResourceNetwork;
  credentialPdfDownloadFilename: (assertionId: string) => string;
  resolveSigningEntryForDid: (context: AppContext, did: string) => Promise<SigningEntry | null>;
  resolveRemoteSignerRegistryEntryForDid: (context: AppContext, did: string) => object | null;
  buildRevocationStatusListCredential: (
    input: BuildRevocationStatusListCredentialInput,
  ) => Promise<{
    credential: JsonObject;
    issuedAt: string;
  }>;
  signCredentialForDid: (input: {
    context: AppContext;
    did: string;
    credential: JsonObject;
    proofType: "DataIntegrityProof";
    cryptosuite: "eddsa-rdfc-2022";
    createdAt?: string;
    missingPrivateKeyError?: string;
    ed25519KeyRequirementError?: string;
  }) => Promise<SignCredentialForDidResult>;
}

const credentialLookupErrorResponse = (
  c: AppContext,
  status: "invalid_id" | "not_found",
): Response => {
  const statusCode: 400 | 404 = status === "invalid_id" ? 400 : 404;
  const errorMessage =
    status === "invalid_id" ? "Invalid credential identifier" : "Credential not found";

  return c.json(
    {
      error: errorMessage,
    },
    statusCode,
  );
};

const publicBadgeLookupErrorResponse = (c: AppContext): Response => {
  return c.json(
    {
      error: "Badge not found",
    },
    404,
  );
};

const sanitizeHeaderValue = (value: string): string => {
  return value.replaceAll(/[\r\n]+/g, " ").trim();
};

const mergedCredentialLifecycle = (input: {
  baseLifecycle: CredentialLifecycleVerificationSummary;
  assertionLifecycle: AssertionLifecycleSummary;
}): CredentialLifecycleVerificationSummary => {
  const { baseLifecycle, assertionLifecycle } = input;

  if (assertionLifecycle.state === "revoked") {
    return {
      state: "revoked",
      reason:
        assertionLifecycle.reason ??
        baseLifecycle.reason ??
        "credential has been revoked by issuer",
      checkedAt: baseLifecycle.checkedAt,
      expiresAt: baseLifecycle.expiresAt,
      revokedAt: assertionLifecycle.revokedAt ?? baseLifecycle.revokedAt,
    };
  }

  if (baseLifecycle.state === "revoked") {
    return baseLifecycle;
  }

  if (assertionLifecycle.state === "suspended") {
    return {
      state: "suspended",
      reason: assertionLifecycle.reason ?? "credential has been suspended by issuer",
      checkedAt: baseLifecycle.checkedAt,
      expiresAt: baseLifecycle.expiresAt,
      revokedAt: baseLifecycle.revokedAt,
    };
  }

  if (assertionLifecycle.state === "expired") {
    return {
      state: "expired",
      reason:
        assertionLifecycle.reason ??
        baseLifecycle.reason ??
        "credential is expired under institutional lifecycle policy",
      checkedAt: baseLifecycle.checkedAt,
      expiresAt: baseLifecycle.expiresAt ?? assertionLifecycle.transitionedAt,
      revokedAt: baseLifecycle.revokedAt,
    };
  }

  return baseLifecycle;
};

const credentialLifecycleLabel = (
  state: CredentialLifecycleVerificationSummary["state"],
): BadgePdfDocumentInput["status"] => {
  switch (state) {
    case "active":
      return "Verified";
    case "suspended":
      return "Suspended";
    case "revoked":
      return "Revoked";
    case "expired":
      return "Expired";
  }
};

const setCredentialLifecycleHeaders = (
  c: AppContext,
  lifecycle: CredentialLifecycleVerificationSummary,
): void => {
  c.header("X-Credtrail-Credential-State", lifecycle.state);

  if (lifecycle.reason !== null) {
    c.header("X-Credtrail-Credential-Reason", sanitizeHeaderValue(lifecycle.reason));
  }
};

export const registerCredentialRoutes = <
  AssertionValue extends VerificationAssertion,
  CredentialValue extends JsonObject,
>(
  input: RegisterCredentialRoutesInput<AssertionValue, CredentialValue>,
): void => {
  const {
    app,
    resolveDatabase,
    loadVerificationViewModel,
    loadPublicBadgeViewModel,
    credentialStatusForAssertion,
    revocationStatusListUrlForTenant,
    summarizeCredentialVerificationChecks,
    summarizeCredentialLifecycleVerification,
    verifyCredentialProofSummary,
    credentialDownloadFilename,
    publicBadgePathForAssertion,
    asString,
    achievementDetailsFromCredential,
    recipientDisplayNameFromAssertion,
    recipientFromCredential,
    badgeNameFromCredential,
    issuerNameFromCredential,
    formatIsoTimestamp,
    renderBadgePdfDocument,
    resolvePublicResourceNetwork,
    credentialPdfDownloadFilename,
    resolveSigningEntryForDid,
    resolveRemoteSignerRegistryEntryForDid,
    buildRevocationStatusListCredential,
    signCredentialForDid,
  } = input;

  const publicBadgeVerificationPathForAssertion = (assertion: AssertionValue): string => {
    return `${publicBadgePathForAssertion(assertion)}/verification`;
  };

  const publicBadgeJsonldPathForAssertion = (assertion: AssertionValue): string => {
    return `${publicBadgePathForAssertion(assertion)}/jsonld`;
  };

  const loadCredentialRouteModel = async (
    c: AppContext,
    credentialId: string,
  ): Promise<Response | VerificationViewModel<AssertionValue, CredentialValue>> => {
    const result = await loadVerificationViewModel(
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      credentialId,
    );

    if (result.status !== "ok") {
      return credentialLookupErrorResponse(c, result.status);
    }

    return result.value;
  };

  const loadPublicBadgeRouteModel = async (
    c: AppContext,
    badgeIdentifier: string,
  ): Promise<Response | VerificationViewModel<AssertionValue, CredentialValue>> => {
    const result = await loadPublicBadgeViewModel(
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      badgeIdentifier,
    );

    if (result.status === "not_found") {
      return publicBadgeLookupErrorResponse(c);
    }

    return result.value;
  };

  const buildVerificationResponse = async (
    c: AppContext,
    model: VerificationViewModel<AssertionValue, CredentialValue>,
  ): Promise<Response> => {
    c.header("Cache-Control", "no-store");
    await recordAssertionEngagementEvent(resolveDatabase(c.env), {
      tenantId: model.assertion.tenantId,
      assertionId: model.assertion.id,
      eventType: "verification_view",
      actorType: "anonymous",
      occurredAt: new Date().toISOString(),
    });

    const statusList: CredentialStatusListReference | null =
      model.assertion.statusListIndex === null
        ? null
        : credentialStatusForAssertion(
            revocationStatusListUrlForTenant(publicRequestUrl(c), model.assertion.tenantId),
            model.assertion.statusListIndex,
          );
    const checkedAt = new Date().toISOString();
    const checks = await summarizeCredentialVerificationChecks({
      context: c,
      credential: model.credential,
      checkedAt,
      expectedStatusList: statusList,
    });
    const resolvedRevokedAt =
      checks.credentialStatus.status === "valid"
        ? checks.credentialStatus.revoked
          ? checkedAt
          : null
        : model.assertion.revokedAt;
    const lifecycle = summarizeCredentialLifecycleVerification(
      model.credential,
      resolvedRevokedAt,
      checkedAt,
    );
    const effectiveLifecycle = mergedCredentialLifecycle({
      baseLifecycle: lifecycle,
      assertionLifecycle: model.lifecycle,
    });
    const proof = await verifyCredentialProofSummary(c, model.credential);
    setCredentialLifecycleHeaders(c, effectiveLifecycle);

    return c.json({
      assertionId: model.assertion.id,
      tenantId: model.assertion.tenantId,
      issuedAt: model.assertion.issuedAt,
      verification: {
        status: effectiveLifecycle.state,
        reason: effectiveLifecycle.reason,
        checkedAt: effectiveLifecycle.checkedAt,
        expiresAt: effectiveLifecycle.expiresAt,
        revokedAt: effectiveLifecycle.revokedAt,
        assertionLifecycle: {
          state: model.lifecycle.state,
          source: model.lifecycle.source,
          reasonCode: model.lifecycle.reasonCode,
          reason: model.lifecycle.reason,
          transitionedAt: model.lifecycle.transitionedAt,
          revokedAt: model.lifecycle.revokedAt,
        },
        statusList,
        checks,
        proof,
      },
      credential: model.credential,
    });
  };

  const buildJsonldResponse = (
    c: AppContext,
    model: VerificationViewModel<AssertionValue, CredentialValue>,
    download: boolean,
  ): Response => {
    c.header("Cache-Control", "no-store");
    c.header("Content-Type", VC_JSON_LD_CONTENT_TYPE);
    const checkedAt = new Date().toISOString();
    const baseLifecycle = summarizeCredentialLifecycleVerification(
      model.credential,
      model.assertion.revokedAt,
      checkedAt,
    );
    const effectiveLifecycle = mergedCredentialLifecycle({
      baseLifecycle,
      assertionLifecycle: model.lifecycle,
    });
    setCredentialLifecycleHeaders(c, effectiveLifecycle);

    if (download) {
      c.header(
        "Content-Disposition",
        `attachment; filename="${credentialDownloadFilename(model.assertion.id)}"`,
      );
    }

    return c.body(JSON.stringify(model.credential, null, 2));
  };

  const buildPdfResponse = async (
    c: AppContext,
    model: VerificationViewModel<AssertionValue, CredentialValue>,
  ): Promise<Response> => {
    const publicBadgePath = publicBadgePathForAssertion(model.assertion);
    const verificationPath = publicBadgeVerificationPathForAssertion(model.assertion);
    const ob3JsonPath = publicBadgeJsonldPathForAssertion(model.assertion);
    const pdfCheckedAt = new Date().toISOString();
    const pdfBaseLifecycle = summarizeCredentialLifecycleVerification(
      model.credential,
      model.assertion.revokedAt,
      pdfCheckedAt,
    );
    const pdfEffectiveLifecycle = mergedCredentialLifecycle({
      baseLifecycle: pdfBaseLifecycle,
      assertionLifecycle: model.lifecycle,
    });
    const credentialId = asString(model.credential.id) ?? model.assertion.id;
    const achievementDetails = achievementDetailsFromCredential(model.credential);
    const recipientName =
      model.recipientDisplayName ??
      recipientDisplayNameFromAssertion(model.assertion) ??
      "Badge recipient";
    const pdfDocument = await renderBadgePdfDocument(
      {
        badgeName: badgeNameFromCredential(model.credential),
        recipientName,
        recipientIdentifier: recipientFromCredential(model.credential),
        issuerName: issuerNameFromCredential(model.credential),
        issuedAt: `${formatIsoTimestamp(model.assertion.issuedAt)} UTC`,
        status: credentialLifecycleLabel(pdfEffectiveLifecycle.state),
        assertionId: model.assertion.id,
        credentialId,
        publicBadgeUrl: new URL(publicBadgePath, publicRequestUrl(c)).toString(),
        verificationUrl: new URL(verificationPath, publicRequestUrl(c)).toString(),
        ob3JsonUrl: new URL(ob3JsonPath, publicRequestUrl(c)).toString(),
        badgeImageUrl: achievementDetails.imageUri,
        ...(pdfEffectiveLifecycle.revokedAt === null
          ? {}
          : {
              revokedAt: `${formatIsoTimestamp(pdfEffectiveLifecycle.revokedAt)} UTC`,
            }),
      },
      {
        publicResourceNetwork: resolvePublicResourceNetwork(c.env),
        signal: c.req.raw.signal,
      },
    );
    const pdfBody = Uint8Array.from(pdfDocument).buffer;

    return new Response(pdfBody, {
      status: 200,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${credentialPdfDownloadFilename(model.assertion.id)}"`,
        "X-Credtrail-Credential-State": pdfEffectiveLifecycle.state,
        ...(pdfEffectiveLifecycle.reason === null
          ? {}
          : {
              "X-Credtrail-Credential-Reason": sanitizeHeaderValue(pdfEffectiveLifecycle.reason),
            }),
      },
    });
  };

  app.get("/credentials/v1/status-lists/:tenantId/revocation", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const issuerDid = createDidWeb({
      host: c.env.PLATFORM_DOMAIN,
      pathSegments: [pathParams.tenantId],
    });
    const signingEntry = await resolveSigningEntryForDid(c, issuerDid);

    if (signingEntry === null) {
      return c.json(
        {
          error: "No signing configuration for tenant DID",
          did: issuerDid,
        },
        404,
      );
    }

    if (signingEntry.privateJwk !== undefined && signingEntry.privateJwk.kty !== "OKP") {
      return c.json(
        {
          error: "Revocation status list signing requires an Ed25519 private key",
          did: issuerDid,
        },
        422,
      );
    }

    if (
      signingEntry.privateJwk === undefined &&
      resolveRemoteSignerRegistryEntryForDid(c, issuerDid) === null
    ) {
      return c.json(
        {
          error:
            "Tenant DID is missing private signing key material and no remote signer is configured",
          did: issuerDid,
        },
        500,
      );
    }

    const assertions = await listAssertionStatusListEntries(
      resolveDatabase(c.env),
      pathParams.tenantId,
    );
    const statusEntries = assertions.map((assertion) => {
      return {
        statusListIndex: assertion.statusListIndex,
        revoked: assertion.revokedAt !== null,
      };
    });
    const statusListCredentialInput = await buildRevocationStatusListCredential({
      requestUrl: publicRequestUrl(c),
      tenantId: pathParams.tenantId,
      issuerDid,
      statusEntries,
    });
    const signedStatusListCredential = await signCredentialForDid({
      context: c,
      did: issuerDid,
      credential: statusListCredentialInput.credential,
      proofType: "DataIntegrityProof",
      cryptosuite: "eddsa-rdfc-2022",
      createdAt: statusListCredentialInput.issuedAt,
      missingPrivateKeyError:
        "Tenant DID is missing private signing key material and no remote signer is configured",
      ed25519KeyRequirementError: "Revocation status list signing requires an Ed25519 private key",
    });

    if (
      signedStatusListCredential.status !== "ok" ||
      signedStatusListCredential.credential === undefined
    ) {
      return c.json(
        {
          error:
            signedStatusListCredential.error ?? "Unable to sign revocation status list credential",
          did: issuerDid,
        },
        signedStatusListCredential.statusCode ?? 500,
      );
    }

    c.header("Cache-Control", "no-store");
    c.header("Content-Type", VC_JSON_LD_CONTENT_TYPE);
    return c.body(JSON.stringify(signedStatusListCredential.credential, null, 2));
  });

  app.get("/credentials/v1/:credentialId", async (c) => {
    const pathParams = parseCredentialPathParams(c.req.param());
    const model = await loadCredentialRouteModel(c, pathParams.credentialId);

    if (model instanceof Response) {
      return model;
    }

    return buildVerificationResponse(c, model);
  });

  app.get("/credentials/v1/:credentialId/jsonld", async (c) => {
    const pathParams = parseCredentialPathParams(c.req.param());
    const model = await loadCredentialRouteModel(c, pathParams.credentialId);

    if (model instanceof Response) {
      return model;
    }

    return buildJsonldResponse(c, model, false);
  });

  app.get("/credentials/v1/:credentialId/download", async (c) => {
    const pathParams = parseCredentialPathParams(c.req.param());
    const model = await loadCredentialRouteModel(c, pathParams.credentialId);

    if (model instanceof Response) {
      return model;
    }

    return buildJsonldResponse(c, model, true);
  });

  app.get("/credentials/v1/:credentialId/download.pdf", async (c) => {
    const pathParams = parseCredentialPathParams(c.req.param());
    const model = await loadCredentialRouteModel(c, pathParams.credentialId);

    if (model instanceof Response) {
      return model;
    }

    return buildPdfResponse(c, model);
  });

  app.get("/badges/:badgeIdentifier/verification", async (c) => {
    const model = await loadPublicBadgeRouteModel(c, c.req.param("badgeIdentifier"));

    if (model instanceof Response) {
      return model;
    }

    return buildVerificationResponse(c, model);
  });

  app.get("/badges/:badgeIdentifier/jsonld", async (c) => {
    const model = await loadPublicBadgeRouteModel(c, c.req.param("badgeIdentifier"));

    if (model instanceof Response) {
      return model;
    }

    return buildJsonldResponse(c, model, false);
  });

  app.get("/badges/:badgeIdentifier/download", async (c) => {
    const model = await loadPublicBadgeRouteModel(c, c.req.param("badgeIdentifier"));

    if (model instanceof Response) {
      return model;
    }

    return buildJsonldResponse(c, model, true);
  });

  app.get("/badges/:badgeIdentifier/download.pdf", async (c) => {
    const model = await loadPublicBadgeRouteModel(c, c.req.param("badgeIdentifier"));

    if (model instanceof Response) {
      return model;
    }

    return buildPdfResponse(c, model);
  });
};
