import { upsertLtiDynamicRegistrationSession } from "@credtrail/db";
import type { LTIDynamicRegistrationSession } from "@longsightgroup/lti-tool";
import { expect, it } from "vitest";

import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  uniqueTestId,
} from "../../../../packages/db/src/postgres-test-support";
import { CredTrailLtiStorage } from "./credtrail-lti-storage";

const sampleDynamicRegistrationSession = (): LTIDynamicRegistrationSession => {
  return {
    openIdConfiguration: {
      issuer: "https://canvas.test",
      authorization_endpoint: "https://canvas.test/api/lti/authorize_redirect",
      registration_endpoint: "https://canvas.test/api/lti/registrations",
      jwks_uri: "https://canvas.test/api/lti/security/jwks",
      token_endpoint: "https://canvas.test/login/oauth2/token",
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      token_endpoint_auth_signing_alg_values_supported: ["RS256"],
      scopes_supported: [],
      response_types_supported: ["id_token"],
      id_token_signing_alg_values_supported: ["RS256"],
      claims_supported: ["iss", "sub"],
      subject_types_supported: ["public"],
      "https://purl.imsglobal.org/spec/lti-platform-configuration": {
        product_family_code: "canvas",
        version: "cloud",
        messages_supported: [{ type: "LtiResourceLinkRequest" }],
      },
    },
    registrationToken: "registration-token-for-test",
    expiresAt: Date.now() + 60_000,
  };
};

describeDbIntegration("CredTrail LTI dynamic-registration storage with Postgres", () => {
  it("round-trips a valid one-time session through the storage interface", async () => {
    const fixture = await createTestTenantFixture();
    const storage = new CredTrailLtiStorage(fixture.db, { tenantId: fixture.tenantId });
    const sessionId = uniqueTestId("lti_registration_session");
    const session = sampleDynamicRegistrationSession();

    try {
      await storage.setRegistrationSession(sessionId, session);

      await expect(storage.consumeRegistrationSession(sessionId)).resolves.toEqual(session);
      await expect(storage.consumeRegistrationSession(sessionId)).resolves.toBeUndefined();
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

  it("consumes malformed persisted JSON without trusting it", async () => {
    const fixture = await createTestTenantFixture();
    const storage = new CredTrailLtiStorage(fixture.db, { tenantId: fixture.tenantId });
    const sessionId = uniqueTestId("lti_registration_session");

    try {
      await upsertLtiDynamicRegistrationSession(fixture.db, {
        tenantId: fixture.tenantId,
        id: sessionId,
        dataJson: "{not-json",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });

      await expect(storage.consumeRegistrationSession(sessionId)).resolves.toBeUndefined();
      await expect(storage.consumeRegistrationSession(sessionId)).resolves.toBeUndefined();
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });
});
