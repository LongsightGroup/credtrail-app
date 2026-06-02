import { expect, it } from "vitest";

import {
  consumeOAuthAuthorizationCode,
  createOAuthAuthorizationCode,
  createOAuthClient,
  upsertUserByEmail,
} from "./index";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("consumeOAuthAuthorizationCode", () => {
  it("consumes an authorization code once using a single atomic update", async () => {
    const fixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(fixture.db, `${uniqueTestId("oauth-user")}@example.edu`);
    const input = {
      clientId: uniqueTestId("oc_client"),
      codeHash: uniqueTestId("code_hash"),
      redirectUri: "https://client.example/callback",
      nowIso: "2026-02-11T20:01:00.000Z",
    };

    try {
      await createOAuthClient(fixture.db, {
        clientId: input.clientId,
        clientSecretHash: "client-secret-hash",
        clientName: "Test OAuth Client",
        redirectUrisJson: JSON.stringify([input.redirectUri]),
        grantTypesJson: JSON.stringify(["authorization_code"]),
        responseTypesJson: JSON.stringify(["code"]),
        scope: "https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly",
        tokenEndpointAuthMethod: "client_secret_post",
      });
      await createOAuthAuthorizationCode(fixture.db, {
        clientId: input.clientId,
        userId: user.id,
        tenantId: fixture.tenantId,
        codeHash: input.codeHash,
        redirectUri: input.redirectUri,
        scope: "https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly",
        codeChallenge: "abcdefghijabcdefghijabcdefghijabcdefghijabc",
        codeChallengeMethod: "S256",
        expiresAt: "2026-02-11T20:05:00.000Z",
      });

      const firstConsume = await consumeOAuthAuthorizationCode(fixture.db, input);
      const secondConsume = await consumeOAuthAuthorizationCode(fixture.db, input);

      expect(firstConsume).not.toBeNull();
      expect(firstConsume?.usedAt).toBe(input.nowIso);
      expect(firstConsume?.clientId).toBe(input.clientId);
      expect(firstConsume?.userId).toBe(user.id);
      expect(firstConsume?.tenantId).toBe(fixture.tenantId);
      expect(secondConsume).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [user.id],
      });
    }
  });
});
