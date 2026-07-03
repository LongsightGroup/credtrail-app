import { describe, expect, it } from "vitest";

import {
  createEnv,
  mockedListTenantAssertions,
  sampleTenantAssertionSummary,
  stubAssertionEvidenceMocks,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { pageAssetPath } from "./ui/page-assets";

describe("GET /tenants/:tenantId/admin/operations/issued-badges/:assertionId/evidence", () => {
  it("renders printable evidence sections for a tenant-scoped assertion", async () => {
    const env = createEnv();
    const assertion = sampleTenantAssertionSummary();

    stubAssertionEvidenceMocks();

    const response = await app.request(
      `/tenants/tenant_123/admin/operations/issued-badges/${encodeURIComponent(assertion.assertionId)}/evidence`,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Credential evidence report");
    expect(body).toContain("Credential summary");
    expect(body).toContain("How this badge was issued");
    expect(body).toContain("Changes after issuance");
    expect(body).toContain('id="assertion-evidence-print"');
    expect(body).toContain('id="assertion-evidence-download-json"');
    expect(body).toContain(pageAssetPath("assertionEvidenceCss"));
    expect(body).toContain(pageAssetPath("assertionEvidenceJs"));
    expect(body).toContain("Back to badge records");
  });

  it("links badge record rows to the evidence page", async () => {
    const env = createEnv();
    const assertion = sampleTenantAssertionSummary();

    mockedListTenantAssertions.mockResolvedValueOnce([assertion]);

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges?recipientQuery=learner@example.edu",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Evidence");
    expect(body).toContain(
      `/tenants/tenant_123/admin/operations/issued-badges/${encodeURIComponent(assertion.assertionId)}/evidence`,
    );
    expect(body).not.toContain("lifecycleMode=audit");
  });
});
