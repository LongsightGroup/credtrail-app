import { describe, expect, it } from "vitest";
import { renderAppPageToString } from "../ui/render-page";
import { createLearnerDashboardPage } from "./pages";

describe("learner dashboard page", () => {
  it("renders DID settings fields with form primitives", () => {
    const renderLearnerDashboardPage = createLearnerDashboardPage({
      formatIsoTimestamp: (timestampIso) => timestampIso,
    });
    const html = renderAppPageToString(
      renderLearnerDashboardPage(
        "https://credtrail.test/tenants/tenant_123/learner/dashboard",
        "tenant_123",
        [],
        "did:key:z6MkExample",
        null,
        null,
      ),
    );

    expect(html).toContain('action="/tenants/tenant_123/learner/settings/did"');
    expect(html).toContain("learner-dashboard__did-form ct-form");
    expect(html).toContain("learner-dashboard__did-label ct-field");
    expect(html).toContain("learner-dashboard__did-input ct-input ct-field__control");
    expect(html).toContain('name="did"');
    expect(html).toContain('value="did:key:z6MkExample"');
    expect(html).toContain('placeholder="did:key:z6Mk..."');
  });
});
