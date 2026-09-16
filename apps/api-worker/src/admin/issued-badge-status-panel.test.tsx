import { describe, expect, it } from "vitest";
import type { AssertionLifecycleState } from "@credtrail/db";
import { appPage, renderAppPageToString } from "../ui/render-page";
import { IssuedBadgeStatusPanel } from "./issued-badge-status-panel";
import {
  emptyIssuedBadgesPageFilterValues,
  type IssuedBadgeLifecycleMode,
} from "./issued-badges-admin-helpers";

const renderPanel = (state: AssertionLifecycleState, mode: IssuedBadgeLifecycleMode): string =>
  renderAppPageToString(
    appPage({
      title: "Selected badge",
      body: (
        <IssuedBadgeStatusPanel
          tenantId="tenant_123"
          badge={{
            assertionId: "tenant_123:badge",
            badgeTitle: "Applied Analytics",
            recipientIdentity: "learner@example.edu",
            issuedAt: "2026-09-16T12:00:00.000Z",
            state,
          }}
          mode={mode}
          filters={{
            ...emptyIssuedBadgesPageFilterValues(),
            recipientQuery: "learner@example.edu",
          }}
        />
      ),
    }),
  );

describe("record-owned status changes", () => {
  it.each([
    ["active", "suspend", "suspended", "Suspend badge"],
    ["suspended", "restore", "active", "Restore badge"],
    ["expired", "restore", "active", "Restore badge"],
    ["active", "expire", "expired", "Mark badge expired"],
  ] as const)(
    "offers %s -> %s with the selected record and preserved search",
    (state, mode, target, label) => {
      const html = renderPanel(state, mode);
      expect(html).toContain("Applied Analytics");
      expect(html).toContain("learner@example.edu");
      expect(html).toContain(`name="toState" type="hidden" value="${target}"`);
      expect(html).toContain('name="assertionId" type="hidden" value="tenant_123:badge"');
      expect(html).toContain('name="recipientQuery" type="hidden" value="learner@example.edu"');
      expect(html).toContain('method="post"');
      expect(html).toContain(label);
      expect(html).toContain("Cancel");
      expect(html).toContain('maxlength="512"');
      expect(html).not.toContain("Assertion ID");
    },
  );

  it("requires an explicit acknowledgement for permanent revocation", () => {
    const html = renderPanel("active", "revoke");
    expect(html).toContain("Revocation is permanent");
    expect(html).toMatch(/name="confirmRevocation"[^>]*required/);
    expect(html).toContain("Choose a reason");
  });

  it("does not offer any mutation for a revoked credential, even with a restore deep link", () => {
    const html = renderPanel("revoked", "restore");
    expect(html).toContain("permanently revoked");
    expect(html).not.toContain('id="issued-badge-status-form"');
    expect(html).toContain("View badge record and history");
  });

  it("does not offer an illegal suspension of an expired credential", () => {
    const html = renderPanel("expired", "suspend");
    expect(html).not.toContain('id="issued-badge-status-form"');
    expect(html).toContain("Restore badge");
    expect(html).not.toContain("Suspend badge");
  });
});
