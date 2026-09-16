import { describe, expect, it } from "vitest";
import type { TenantRecord } from "@credtrail/db";
import { buildBadgeRuleVersionRecord } from "../../test-support/badge-rule-version";
import { buildInstitutionAdminHomeViewResources } from "./home-view-resources";
import { buildInstitutionAdminViewPaths } from "./view-paths";
const renderMarkup = (node: { toString(): string }): string => node.toString();

const tenant: TenantRecord = {
  id: "tenant_123",
  slug: "example",
  displayName: "Example",
  planTier: "team",
  issuerDomain: "example.edu",
  didWeb: "did:web:example.edu",
  isActive: true,
  createdAt: "2026-09-01",
  updatedAt: "2026-09-01",
};

describe("Home workflow tasks", () => {
  it("keeps authoritative counts separate from the small task list and waiting summary", () => {
    const version = buildBadgeRuleVersionRecord({ status: "pending_approval" });
    const content = buildInstitutionAdminHomeViewResources({
      paths: buildInstitutionAdminViewPaths(tenant.id),
      page: {
        tenant,
        workflowHome: {
          ruleCount: 42,
          activeRuleCount: 20,
          actionCount: 7,
          waitingCount: 3,
          tasks: [{ action: "review", version, current: false }],
        },
      },
    });
    const html = renderMarkup(<div>{content.workspaceCardsMarkup}</div>);
    expect(html).toContain("42 rules");
    expect(html).toContain("20 active");
    expect(html).toContain("7 rules need attention");
    expect(html).toContain("3 of your submitted rules are waiting for another reviewer");
    expect(html).toContain(`/rules/approvals/${version.ruleId}/versions/${version.id}`);
    expect(html).toContain("You can review this submission.");
  });
  it("omits action clutter when nothing needs attention", () => {
    const content = buildInstitutionAdminHomeViewResources({
      paths: buildInstitutionAdminViewPaths(tenant.id),
      page: {
        tenant,
        workflowHome: {
          ruleCount: 0,
          activeRuleCount: 0,
          actionCount: 0,
          waitingCount: 0,
          tasks: [],
        },
      },
    });
    const html = renderMarkup(<div>{content.workspaceCardsMarkup}</div>);
    expect(html).not.toContain("Action needed");
    expect(html).not.toContain("Start Here");
    expect(html).toContain("Open Badge Program workspace");
  });
});
