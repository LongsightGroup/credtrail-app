import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import { describe, expect, it } from "vitest";

import { buildBadgeRuleVersionRecord } from "../../test-support/badge-rule-version";
import { renderBadgeRulesTable } from "./badge-rules-table";

const sampleRule = (overrides: Partial<BadgeIssuanceRuleRecord> = {}): BadgeIssuanceRuleRecord => ({
  id: "brl_registry",
  tenantId: "tenant_123",
  name: "Registry rule",
  description: null,
  badgeTemplateId: "badge_template_001",
  orgUnitId: "tenant_123:org:institution",
  ownerOrgUnitId: "tenant_123:org:institution",
  lmsProviderKind: "canvas",
  lmsConnectionId: "lms_canvas",
  activeVersionId: null,
  createdByUserId: "usr_admin",
  createdAt: "2026-02-18T12:00:00.000Z",
  updatedAt: "2026-02-18T12:30:00.000Z",
  ...overrides,
});

const renderRulesTable = async (
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): Promise<string> => {
  const rendered = await renderBadgeRulesTable({
    tenantId: rule.tenantId,
    userId: "usr_admin",
    ruleBuilderPath: `/tenants/${rule.tenantId}/admin/rules/new`,
    rulesTemplatesPath: `/tenants/${rule.tenantId}/admin/rules/templates`,
    badgeRules: [rule],
    badgeRuleVersions: versions,
    builderDraftRows: [],
    builderDraftCount: 0,
    registry: {
      searchQuery: "",
      latestStatus: null,
      sort: "updated",
      direction: "desc",
      limit: 50,
      totalCount: 1,
      previousPageHref: null,
      nextPageHref: null,
    },
  });

  return rendered.toString();
};

describe("badge rules table lifecycle states", () => {
  it("renders an incomplete rule as cleanup-only", async () => {
    const rule = sampleRule({ id: "brl_incomplete", name: "Incomplete cleanup rule" });
    const html = await renderRulesTable(rule, []);

    expect(html).toContain("Setup incomplete");
    expect(html).toContain("No version was created");
    expect(html).toContain("Needs cleanup");
    expect(html).toContain('action="/tenants/tenant_123/admin/rules/brl_incomplete/delete"');
    expect(html).not.toContain('href="/tenants/tenant_123/admin/rules/brl_incomplete"');
    expect(html).not.toContain("copyRuleId=");
    expect(html).not.toContain("/availability");
  });

  it("surfaces an invalid active-version reference without calling it incomplete", async () => {
    const rule = sampleRule({
      id: "brl_invalid_active",
      name: "Rule with invalid active version",
      activeVersionId: "brv_missing",
    });
    const latestVersion = buildBadgeRuleVersionRecord({
      id: "brv_latest",
      ruleId: rule.id,
      versionNumber: 2,
      status: "draft",
    });
    const html = await renderRulesTable(rule, [latestVersion]);

    expect(html).toContain("Version reference unavailable");
    expect(html).toContain("The saved active version was not found");
    expect(html).toContain("Needs attention");
    expect(html).toContain('href="/tenants/tenant_123/admin/rules/brl_invalid_active"');
    expect(html).not.toContain("Setup incomplete");
    expect(html).not.toContain(
      'action="/tenants/tenant_123/admin/rules/brl_invalid_active/delete"',
    );
    expect(html).not.toContain("copyRuleId=");
    expect(html).not.toContain("/availability");
  });

  it("offers Copy on a resolved rule row with an encoded tenant-local source", async () => {
    const rule = sampleRule({ id: "brl_copy/source", name: "Mutable rule head" });
    const version = buildBadgeRuleVersionRecord({
      id: "brv_copy",
      ruleId: rule.id,
      snapshot: { name: "Course completion source" },
    });
    const html = await renderRulesTable(rule, [version]);

    expect(html).toContain(
      'href="/tenants/tenant_123/admin/rules/new?copyRuleId=brl_copy%2Fsource"',
    );
    expect(html).toContain('aria-label="Copy Course completion source"');
    expect(html).toContain(">Copy</a>");
    expect(html).toContain('href="/tenants/tenant_123/admin/rules/brl_copy%2Fsource/availability"');
    expect(html).toContain('aria-label="Set course availability for Course completion source"');
    expect(html).toContain(">Set course availability</a>");
    expect(html).toContain('class="ct-admin__rule-row-actions ct-action-group"');
    expect(html).not.toContain("Mutable rule head");
  });
});
