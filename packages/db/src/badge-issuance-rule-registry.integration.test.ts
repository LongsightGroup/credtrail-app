import { expect, it } from "vitest";

import { createBadgeIssuanceRule } from "./badge-issuance-rule-writes";
import { listBadgeIssuanceRuleRegistryPage } from "./badge-issuance-rule-registry";
import type {
  BadgeIssuanceRuleRegistryCursor,
  BadgeIssuanceRuleRegistrySort,
} from "./badge-issuance-rule-types";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy,
  describeDbIntegration,
} from "./postgres-test-support";

const requireCursor = (
  cursor: BadgeIssuanceRuleRegistryCursor | null,
): BadgeIssuanceRuleRegistryCursor => {
  if (cursor === null) {
    throw new Error("Expected the registry fixture to produce a page cursor");
  }

  return cursor;
};

const createRegistryRule = async (
  fixture: Awaited<ReturnType<typeof createBadgeRuleIntegrationFixture>>,
  name: string,
  orgUnitId?: string,
) => {
  return createBadgeIssuanceRule(fixture.db, {
    tenantId: fixture.tenantId,
    name,
    badgeTemplateId: fixture.badgeTemplateId,
    ...(orgUnitId === undefined ? {} : { orgUnitId }),
    lmsProviderKind: "canvas",
    lmsConnectionId: fixture.lmsConnectionId,
    ruleJson: JSON.stringify({
      conditions: { type: "course_membership", courseId: name.toLowerCase() },
    }),
    createdByUserId: fixture.userId,
  });
};

describeDbIntegration("badge issuance rule registry with Postgres", () => {
  it("searches, filters, sorts, and traverses stable cursor pages", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await Promise.all(
        ["Gamma Rule", "Alpha Rule", "Epsilon Rule", "Beta Rule", "Delta Rule"].map((name) =>
          createRegistryRule(fixture, name),
        ),
      );
      const gamma = created[0];
      if (gamma === undefined) {
        throw new Error("Gamma registry fixture was not created");
      }

      await fixture.db
        .prepare(
          `
          UPDATE badge_issuance_rule_versions
          SET status = 'pending_approval'
          WHERE tenant_id = ?
            AND id = ?
        `,
        )
        .bind(fixture.tenantId, gamma.version.id)
        .run();

      const firstPage = await listBadgeIssuanceRuleRegistryPage(fixture.db, {
        tenantId: fixture.tenantId,
        searchQuery: "rule",
        sort: "rule",
        direction: "asc",
        limit: 2,
      });
      const secondPage = await listBadgeIssuanceRuleRegistryPage(fixture.db, {
        tenantId: fixture.tenantId,
        searchQuery: "rule",
        sort: "rule",
        direction: "asc",
        limit: 2,
        cursor: {
          position: "after",
          boundary: requireCursor(firstPage.nextCursor),
        },
      });
      const previousPage = await listBadgeIssuanceRuleRegistryPage(fixture.db, {
        tenantId: fixture.tenantId,
        searchQuery: "rule",
        sort: "rule",
        direction: "asc",
        limit: 2,
        cursor: {
          position: "before",
          boundary: requireCursor(secondPage.previousCursor),
        },
      });
      const statusPage = await listBadgeIssuanceRuleRegistryPage(fixture.db, {
        tenantId: fixture.tenantId,
        searchQuery: "gamma",
        latestStatus: "pending_approval",
        sort: "updated",
        direction: "desc",
        limit: 25,
      });
      const descendingFirstPage = await listBadgeIssuanceRuleRegistryPage(fixture.db, {
        tenantId: fixture.tenantId,
        searchQuery: "",
        sort: "updated",
        direction: "desc",
        limit: 2,
      });
      const descendingSecondPage = await listBadgeIssuanceRuleRegistryPage(fixture.db, {
        tenantId: fixture.tenantId,
        searchQuery: "",
        sort: "updated",
        direction: "desc",
        limit: 2,
        cursor: {
          position: "after",
          boundary: requireCursor(descendingFirstPage.nextCursor),
        },
      });
      const descendingPreviousPage = await listBadgeIssuanceRuleRegistryPage(fixture.db, {
        tenantId: fixture.tenantId,
        searchQuery: "",
        sort: "updated",
        direction: "desc",
        limit: 2,
        cursor: {
          position: "before",
          boundary: requireCursor(descendingSecondPage.previousCursor),
        },
      });
      const sortOptions: readonly BadgeIssuanceRuleRegistrySort[] = [
        "rule",
        "badge",
        "lms",
        "current_version",
        "latest_version",
        "updated",
      ];
      const sortedPages = await Promise.all(
        sortOptions.map((sort) =>
          listBadgeIssuanceRuleRegistryPage(fixture.db, {
            tenantId: fixture.tenantId,
            searchQuery: "",
            sort,
            direction: "asc",
            limit: 25,
          }),
        ),
      );

      expect(firstPage.totalCount).toBe(5);
      expect(firstPage.rules.map((rule) => rule.name)).toEqual(["Alpha Rule", "Beta Rule"]);
      expect(secondPage.rules.map((rule) => rule.name)).toEqual(["Delta Rule", "Epsilon Rule"]);
      expect(previousPage.rules.map((rule) => rule.name)).toEqual(["Alpha Rule", "Beta Rule"]);
      expect(statusPage.rules.map((rule) => rule.name)).toEqual(["Gamma Rule"]);
      expect(descendingSecondPage.rules.map((rule) => rule.id)).not.toEqual(
        descendingFirstPage.rules.map((rule) => rule.id),
      );
      expect(descendingPreviousPage.rules.map((rule) => rule.id)).toEqual(
        descendingFirstPage.rules.map((rule) => rule.id),
      );
      expect(sortedPages.every((page) => page.totalCount === 5)).toBe(true);
      expect(firstPage.previousCursor).toBeNull();
      expect(secondPage.previousCursor).not.toBeNull();
      expect(secondPage.nextCursor).not.toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("keeps descendant org-unit visibility inside the paginated registry", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const { department, course } = await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });
      await createRegistryRule(fixture, "Institution Rule");
      await createRegistryRule(fixture, "Course Rule", course.id);

      const page = await listBadgeIssuanceRuleRegistryPage(fixture.db, {
        tenantId: fixture.tenantId,
        scope: { type: "descendants", rootOrgUnitIds: [department.id] },
        searchQuery: "",
        sort: "rule",
        direction: "asc",
        limit: 25,
      });

      expect(page.totalCount).toBe(1);
      expect(page.rules.map((rule) => rule.name)).toEqual(["Course Rule"]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});
