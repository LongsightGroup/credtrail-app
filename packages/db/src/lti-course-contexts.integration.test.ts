import { expect, it } from "vitest";

import {
  assignLmsCourseContextOrgUnit,
  findTenantLmsCourseContextById,
  findTenantLmsCourseContextByIdentity,
  listTenantLmsCourseContexts,
  observeVerifiedLtiCourseContext,
  upsertCatalogLmsCourseContext,
} from "./lti-course-contexts.js";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy,
  describeDbIntegration,
  uniqueTestId,
} from "./postgres-test-support.js";
import { upsertTenantLmsConnection } from "./tenant-lms-connections.js";
import { createTenantOrgUnit } from "./tenant-org-units.js";

describeDbIntegration("LMS course contexts with Postgres", () => {
  it("keeps catalog metadata separate from monotonic verified launch evidence", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const catalog = await upsertCatalogLmsCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: "course-101",
        displayName: "Intro to Computing",
        courseCode: "CS 101",
        createdByUserId: fixture.userId,
      });

      expect(catalog).toMatchObject({
        contextId: "course-101",
        displayName: "Intro to Computing",
        courseCode: "CS 101",
        firstSeenAt: null,
        lastSeenAt: null,
      });

      const firstLaunch = await observeVerifiedLtiCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: "course-101",
        displayName: "Introduction to Computing",
        courseCode: "CS-101",
        observedAt: "2026-08-20T12:00:00.000Z",
      });
      const olderReplay = await observeVerifiedLtiCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: "course-101",
        displayName: "Computing Foundations",
        observedAt: "2026-08-19T12:00:00.000Z",
      });
      const laterLaunch = await observeVerifiedLtiCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: "course-101",
        displayName: "Computing Foundations",
        observedAt: "2026-08-22T12:00:00.000Z",
      });

      expect(firstLaunch.id).toBe(catalog.id);
      expect(olderReplay).toMatchObject({
        firstSeenAt: "2026-08-19T12:00:00.000Z",
        lastSeenAt: "2026-08-20T12:00:00.000Z",
      });
      expect(laterLaunch).toMatchObject({
        displayName: "Computing Foundations",
        courseCode: null,
        firstSeenAt: "2026-08-19T12:00:00.000Z",
        lastSeenAt: "2026-08-22T12:00:00.000Z",
      });

      const catalogRefresh = await upsertCatalogLmsCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: "course-101",
        displayName: "Computing Foundations — Fall",
        courseCode: "CS 101-01",
        createdByUserId: fixture.userId,
      });

      expect(catalogRefresh).toMatchObject({
        id: catalog.id,
        displayName: "Computing Foundations — Fall",
        courseCode: "CS 101-01",
        firstSeenAt: "2026-08-19T12:00:00.000Z",
        lastSeenAt: "2026-08-22T12:00:00.000Z",
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("assigns only an active same-tenant course and refuses silent remapping", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const hierarchy = await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });
      const secondCourse = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "course",
        slug: "cs-102",
        displayName: "CS 102",
        parentOrgUnitId: hierarchy.department.id,
        createdByUserId: fixture.userId,
      });
      const inactiveCourse = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "course",
        slug: "cs-103",
        displayName: "CS 103",
        parentOrgUnitId: hierarchy.department.id,
        createdByUserId: fixture.userId,
      });
      await fixture.db
        .prepare("UPDATE tenant_org_units SET is_active = 0 WHERE tenant_id = ? AND id = ?")
        .bind(fixture.tenantId, inactiveCourse.id)
        .run();
      const context = await upsertCatalogLmsCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: "course-map",
        displayName: "Course to map",
        createdByUserId: fixture.userId,
      });

      expect(
        await assignLmsCourseContextOrgUnit(fixture.db, {
          tenantId: fixture.tenantId,
          courseContextId: context.id,
          courseOrgUnitId: hierarchy.department.id,
        }),
      ).toEqual({ status: "org_unit_not_course" });
      expect(
        await assignLmsCourseContextOrgUnit(fixture.db, {
          tenantId: fixture.tenantId,
          courseContextId: context.id,
          courseOrgUnitId: inactiveCourse.id,
        }),
      ).toEqual({ status: "org_unit_inactive" });

      const assigned = await assignLmsCourseContextOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        courseContextId: context.id,
        courseOrgUnitId: hierarchy.course.id,
      });

      expect(assigned).toMatchObject({
        status: "assigned",
        courseContext: { courseOrgUnitId: hierarchy.course.id },
      });
      expect(
        await assignLmsCourseContextOrgUnit(fixture.db, {
          tenantId: fixture.tenantId,
          courseContextId: context.id,
          courseOrgUnitId: hierarchy.course.id,
        }),
      ).toMatchObject({ status: "unchanged" });
      expect(
        await assignLmsCourseContextOrgUnit(fixture.db, {
          tenantId: fixture.tenantId,
          courseContextId: context.id,
          courseOrgUnitId: secondCourse.id,
        }),
      ).toEqual({
        status: "mapping_conflict",
        existingCourseOrgUnitId: hierarchy.course.id,
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("isolates identical context strings by LMS connection and tenant", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const otherFixture = await createBadgeRuleIntegrationFixture();

    try {
      const secondConnection = await upsertTenantLmsConnection(fixture.db, {
        id: uniqueTestId("lms_second"),
        tenantId: fixture.tenantId,
        displayName: "Second LMS",
        providerKind: "sakai",
        apiBaseUrl: "https://sakai.example.test",
      });
      const first = await upsertCatalogLmsCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: "shared-context",
        displayName: "First LMS course",
        createdByUserId: fixture.userId,
      });
      const second = await upsertCatalogLmsCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: secondConnection.id,
        contextId: "shared-context",
        displayName: "Second LMS course",
        createdByUserId: fixture.userId,
      });

      expect(first.id).not.toBe(second.id);
      expect(
        await findTenantLmsCourseContextByIdentity(fixture.db, {
          tenantId: fixture.tenantId,
          lmsConnectionId: secondConnection.id,
          contextId: "shared-context",
        }),
      ).toMatchObject({ id: second.id });
      expect(
        await findTenantLmsCourseContextById(fixture.db, {
          tenantId: otherFixture.tenantId,
          courseContextId: first.id,
        }),
      ).toBeNull();
      expect(
        await listTenantLmsCourseContexts(fixture.db, {
          tenantId: fixture.tenantId,
        }),
      ).toHaveLength(2);
      await expect(
        upsertCatalogLmsCourseContext(fixture.db, {
          tenantId: otherFixture.tenantId,
          lmsConnectionId: fixture.lmsConnectionId,
          contextId: "cross-tenant",
          displayName: "Cross tenant",
          createdByUserId: otherFixture.userId,
        }),
      ).rejects.toThrow(/foreign key/i);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId, otherFixture.tenantId],
        userIds: [fixture.userId, otherFixture.userId],
      });
    }
  });
});
