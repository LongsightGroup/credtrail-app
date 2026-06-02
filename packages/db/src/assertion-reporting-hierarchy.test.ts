import { describe, expect, it } from "vitest";

import { summarizeTenantReportingHierarchyRows } from "./index";
import * as validationModule from "../../validation/src/index";

const parseTenantReportingHierarchyQuery = validationModule.parseTenantReportingHierarchyQuery;

describe("hierarchy reporting foundation", () => {
  const orgUnits = [
    {
      id: "org_institution",
      unitType: "institution" as const,
      displayName: "CredTrail University",
      parentOrgUnitId: null,
    },
    {
      id: "org_college_science",
      unitType: "college" as const,
      displayName: "College of Science",
      parentOrgUnitId: "org_institution",
    },
    {
      id: "org_college_arts",
      unitType: "college" as const,
      displayName: "College of Arts",
      parentOrgUnitId: "org_institution",
    },
    {
      id: "org_department_biology",
      unitType: "department" as const,
      displayName: "Biology",
      parentOrgUnitId: "org_college_science",
    },
    {
      id: "org_department_chemistry",
      unitType: "department" as const,
      displayName: "Chemistry",
      parentOrgUnitId: "org_college_science",
    },
    {
      id: "org_department_music",
      unitType: "department" as const,
      displayName: "Music",
      parentOrgUnitId: "org_college_arts",
    },
    {
      id: "org_program_microbiology",
      unitType: "program" as const,
      displayName: "Microbiology",
      parentOrgUnitId: "org_department_biology",
    },
    {
      id: "org_program_biochemistry",
      unitType: "program" as const,
      displayName: "Biochemistry",
      parentOrgUnitId: "org_department_chemistry",
    },
    {
      id: "org_program_music_theory",
      unitType: "program" as const,
      displayName: "Music Theory",
      parentOrgUnitId: "org_department_music",
    },
  ];

  it("rolls leaf-attributed reporting rows into institution, college, department, and program groupings", () => {
    const rows = [
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_microbiology",
        issuedAt: "2026-03-01T08:00:00.000Z",
        eventType: null,
        occurredAt: null,
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_microbiology",
        issuedAt: "2026-03-01T09:00:00.000Z",
        eventType: "share_click" as const,
        occurredAt: "2026-03-03T08:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_biochemistry",
        issuedAt: "2026-03-02T09:00:00.000Z",
        eventType: "learner_claim" as const,
        occurredAt: "2026-03-04T08:00:00.000Z",
      },
      {
        assertionId: "assertion_4",
        badgeTemplateId: "bt_arts",
        orgUnitId: "org_program_music_theory",
        issuedAt: "2026-03-02T10:00:00.000Z",
        eventType: "public_badge_view" as const,
        occurredAt: "2026-03-04T09:00:00.000Z",
      },
    ];

    expect(
      summarizeTenantReportingHierarchyRows({
        rows,
        orgUnits,
        query: {
          level: "institution",
        },
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_institution",
        level: "institution",
        issuedCount: 4,
      }),
    ]);

    expect(
      summarizeTenantReportingHierarchyRows({
        rows,
        orgUnits,
        query: {
          level: "college",
        },
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_college_science",
        level: "college",
        issuedCount: 3,
      }),
      expect.objectContaining({
        orgUnitId: "org_college_arts",
        level: "college",
        issuedCount: 1,
      }),
    ]);

    expect(
      summarizeTenantReportingHierarchyRows({
        rows,
        orgUnits,
        query: {
          level: "department",
        },
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_department_biology",
        level: "department",
        issuedCount: 2,
      }),
      expect.objectContaining({
        orgUnitId: "org_department_chemistry",
        level: "department",
        issuedCount: 1,
      }),
      expect.objectContaining({
        orgUnitId: "org_department_music",
        level: "department",
        issuedCount: 1,
      }),
    ]);

    expect(
      summarizeTenantReportingHierarchyRows({
        rows,
        orgUnits,
        query: {
          level: "program",
        },
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_program_microbiology",
        level: "program",
        issuedCount: 2,
      }),
      expect.objectContaining({
        orgUnitId: "org_program_biochemistry",
        level: "program",
        issuedCount: 1,
      }),
      expect.objectContaining({
        orgUnitId: "org_program_music_theory",
        level: "program",
        issuedCount: 1,
      }),
    ]);
  });

  it("adds an explicit hierarchy query contract without redefining exact-match orgUnitId filters", () => {
    expect(
      parseTenantReportingHierarchyQuery({
        from: "2026-03-01",
        to: "2026-03-31",
        focusOrgUnitId: "org_college_science",
        level: "department",
      }),
    ).toEqual({
      from: "2026-03-01",
      to: "2026-03-31",
      focusOrgUnitId: "org_college_science",
      level: "department",
    });

    expect(
      validationModule.parseTenantReportingComparisonQuery({
        from: "2026-03-01",
        to: "2026-03-31",
        orgUnitId: "org_program_microbiology",
        groupBy: "orgUnit",
      }),
    ).toEqual({
      from: "2026-03-01",
      to: "2026-03-31",
      orgUnitId: "org_program_microbiology",
      groupBy: "orgUnit",
    });
  });

  it("keeps Phase 10 raw counts and distinct-assertion rates intact after subtree filtering", () => {
    const rows = [
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_microbiology",
        issuedAt: "2026-03-01T08:00:00.000Z",
        eventType: "share_click" as const,
        occurredAt: "2026-03-02T08:00:00.000Z",
      },
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_microbiology",
        issuedAt: "2026-03-01T08:00:00.000Z",
        eventType: "share_click" as const,
        occurredAt: "2026-03-02T09:00:00.000Z",
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_biochemistry",
        issuedAt: "2026-03-01T09:00:00.000Z",
        eventType: "learner_claim" as const,
        occurredAt: "2026-03-03T08:00:00.000Z",
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_biochemistry",
        issuedAt: "2026-03-01T09:00:00.000Z",
        eventType: "wallet_accept" as const,
        occurredAt: "2026-03-03T09:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_arts",
        orgUnitId: "org_program_music_theory",
        issuedAt: "2026-03-01T10:00:00.000Z",
        eventType: "share_click" as const,
        occurredAt: "2026-03-03T10:00:00.000Z",
      },
    ];

    expect(
      summarizeTenantReportingHierarchyRows({
        rows,
        orgUnits,
        query: {
          focusOrgUnitId: "org_college_science",
          level: "department",
        },
        scopedRootOrgUnitIds: ["org_college_science"],
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_department_biology",
        level: "department",
        issuedCount: 1,
        shareClickCount: 2,
        shareRate: 1,
        claimRate: 0,
      }),
      expect.objectContaining({
        orgUnitId: "org_department_chemistry",
        level: "department",
        issuedCount: 1,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
        shareRate: 0,
        claimRate: 1,
      }),
    ]);
  });
});
