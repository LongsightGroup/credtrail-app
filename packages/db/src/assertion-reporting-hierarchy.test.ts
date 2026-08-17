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
    const comparisonRows = [
      {
        groupBy: "orgUnit" as const,
        groupId: "org_program_microbiology",
        issuedCount: 2,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 1,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        shareEngagedCount: 1,
        claimEngagedCount: 0,
      },
      {
        groupBy: "orgUnit" as const,
        groupId: "org_program_biochemistry",
        issuedCount: 1,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 0,
        learnerClaimCount: 1,
        walletAcceptCount: 0,
        shareEngagedCount: 0,
        claimEngagedCount: 1,
      },
      {
        groupBy: "orgUnit" as const,
        groupId: "org_program_music_theory",
        issuedCount: 1,
        publicBadgeViewCount: 1,
        verificationViewCount: 0,
        shareClickCount: 0,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        shareEngagedCount: 0,
        claimEngagedCount: 0,
      },
    ];

    expect(
      summarizeTenantReportingHierarchyRows({
        comparisonRows,
        orgUnits,
        level: "institution",
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
        comparisonRows,
        orgUnits,
        level: "college",
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
        comparisonRows,
        orgUnits,
        level: "department",
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
        comparisonRows,
        orgUnits,
        level: "program",
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
    const comparisonRows = [
      {
        groupBy: "orgUnit" as const,
        groupId: "org_program_microbiology",
        issuedCount: 1,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 2,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        shareEngagedCount: 1,
        claimEngagedCount: 0,
      },
      {
        groupBy: "orgUnit" as const,
        groupId: "org_program_biochemistry",
        issuedCount: 1,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 0,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
        shareEngagedCount: 0,
        claimEngagedCount: 1,
      },
      {
        groupBy: "orgUnit" as const,
        groupId: "org_program_music_theory",
        issuedCount: 1,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 1,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        shareEngagedCount: 1,
        claimEngagedCount: 0,
      },
    ];

    expect(
      summarizeTenantReportingHierarchyRows({
        comparisonRows,
        orgUnits,
        focusOrgUnitId: "org_college_science",
        level: "department",
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
