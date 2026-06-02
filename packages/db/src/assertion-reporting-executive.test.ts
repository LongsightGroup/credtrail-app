import { describe, expect, it } from "vitest";

import { summarizeTenantExecutiveRollup } from "./index";

describe("executive rollup foundation", () => {
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

  it("rolls institution-focused executive views into top-level child rows", () => {
    expect(
      summarizeTenantExecutiveRollup({
        rows,
        orgUnits,
        query: {
          focusOrgUnitId: "org_institution",
          comparisonLevel: "college",
        },
      }),
    ).toEqual({
      focusOrgUnitId: "org_institution",
      focusDisplayName: "CredTrail University",
      focusParentOrgUnitId: null,
      focusUnitType: "institution",
      comparisonLevel: "college",
      focusLineageOrgUnitIds: ["org_institution"],
      filters: {
        from: null,
        to: null,
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      rows: [
        expect.objectContaining({
          orgUnitId: "org_college_science",
          displayName: "College of Science",
          level: "college",
          issuedCount: 3,
          shareRate: 1 / 3,
          claimRate: 1 / 3,
        }),
        expect.objectContaining({
          orgUnitId: "org_college_arts",
          displayName: "College of Arts",
          level: "college",
          issuedCount: 1,
          publicBadgeViewCount: 1,
          shareRate: 0,
          claimRate: 0,
        }),
      ],
    });
  });

  it("keeps scoped college executive views at the direct-child level", () => {
    expect(
      summarizeTenantExecutiveRollup({
        rows,
        orgUnits,
        query: {
          focusOrgUnitId: "org_college_science",
          comparisonLevel: "department",
        },
        scopedRootOrgUnitIds: ["org_college_science"],
      }),
    ).toEqual(
      expect.objectContaining({
        focusOrgUnitId: "org_college_science",
        focusDisplayName: "College of Science",
        focusUnitType: "college",
        comparisonLevel: "department",
        focusLineageOrgUnitIds: ["org_institution", "org_college_science"],
        rows: [
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
        ],
      }),
    );
  });

  it("falls back honestly to the focused program when no deeper comparison level exists", () => {
    expect(
      summarizeTenantExecutiveRollup({
        rows,
        orgUnits,
        query: {
          focusOrgUnitId: "org_program_microbiology",
          comparisonLevel: "program",
        },
        scopedRootOrgUnitIds: ["org_program_microbiology"],
      }),
    ).toEqual(
      expect.objectContaining({
        focusOrgUnitId: "org_program_microbiology",
        focusDisplayName: "Microbiology",
        focusUnitType: "program",
        comparisonLevel: "program",
        focusLineageOrgUnitIds: [
          "org_institution",
          "org_college_science",
          "org_department_biology",
          "org_program_microbiology",
        ],
        rows: [
          expect.objectContaining({
            orgUnitId: "org_program_microbiology",
            level: "program",
            issuedCount: 2,
            shareRate: 1 / 2,
            claimRate: 0,
          }),
        ],
      }),
    );
  });
});
