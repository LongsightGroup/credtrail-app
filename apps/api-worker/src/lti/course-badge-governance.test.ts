import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findActiveDelegatedIssuingAuthorityGrantForAction: vi.fn(),
  };
});

import {
  findActiveDelegatedIssuingAuthorityGrantForAction,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type SqlDatabase,
} from "@credtrail/db";
import {
  isLtiInstructorPlaceableBadgeTemplate,
  parseLtiInstructorPlacementEnabled,
  resolveLtiCourseBadgeAuthority,
} from "./course-badge-governance";

const mockedFindActiveDelegatedIssuingAuthorityGrantForAction = vi.mocked(
  findActiveDelegatedIssuingAuthorityGrantForAction,
);

const fakeDb = {} as SqlDatabase;

const sampleBadgeTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => ({
  id: "badge_template_001",
  tenantId: "tenant_123",
  slug: "typescript-foundations",
  title: "TypeScript Foundations",
  description: "Awarded for completing TypeScript fundamentals.",
  criteriaUri: "https://example.edu/criteria",
  imageUri: "https://example.edu/image.png",
  createdByUserId: "usr_123",
  ownerOrgUnitId: "tenant_123:org:department-cs",
  governanceMetadataJson: JSON.stringify({ ltiInstructorPlacement: { enabled: true } }),
  isArchived: false,
  createdAt: "2026-02-10T22:00:00.000Z",
  updatedAt: "2026-02-10T22:00:00.000Z",
  ...overrides,
});

const sampleGrant = (
  overrides?: Partial<DelegatedIssuingAuthorityGrantRecord>,
): DelegatedIssuingAuthorityGrantRecord => ({
  id: "diag_lti_course_setup_123",
  tenantId: "tenant_123",
  delegateUserId: "usr_lti_123",
  delegatedByUserId: "usr_admin_123",
  orgUnitId: "tenant_123:org:department-cs",
  allowedActions: ["place_lti_badge", "configure_course_rule"],
  badgeTemplateIds: ["badge_template_001"],
  startsAt: "2026-02-01T00:00:00.000Z",
  endsAt: "2026-06-01T00:00:00.000Z",
  revokedAt: null,
  revokedByUserId: null,
  revokedReason: null,
  status: "active",
  createdAt: "2026-02-10T22:00:00.000Z",
  updatedAt: "2026-02-10T22:00:00.000Z",
  ...overrides,
});

describe("LTI course badge governance", () => {
  beforeEach(() => {
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
  });

  it("requires explicit instructor placement metadata", () => {
    expect(
      parseLtiInstructorPlacementEnabled(
        JSON.stringify({ ltiInstructorPlacement: { enabled: true } }),
      ),
    ).toBe(true);
    expect(parseLtiInstructorPlacementEnabled(null)).toBe(false);
    expect(parseLtiInstructorPlacementEnabled("{not-json")).toBe(false);
    expect(
      parseLtiInstructorPlacementEnabled(
        JSON.stringify({ ltiInstructorPlacement: { enabled: false } }),
      ),
    ).toBe(false);
    expect(isLtiInstructorPlaceableBadgeTemplate(sampleBadgeTemplate({ isArchived: true }))).toBe(
      false,
    );
  });

  it("resolves delegated course setup authority through existing scoped grants", async () => {
    const grant = sampleGrant();
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValueOnce(grant);

    const result = await resolveLtiCourseBadgeAuthority(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_lti_123",
      badgeTemplate: sampleBadgeTemplate(),
      requiredAction: "configure_course_rule",
    });

    expect(result).toEqual({
      ok: true,
      grant,
    });
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_lti_123",
      orgUnitId: "tenant_123:org:department-cs",
      badgeTemplateId: "badge_template_001",
      requiredAction: "configure_course_rule",
    });
  });

  it("rejects templates before grant lookup when metadata is not instructor-placeable", async () => {
    const result = await resolveLtiCourseBadgeAuthority(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_lti_123",
      badgeTemplate: sampleBadgeTemplate({ governanceMetadataJson: null }),
      requiredAction: "place_lti_badge",
    });

    expect(result).toMatchObject({
      ok: false,
      reason: "template_not_placeable",
    });
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).not.toHaveBeenCalled();
  });

  it("rejects missing active delegated authority grants", async () => {
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValueOnce(null);

    const result = await resolveLtiCourseBadgeAuthority(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_lti_123",
      badgeTemplate: sampleBadgeTemplate(),
      requiredAction: "place_lti_badge",
    });

    expect(result).toMatchObject({
      ok: false,
      reason: "missing_delegated_authority",
    });
  });
});
