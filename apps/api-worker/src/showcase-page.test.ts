import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findUserById: vi.fn(),
    listPublicBadgeWallEntries: vi.fn(),
    resolveAssertionLifecycleState: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  listPublicBadgeWallEntries,
  resolveAssertionLifecycleState,
  type PublicBadgeWallEntryRecord,
  type ResolveAssertionLifecycleStateResult,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { PUBLIC_BADGE_CSS } from "./ui/page-assets/content/public-badge-css";

const mockedListPublicBadgeWallEntries = vi.mocked(listPublicBadgeWallEntries);
const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const samplePublicBadgeWallEntry = (
  overrides?: Partial<PublicBadgeWallEntryRecord>,
): PublicBadgeWallEntryRecord => {
  return {
    assertionId: "sakai:assertion_001",
    assertionPublicId: "a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf",
    tenantId: "sakai",
    badgeTemplateId: "badge_template_sakai_1000",
    badgeTitle: "Sakai 1000+ Commits Contributor",
    badgeDescription: "Awarded for 1000+ commits.",
    badgeImageUri: null,
    recipientIdentity: "https://github.com/ottenhoff",
    recipientIdentityType: "url",
    issuedAt: "2026-02-11T16:29:14.571Z",
    revokedAt: null,
    ...overrides,
  };
};

const sampleLifecycle = (
  overrides?: Partial<ResolveAssertionLifecycleStateResult>,
): ResolveAssertionLifecycleStateResult => {
  return {
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: null,
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe("GET /showcase/:tenantId", () => {
  beforeEach(() => {
    mockedListPublicBadgeWallEntries.mockReset();
    mockedResolveAssertionLifecycleState.mockReset();
    mockedResolveAssertionLifecycleState.mockResolvedValue(sampleLifecycle());
  });

  it("renders public tenant badge wall entries with badge URLs", async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([
      samplePublicBadgeWallEntry(),
      samplePublicBadgeWallEntry({
        assertionPublicId: "620b51c5-c6f8-4506-8a5c-2daaa2eb6f04",
        recipientIdentity: "https://github.com/steveswinsburg",
        badgeTitle: "Sakai Distinguished Contributor",
      }),
    ]);

    const response = await app.request("/showcase/sakai", undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Sakai 1000+ Commits Contributor · sakai");
    expect(body).toContain("2 issued badges");
    expect(body).toContain("/badges/a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf");
    expect(body).toContain("/badges/620b51c5-c6f8-4506-8a5c-2daaa2eb6f04");
    expect(body).toContain("/showcase/sakai/criteria?badgeTemplateId=badge_template_sakai_1000");
    expect(body).toContain(
      '<link rel="canonical" href="http://localhost/showcase/sakai?badgeTemplateId=badge_template_sakai_1000"',
    );
    expect(body).toContain(
      '<meta property="og:title" content="Sakai 1000+ Commits Contributor · sakai | CredTrail"',
    );
    expect(body).toContain('<meta property="og:type" content="website"');
    expect(body).toContain('<meta name="twitter:card" content="summary"');
    expect(body).toContain(
      '<meta name="description" content="Publicly verified credentials for Sakai 1000+ Commits Contributor."',
    );
    expect(body).toContain("http://localhost/badges/a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf");
    expect(body).toContain("@ottenhoff");
    expect(body).toContain("Sakai 1000+ Commits Contributor");
    expect(body).toContain("Sakai Distinguished Contributor");
    expect(body).toContain("github.com/ottenhoff.png");
    expect(body).toContain("View credential");
    expect(body).toContain('aria-label="Copy link"');
    expect(body).toContain('class="badge-wall__icon-button"');
    expect(body).toContain('rel="stylesheet" href="/assets/ui/public-badge.');
    expect(PUBLIC_BADGE_CSS).toContain(".badge-wall__hero-link:hover");
    expect(PUBLIC_BADGE_CSS).toContain(".badge-wall__button--primary:hover");
    expect(mockedListPublicBadgeWallEntries).toHaveBeenCalledWith(fakeDb, {
      tenantId: "sakai",
      badgeTemplateId: "badge_template_sakai_1000",
    });
    expect(mockedResolveAssertionLifecycleState).toHaveBeenCalledTimes(2);
  });

  it("renders lifecycle status labels for non-active entries", async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([samplePublicBadgeWallEntry()]);
    mockedResolveAssertionLifecycleState.mockResolvedValue(
      sampleLifecycle({
        state: "suspended",
        source: "lifecycle_event",
        reasonCode: "appeal_pending",
        reason: "Credential is suspended while appeal is reviewed.",
        transitionedAt: "2026-02-18T00:00:00.000Z",
      }),
    );

    const response = await app.request("/showcase/sakai", undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Suspended");
    expect(body).toContain("Credential is suspended while appeal is reviewed.");
  });

  it("applies badgeTemplateId filter when provided", async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([
      samplePublicBadgeWallEntry({
        badgeImageUri: "https://example.edu/badges/intro-to-badging.png",
        badgeTitle: "Intro to Badging",
        badgeDescription: "Awarded for completing an introduction to badging.",
      }),
    ]);

    const response = await app.request(
      "/showcase/sakai?badgeTemplateId=badge_template_sakai_1000",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Intro to Badging · sakai");
    expect(body).toContain("Publicly verified credentials for Intro to Badging.");
    expect(body).toContain('class="badge-wall__hero-image-frame"');
    expect(body).toContain('class="badge-wall__hero-image"');
    expect(body).toContain('src="https://example.edu/badges/intro-to-badging.png"');
    expect(body).toContain("Awarded for completing an introduction to badging.");
    expect(mockedListPublicBadgeWallEntries).toHaveBeenCalledWith(fakeDb, {
      tenantId: "sakai",
      badgeTemplateId: "badge_template_sakai_1000",
    });
  });

  it("renders empty state when no badges are present", async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([]);

    const response = await app.request("/showcase/sakai", undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("0 issued badges");
    expect(body).toContain("No public badges found for this showcase.");
  });
});
