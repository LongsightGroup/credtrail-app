import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockedFindTenantLmsUserIdentity } = vi.hoisted(() => ({
  mockedFindTenantLmsUserIdentity: vi.fn(),
}));

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findTenantLmsUserIdentity: mockedFindTenantLmsUserIdentity,
  };
});

import type {
  SqlDatabase,
  TenantLmsConnectionRecord,
  TenantLmsUserIdentityRecord,
} from "@credtrail/db";
import type { GradebookProvider } from "./gradebook-types";
import { authorizeLmsUserCourses, authorizeLmsUserCoursesWithScope } from "./user-course-access";

const connection: TenantLmsConnectionRecord = {
  id: "lms_123",
  tenantId: "tenant_123",
  displayName: "Institution Sakai",
  providerKind: "sakai",
  apiBaseUrl: "https://sakai.example.edu",
  authorizationEndpoint: null,
  tokenEndpoint: null,
  clientId: "service-admin",
  clientSecret: "secret",
  scope: null,
  accessToken: "SAKAIID=session",
  refreshToken: null,
  accessTokenExpiresAt: null,
  refreshTokenExpiresAt: null,
  connectedAt: "2026-07-26T00:00:00.000Z",
  ltiIssuer: "https://sakai.example.edu",
  ltiClientId: "credtrail-client",
  ltiDeploymentId: "deployment-1",
  createdAt: "2026-07-26T00:00:00.000Z",
  updatedAt: "2026-07-26T00:00:00.000Z",
};

const canvasConnection: TenantLmsConnectionRecord = {
  ...connection,
  displayName: "Institution Canvas",
  providerKind: "canvas",
};

const identity: TenantLmsUserIdentityRecord = {
  tenantId: "tenant_123",
  connectionId: "lms_123",
  userId: "usr_123",
  providerUserId: "instructor-123",
  createdAt: "2026-07-26T00:00:00.000Z",
  updatedAt: "2026-07-26T00:00:00.000Z",
};

const createProvider = (
  kind: GradebookProvider["kind"],
  verifyCourseAccess: GradebookProvider["verifyCourseAccess"],
): GradebookProvider => ({
  kind,
  listCourses: () => Promise.resolve({ courses: [], hasMore: false }),
  verifyCourseAccess,
  listAssignments: () => Promise.resolve([]),
  listEnrollments: () => Promise.resolve([]),
  listLearners: () => Promise.resolve([]),
  listSubmissions: () => Promise.resolve([]),
  listGrades: () => Promise.resolve([]),
  listCompletions: () => Promise.resolve([]),
});

describe("authorizeLmsUserCourses", () => {
  beforeEach(() => {
    mockedFindTenantLmsUserIdentity.mockReset();
  });

  it("uses the saved Sakai administrator connection without requiring an LTI identity", async () => {
    mockedFindTenantLmsUserIdentity.mockResolvedValue(null);
    const verifyCourseAccess = vi.fn().mockResolvedValue({
      authorizedCourses: [],
      unauthorizedCourseIds: [],
    });

    const result = await authorizeLmsUserCourses({
      db: {} as SqlDatabase,
      connection,
      provider: createProvider("sakai", verifyCourseAccess),
      userId: "usr_123",
      courseIds: ["course-101"],
    });

    expect(result).toEqual({ status: "authorized" });
    expect(mockedFindTenantLmsUserIdentity).not.toHaveBeenCalled();
    expect(verifyCourseAccess).toHaveBeenCalledWith({
      accessScope: { kind: "connection" },
      courseIds: ["course-101"],
    });
  });

  it("requires a linked provider identity for Canvas course access", async () => {
    mockedFindTenantLmsUserIdentity.mockResolvedValue(null);
    const verifyCourseAccess = vi.fn();

    const result = await authorizeLmsUserCourses({
      db: {} as SqlDatabase,
      connection: canvasConnection,
      provider: createProvider("canvas", verifyCourseAccess),
      userId: "usr_123",
      courseIds: ["course-101"],
    });

    expect(result).toEqual({
      status: "identity_unlinked",
      error: "Open CredTrail from Canvas once to link your account before choosing courses.",
    });
    expect(verifyCourseAccess).not.toHaveBeenCalled();
  });

  it("checks Canvas courses with the instructor's linked provider identity", async () => {
    mockedFindTenantLmsUserIdentity.mockResolvedValue(identity);
    const verifyCourseAccess = vi.fn().mockResolvedValue({
      authorizedCourses: [],
      unauthorizedCourseIds: ["course-202"],
    });

    const result = await authorizeLmsUserCourses({
      db: {} as SqlDatabase,
      connection: canvasConnection,
      provider: createProvider("canvas", verifyCourseAccess),
      userId: "usr_123",
      courseIds: ["course-101", "course-202"],
    });

    expect(verifyCourseAccess).toHaveBeenCalledWith({
      accessScope: { kind: "provider_user", providerUserId: "instructor-123" },
      courseIds: ["course-101", "course-202"],
    });
    expect(result).toEqual({
      status: "course_unauthorized",
      courseId: "course-202",
      error: "You do not have instructor access to course course-202 in Institution Canvas.",
    });
  });

  it("returns exact authorized course records to version-scoped LMS readers", async () => {
    mockedFindTenantLmsUserIdentity.mockResolvedValue(identity);
    const course = {
      courseId: "course-101",
      title: "Course 101",
      courseCode: null,
      workflowState: null,
      startsAt: null,
      endsAt: null,
    };
    const verifyCourseAccess = vi.fn().mockResolvedValue({
      authorizedCourses: [course],
      unauthorizedCourseIds: [],
    });

    const result = await authorizeLmsUserCoursesWithScope({
      db: {} as SqlDatabase,
      connection: canvasConnection,
      provider: createProvider("canvas", verifyCourseAccess),
      userId: "usr_123",
      courseIds: ["course-101"],
    });

    expect(result).toEqual({
      status: "authorized",
      courses: [course],
    });
  });
});
