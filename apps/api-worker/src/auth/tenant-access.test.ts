import { beforeEach, describe, expect, it, vi } from "vitest";
import * as tenantAccessModule from "./tenant-access";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findTenantMembership: vi.fn(),
    listTenantMembershipOrgUnitScopes: vi.fn(),
  };
});

import {
  findTenantMembership,
  listTenantMembershipOrgUnitScopes,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRecord,
  type TenantMembershipRecord,
} from "@credtrail/db";
import { ADMIN_ROLES, requirePrincipalTenantRole, type TenantAccessContext } from "./tenant-access";
import type { AuthenticatedPrincipal, RequestedTenantContext } from "./auth-context";

type FakeBindings = Record<string, never>;

type FakeContext = TenantAccessContext<FakeBindings>;

const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedListTenantMembershipOrgUnitScopes = vi.mocked(listTenantMembershipOrgUnitScopes);

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createContext = (): FakeContext => {
  return {
    env: {},
    req: {
      header: vi.fn(),
    },
    json: (payload: unknown, status = 200) => {
      return Response.json(payload, {
        status,
      });
    },
  };
};

const samplePrincipal = (): AuthenticatedPrincipal => {
  return {
    userId: "usr_123",
    authSessionId: "ses_123",
    authMethod: "better_auth",
    expiresAt: "2026-02-18T22:00:00.000Z",
  };
};

const requestedTenant = (overrides?: Partial<RequestedTenantContext>): RequestedTenantContext => {
  return {
    tenantId: "tenant_requested",
    ...overrides,
  };
};

const membershipRecord = (overrides?: Partial<TenantMembershipRecord>): TenantMembershipRecord => {
  return {
    tenantId: "tenant_requested",
    userId: "usr_123",
    role: "admin",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
    ...overrides,
  };
};

const scopeRecord = (
  overrides?: Partial<TenantMembershipOrgUnitScopeRecord>,
): TenantMembershipOrgUnitScopeRecord => {
  return {
    tenantId: "tenant_requested",
    userId: "usr_123",
    orgUnitId: "org_college_science",
    role: "issuer",
    createdByUserId: null,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedFindTenantMembership.mockReset();
  mockedListTenantMembershipOrgUnitScopes.mockReset();
});

describe("requirePrincipalTenantRole", () => {
  it("returns 401 when no authenticated principal is available", async () => {
    const response = await requirePrincipalTenantRole({
      context: createContext(),
      principal: null,
      requestedTenant: requestedTenant(),
      allowedRoles: ADMIN_ROLES,
      resolveDatabase: () => fakeDb,
    });

    expect(response).toBeInstanceOf(Response);
    expect((response as Response).status).toBe(401);
    await expect((response as Response).json()).resolves.toEqual({
      error: "Not authenticated",
    });
  });

  it("authorizes using principal user id plus requested tenant membership lookup", async () => {
    mockedFindTenantMembership.mockResolvedValue(membershipRecord());

    const result = await requirePrincipalTenantRole({
      context: createContext(),
      principal: samplePrincipal(),
      requestedTenant: requestedTenant({
        tenantId: "tenant_path",
      }),
      allowedRoles: ADMIN_ROLES,
      resolveDatabase: () => fakeDb,
    });

    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_path", "usr_123");
    expect(result).toEqual({
      principal: samplePrincipal(),
      requestedTenant: requestedTenant({
        tenantId: "tenant_path",
      }),
      membershipRole: "admin",
    });
  });

  it("returns 403 when the requested tenant membership role is insufficient", async () => {
    mockedFindTenantMembership.mockResolvedValue(
      membershipRecord({
        role: "viewer",
      }),
    );

    const response = await requirePrincipalTenantRole({
      context: createContext(),
      principal: samplePrincipal(),
      requestedTenant: requestedTenant(),
      allowedRoles: ADMIN_ROLES,
      resolveDatabase: () => fakeDb,
    });

    expect(response).toBeInstanceOf(Response);
    expect((response as Response).status).toBe(403);
    await expect((response as Response).json()).resolves.toEqual({
      error: "Insufficient role for requested action",
    });
  });
});

describe("resolveTenantReportingAccess", () => {
  const resolveTenantReportingAccess = (
    tenantAccessModule as {
      resolveTenantReportingAccess?: (input: {
        db: SqlDatabase;
        tenantId: string;
        userId: string;
        membershipRole: "owner" | "admin" | "issuer" | "approver" | "viewer";
      }) => Promise<unknown>;
    }
  ).resolveTenantReportingAccess;

  it("keeps owner and admin reporting visibility tenant-wide", async () => {
    expect(resolveTenantReportingAccess).toBeTypeOf("function");
    mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([
      scopeRecord({
        role: "issuer",
      }),
    ]);

    await expect(
      resolveTenantReportingAccess?.({
        db: fakeDb,
        tenantId: "tenant_requested",
        userId: "usr_123",
        membershipRole: "admin",
      }),
    ).resolves.toEqual({
      tenantId: "tenant_requested",
      membershipRole: "admin",
      visibility: "tenant",
      scopedOrgUnitIds: [],
    });
  });

  it("resolves scoped issuer reporting access to subtree roots when reporting scopes exist", async () => {
    expect(resolveTenantReportingAccess).toBeTypeOf("function");
    mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([
      scopeRecord({
        orgUnitId: "org_college_science",
        role: "issuer",
      }),
      scopeRecord({
        orgUnitId: "org_department_biology",
        role: "viewer",
      }),
      scopeRecord({
        orgUnitId: "org_department_biology",
        role: "admin",
      }),
    ]);

    await expect(
      resolveTenantReportingAccess?.({
        db: fakeDb,
        tenantId: "tenant_requested",
        userId: "usr_123",
        membershipRole: "issuer",
      }),
    ).resolves.toEqual({
      tenantId: "tenant_requested",
      membershipRole: "issuer",
      visibility: "scoped",
      scopedOrgUnitIds: ["org_college_science", "org_department_biology"],
    });
  });

  it("preserves legacy tenant-wide reporting access for issuers without scope rows", async () => {
    expect(resolveTenantReportingAccess).toBeTypeOf("function");
    mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([]);

    await expect(
      resolveTenantReportingAccess?.({
        db: fakeDb,
        tenantId: "tenant_requested",
        userId: "usr_123",
        membershipRole: "issuer",
      }),
    ).resolves.toEqual({
      tenantId: "tenant_requested",
      membershipRole: "issuer",
      visibility: "tenant",
      scopedOrgUnitIds: [],
    });
  });
});

describe("resolveTenantExecutiveAccess", () => {
  const resolveTenantExecutiveAccess = (
    tenantAccessModule as {
      resolveTenantExecutiveAccess?: (input: {
        db: SqlDatabase;
        tenantId: string;
        userId: string;
        membershipRole: "owner" | "admin" | "issuer" | "approver" | "viewer";
      }) => Promise<unknown>;
    }
  ).resolveTenantExecutiveAccess;

  it("keeps owner and admin executive visibility tenant-wide", async () => {
    expect(resolveTenantExecutiveAccess).toBeTypeOf("function");

    await expect(
      resolveTenantExecutiveAccess?.({
        db: fakeDb,
        tenantId: "tenant_requested",
        userId: "usr_123",
        membershipRole: "owner",
      }),
    ).resolves.toEqual({
      tenantId: "tenant_requested",
      membershipRole: "owner",
      visibility: "tenant",
      scopedOrgUnitIds: [],
    });
  });

  it("resolves scoped executive access for narrower audiences from existing org scopes", async () => {
    expect(resolveTenantExecutiveAccess).toBeTypeOf("function");
    mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([
      scopeRecord({
        orgUnitId: "org_college_science",
        role: "viewer",
      }),
      scopeRecord({
        orgUnitId: "org_department_biology",
        role: "issuer",
      }),
    ]);

    await expect(
      resolveTenantExecutiveAccess?.({
        db: fakeDb,
        tenantId: "tenant_requested",
        userId: "usr_123",
        membershipRole: "viewer",
      }),
    ).resolves.toEqual({
      tenantId: "tenant_requested",
      membershipRole: "viewer",
      visibility: "scoped",
      scopedOrgUnitIds: ["org_college_science", "org_department_biology"],
    });
  });

  it("fails closed for viewers without executive scopes", async () => {
    expect(resolveTenantExecutiveAccess).toBeTypeOf("function");
    mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([]);

    await expect(
      resolveTenantExecutiveAccess?.({
        db: fakeDb,
        tenantId: "tenant_requested",
        userId: "usr_123",
        membershipRole: "viewer",
      }),
    ).resolves.toBeNull();
  });
});
