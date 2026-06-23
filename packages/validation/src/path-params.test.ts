import { describe, expect, it } from "vitest";

import {
  parseCredentialPathParams,
  parseTenantMemberPathParams,
  parseTenantUserDelegatedGrantPathParams,
  parseTenantUserOrgUnitPathParams,
  parseTenantUserPathParams,
} from "./path-params.js";

describe("path param parsers", () => {
  it("parses path params for public credential verification route", () => {
    const params = parseCredentialPathParams({
      credentialId: "tenant_123:assertion_456",
    });

    expect(params.credentialId).toBe("tenant_123:assertion_456");
  });

  it("parses tenant/user path params for membership role routes", () => {
    const params = parseTenantUserPathParams({
      tenantId: "tenant_123",
      userId: "usr_456",
    });

    expect(params.tenantId).toBe("tenant_123");
    expect(params.userId).toBe("usr_456");
  });

  it("parses tenant member path params for member routes", () => {
    const params = parseTenantMemberPathParams({
      tenantId: "tenant_123",
      userId: "usr_456",
    });

    expect(params.tenantId).toBe("tenant_123");
    expect(params.userId).toBe("usr_456");

    expect(() => {
      parseTenantMemberPathParams({
        tenantId: "tenant_123",
      });
    }).toThrow(/./);
  });

  it("parses tenant/user/org-unit path params for scoped membership routes", () => {
    const params = parseTenantUserOrgUnitPathParams({
      tenantId: "tenant_123",
      userId: "usr_456",
      orgUnitId: "tenant_123:org:department-math",
    });

    expect(params.tenantId).toBe("tenant_123");
    expect(params.userId).toBe("usr_456");
    expect(params.orgUnitId).toBe("tenant_123:org:department-math");
  });

  it("parses tenant/user/grant path params for delegated authority routes", () => {
    const params = parseTenantUserDelegatedGrantPathParams({
      tenantId: "tenant_123",
      userId: "usr_456",
      grantId: "dag_789",
    });

    expect(params.tenantId).toBe("tenant_123");
    expect(params.userId).toBe("usr_456");
    expect(params.grantId).toBe("dag_789");
  });
});
