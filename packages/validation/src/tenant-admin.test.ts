import { describe, expect, it } from "vitest";

import {
  parseCreateDedicatedDbProvisioningRequest,
  parseResolveDedicatedDbProvisioningRequest,
} from "./badge-rules.js";
import { parseTenantApiKeyListQuery, parseTenantAssertionListQuery } from "./list-queries.js";
import {
  parseTenantApiKeyPathParams,
  parseTenantAuthProviderPathParams,
  parseTenantDedicatedDbProvisioningRequestPathParams,
} from "./path-params.js";
import {
  parseTenantAssertionLedgerExportQuery,
  parseTenantExecutiveDashboardQuery,
  parseTenantReportingComparisonQuery,
  parseTenantReportingHierarchyQuery,
  parseTenantReportingTrendQuery,
} from "./reporting-queries.js";
import {
  parseAdminCanvasOAuthAuthorizeUrlRequest,
  parseAdminCanvasOAuthExchangeRequest,
  parseCreateTenantApiKeyRequest,
  parseRevokeTenantApiKeyRequest,
  parseTenantCanvasGradebookSnapshotQuery,
  parseTenantLmsConnectionCoursePathParams,
  parseTenantLmsConnectionCourseSearchQuery,
  parseTenantLmsConnectionGradebookItemPathParams,
  parseTenantLmsConnectionPathParams,
  parseUpsertTenantAuthPolicyRequest,
  parseUpsertTenantAuthProviderRequest,
  parseUpsertTenantCanvasGradebookIntegrationRequest,
  parseUpsertTenantLmsConnectionRequest,
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseCreateTenantMemberRequest,
  parseCreateTenantOrgUnitRequest,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseTransferBadgeTemplateOwnershipRequest,
  parseUpdateTenantMemberRoleRequest,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
} from "./tenant-admin.js";

describe("canvas gradebook integration parsers", () => {
  it("accepts valid Canvas integration payloads", () => {
    const request = parseUpsertTenantCanvasGradebookIntegrationRequest({
      apiBaseUrl: "https://canvas.example.edu",
      authorizationEndpoint: "https://canvas.example.edu/login/oauth2/auth",
      tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
      clientId: "canvas-client-id",
      clientSecret: "canvas-client-secret",
      scope: "url:GET|/api/v1/courses",
    });

    expect(request.apiBaseUrl).toBe("https://canvas.example.edu");
    expect(request.clientId).toBe("canvas-client-id");
  });

  it("accepts valid OAuth authorize/exchange payloads and snapshot query", () => {
    const authorize = parseAdminCanvasOAuthAuthorizeUrlRequest({
      redirectUri: "https://credtrail.example.edu/callback",
    });
    const exchange = parseAdminCanvasOAuthExchangeRequest({
      code: "oauth-code-123",
      state: "abcdefghijklmnopqrstuvwxyz123456",
      redirectUri: "https://credtrail.example.edu/callback",
    });
    const snapshotQuery = parseTenantCanvasGradebookSnapshotQuery({
      courseId: "course_123",
      learnerId: "learner_456",
      assignmentId: "assignment_789",
    });

    expect(authorize.redirectUri).toBe("https://credtrail.example.edu/callback");
    expect(exchange.code).toBe("oauth-code-123");
    expect(snapshotQuery.assignmentId).toBe("assignment_789");
  });

  it("rejects invalid Canvas integration URLs", () => {
    expect(() => {
      parseUpsertTenantCanvasGradebookIntegrationRequest({
        apiBaseUrl: "not-a-url",
        authorizationEndpoint: "https://canvas.example.edu/login/oauth2/auth",
        tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
        clientId: "canvas-client-id",
        clientSecret: "canvas-client-secret",
      });
    }).toThrow(/./);
  });
});

describe("tenant LMS connection parsers", () => {
  it("accepts tenant LMS connection payloads and lookup params", () => {
    const request = parseUpsertTenantLmsConnectionRequest({
      displayName: "TrySakai",
      providerKind: "sakai",
      apiBaseUrl: "https://trysakai.example.edu",
      accessToken: "sakai-session",
      ltiIssuer: "https://trysakai.example.edu",
      ltiClientId: "client-123",
      ltiDeploymentId: "deployment-123",
    });
    const connectionParams = parseTenantLmsConnectionPathParams({
      tenantId: "tenant_123",
      connectionId: "lms_123",
    });
    const courseParams = parseTenantLmsConnectionCoursePathParams({
      tenantId: "tenant_123",
      connectionId: "lms_123",
      courseId: "course_101",
    });
    const gradebookItemParams = parseTenantLmsConnectionGradebookItemPathParams({
      tenantId: "tenant_123",
      connectionId: "lms_123",
      courseId: "course_101",
      assignmentId: "assignment_1",
    });
    const searchQuery = parseTenantLmsConnectionCourseSearchQuery({
      q: "biology",
    });

    expect(request.providerKind).toBe("sakai");
    expect(request.ltiDeploymentId).toBe("deployment-123");
    expect(connectionParams.connectionId).toBe("lms_123");
    expect(courseParams.courseId).toBe("course_101");
    expect(gradebookItemParams.assignmentId).toBe("assignment_1");
    expect(searchQuery.q).toBe("biology");
  });

  it("rejects unsupported LMS connection providers", () => {
    expect(() => {
      parseUpsertTenantLmsConnectionRequest({
        displayName: "Moodle",
        providerKind: "moodle",
        apiBaseUrl: "https://moodle.example.edu",
      });
    }).toThrow(/./);
  });
});

describe("enterprise governance request parsers", () => {
  it("parses tenant API key path params and list query", () => {
    const pathParams = parseTenantApiKeyPathParams({
      tenantId: "tenant_123",
      apiKeyId: "tak_123",
    });
    const defaultQuery = parseTenantApiKeyListQuery({});
    const explicitQuery = parseTenantApiKeyListQuery({
      includeRevoked: "true",
    });

    expect(pathParams.apiKeyId).toBe("tak_123");
    expect(defaultQuery.includeRevoked).toBe(false);
    expect(explicitQuery.includeRevoked).toBe(true);
  });

  it("parses tenant assertion list query filters and bounds", () => {
    const defaultQuery = parseTenantAssertionListQuery({});
    const filteredQuery = parseTenantAssertionListQuery({
      badgeTemplateId: "badge_template_001",
      recipientQuery: "csev@umich.edu",
      state: "revoked",
      limit: "125",
    });

    expect(defaultQuery.badgeTemplateId).toBeUndefined();
    expect(defaultQuery.recipientQuery).toBeUndefined();
    expect(defaultQuery.state).toBeUndefined();
    expect(defaultQuery.limit).toBeUndefined();
    expect(filteredQuery.badgeTemplateId).toBe("badge_template_001");
    expect(filteredQuery.recipientQuery).toBe("csev@umich.edu");
    expect(filteredQuery.state).toBe("revoked");
    expect(filteredQuery.limit).toBe(125);
  });

  it("rejects invalid tenant assertion list query values", () => {
    expect(() => {
      parseTenantAssertionListQuery({
        state: "paused",
      });
    }).toThrow(/./);

    expect(() => {
      parseTenantAssertionListQuery({
        limit: "0",
      });
    }).toThrow(/./);
  });

  it("parses tenant assertion ledger export filters and issued date bounds", () => {
    const query = parseTenantAssertionLedgerExportQuery({
      issuedFrom: "2026-03-01",
      issuedTo: "2026-03-31",
      badgeTemplateId: "badge_template_science",
      orgUnitId: "org_program_microbiology",
      state: "suspended",
      recipientQuery: " learner.one@example.edu ",
    });

    expect(query).toEqual({
      issuedFrom: "2026-03-01",
      issuedTo: "2026-03-31",
      badgeTemplateId: "badge_template_science",
      orgUnitId: "org_program_microbiology",
      state: "suspended",
      recipientQuery: "learner.one@example.edu",
    });
  });

  it("rejects invalid tenant assertion ledger export query values", () => {
    expect(() => {
      parseTenantAssertionLedgerExportQuery({
        issuedFrom: "2026-03-31",
        issuedTo: "2026-03-01",
      });
    }).toThrow(/./);

    expect(() => {
      parseTenantAssertionLedgerExportQuery({
        state: "pending_review",
      });
    }).toThrow(/./);
  });

  it("parses reporting trend and comparison queries with lifecycle-state filters", () => {
    expect(
      parseTenantReportingTrendQuery({
        from: "2026-03-01",
        to: "2026-03-31",
        badgeTemplateId: "badge_template_science",
        orgUnitId: "org_program_microbiology",
        state: "expired",
        bucket: "day",
      }),
    ).toEqual({
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: "badge_template_science",
      orgUnitId: "org_program_microbiology",
      state: "expired",
      bucket: "day",
    });

    expect(
      parseTenantReportingComparisonQuery({
        from: "2026-03-01",
        to: "2026-03-31",
        badgeTemplateId: "badge_template_science",
        orgUnitId: "org_program_microbiology",
        state: "pending_review",
        groupBy: "orgUnit",
      }),
    ).toEqual({
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: "badge_template_science",
      orgUnitId: "org_program_microbiology",
      state: "pending_review",
      groupBy: "orgUnit",
    });
  });

  it("parses hierarchy queries with full page-filter parity", () => {
    expect(
      parseTenantReportingHierarchyQuery({
        from: "2026-03-01",
        to: "2026-03-31",
        badgeTemplateId: "badge_template_science",
        orgUnitId: "org_program_microbiology",
        state: "active",
        focusOrgUnitId: "org_college_science",
        level: "department",
      }),
    ).toEqual({
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: "badge_template_science",
      orgUnitId: "org_program_microbiology",
      state: "active",
      focusOrgUnitId: "org_college_science",
      level: "department",
    });

    expect(() => {
      parseTenantReportingTrendQuery({
        from: "2026-03-31",
        to: "2026-03-01",
        state: "paused",
      });
    }).toThrow(/./);
  });

  it("parses executive dashboard queries with reporting-filter parity and smart-default hints", () => {
    expect(
      parseTenantExecutiveDashboardQuery({
        window: "last-30-days",
        audience: "college",
        badgeTemplateId: "badge_template_science",
        orgUnitId: "org_program_microbiology",
        state: "active",
        focusOrgUnitId: "org_college_science",
        comparisonLevel: "department",
      }),
    ).toEqual({
      window: "last-30-days",
      audience: "college",
      badgeTemplateId: "badge_template_science",
      orgUnitId: "org_program_microbiology",
      state: "active",
      focusOrgUnitId: "org_college_science",
      comparisonLevel: "department",
    });

    expect(() => {
      parseTenantExecutiveDashboardQuery({
        window: "last-quarter",
        audience: "campus",
      });
    }).toThrow(/./);
  });

  it("parses tenant API key create and revoke payloads", () => {
    const createPayload = parseCreateTenantApiKeyRequest({
      label: "Integration key",
      scopes: ["queue.issue", "queue.revoke"],
      expiresAt: "2026-03-15T00:00:00.000Z",
    });
    const revokePayload = parseRevokeTenantApiKeyRequest({
      revokedAt: "2026-03-16T00:00:00.000Z",
    });

    expect(createPayload.label).toBe("Integration key");
    expect(createPayload.scopes).toEqual(["queue.issue", "queue.revoke"]);
    expect(revokePayload.revokedAt).toBe("2026-03-16T00:00:00.000Z");
  });

  it("parses tenant auth policy and provider payloads", () => {
    const providerPathParams = parseTenantAuthProviderPathParams({
      tenantId: "tenant_123",
      providerId: "tap_oidc",
    });
    const policyPayload = parseUpsertTenantAuthPolicyRequest({
      loginMode: "sso_required",
      breakGlassEnabled: true,
      localMfaRequired: true,
      defaultProviderId: "tap_oidc",
    });
    const providerPayload = parseUpsertTenantAuthProviderRequest({
      protocol: "oidc",
      label: "Campus OIDC",
      enabled: true,
      isDefault: true,
      configJson:
        '{"issuer":"https://idp.example.edu","clientId":"credtrail","clientSecret":"secret"}',
    });

    expect(providerPathParams.providerId).toBe("tap_oidc");
    expect(policyPayload.loginMode).toBe("sso_required");
    expect(providerPayload.protocol).toBe("oidc");
    expect(providerPayload.label).toBe("Campus OIDC");
  });

  it("rejects malformed tenant auth provider configuration payloads", () => {
    expect(() => {
      parseUpsertTenantAuthProviderRequest({
        protocol: "oidc",
        label: "Campus OIDC",
        configJson: "not-json",
      });
    }).toThrow(/./);
  });

  it("parses dedicated DB provisioning create/resolve payloads and path params", () => {
    const pathParams = parseTenantDedicatedDbProvisioningRequestPathParams({
      tenantId: "tenant_123",
      requestId: "dpr_123",
    });
    const createPayload = parseCreateDedicatedDbProvisioningRequest({
      targetRegion: "us-east-1",
      notes: "Enterprise migration window approved",
    });
    const resolvePayload = parseResolveDedicatedDbProvisioningRequest({
      status: "provisioned",
      dedicatedDatabaseUrl: "postgres://dedicated.example/db",
      notes: "Provisioned and smoke tested",
      resolvedAt: "2026-03-16T00:00:00.000Z",
    });

    expect(pathParams.requestId).toBe("dpr_123");
    expect(createPayload.targetRegion).toBe("us-east-1");
    expect(resolvePayload.status).toBe("provisioned");
  });
});

describe("tenant membership and delegation parsers", () => {
  it("parses create tenant org unit request payload", () => {
    const payload = parseCreateTenantOrgUnitRequest({
      unitType: "department",
      slug: "school-of-information",
      displayName: "School of Information",
      parentOrgUnitId: "tenant_123:org:college-engineering",
    });

    expect(payload.unitType).toBe("department");
    expect(payload.slug).toBe("school-of-information");
  });

  it("parses org-unit scope upsert payloads", () => {
    const payload = parseUpsertTenantMembershipOrgUnitScopeRequest({
      role: "issuer",
    });

    expect(payload.role).toBe("issuer");

    expect(() => {
      parseUpsertTenantMembershipOrgUnitScopeRequest({
        role: "owner",
      });
    }).toThrow(/./);
  });

  it("parses tenant member create and role update payloads", () => {
    const createPayload = parseCreateTenantMemberRequest({
      email: " Colleague@Example.edu ",
      role: "admin",
      sendInvite: true,
    });
    const rolePayload = parseUpdateTenantMemberRoleRequest({
      role: "viewer",
    });

    expect(createPayload).toEqual({
      email: "Colleague@Example.edu",
      role: "admin",
      sendInvite: true,
    });
    expect(rolePayload.role).toBe("viewer");
  });

  it("rejects invalid tenant member payloads", () => {
    expect(() => {
      parseCreateTenantMemberRequest({
        email: "not-an-email",
        role: "admin",
      });
    }).toThrow(/./);

    expect(() => {
      parseCreateTenantMemberRequest({
        email: "colleague@example.edu",
        role: "superadmin",
      });
    }).toThrow(/./);

    expect(() => {
      parseUpdateTenantMemberRoleRequest({
        role: "superadmin",
      });
    }).toThrow(/./);
  });

  it("parses delegated authority grant creation payloads", () => {
    const payload = parseCreateDelegatedIssuingAuthorityGrantRequest({
      orgUnitId: "tenant_123:org:department-math",
      badgeTemplateIds: ["badge_template_001", "badge_template_002"],
      allowedActions: ["issue_badge", "revoke_badge"],
      startsAt: "2026-02-13T12:00:00.000Z",
      endsAt: "2026-03-13T12:00:00.000Z",
      reason: "Spring term delegation",
    });

    expect(payload.allowedActions).toEqual(["issue_badge", "revoke_badge"]);
    expect(payload.badgeTemplateIds).toEqual(["badge_template_001", "badge_template_002"]);

    expect(() => {
      parseCreateDelegatedIssuingAuthorityGrantRequest({
        orgUnitId: "tenant_123:org:department-math",
        allowedActions: ["issue_badge", "issue_badge"],
        endsAt: "2026-03-13T12:00:00.000Z",
      });
    }).toThrow(/./);

    expect(() => {
      parseCreateDelegatedIssuingAuthorityGrantRequest({
        orgUnitId: "tenant_123:org:department-math",
        allowedActions: ["issue_badge"],
        startsAt: "2026-03-13T12:00:00.000Z",
        endsAt: "2026-02-13T12:00:00.000Z",
      });
    }).toThrow(/./);
  });

  it("parses delegated authority grant revoke payloads", () => {
    const payload = parseRevokeDelegatedIssuingAuthorityGrantRequest({
      reason: "Policy update",
      revokedAt: "2026-02-20T09:30:00.000Z",
    });

    expect(payload.reason).toBe("Policy update");
    expect(payload.revokedAt).toBe("2026-02-20T09:30:00.000Z");
  });

  it("parses ownership transfer payloads and rejects initial_assignment reason", () => {
    const payload = parseTransferBadgeTemplateOwnershipRequest({
      toOrgUnitId: "tenant_123:org:department-math",
      reasonCode: "administrative_transfer",
      reason: "Moved under Math governance",
      governanceMetadata: {
        governancePolicyVersion: "2026-02-13",
      },
    });

    expect(payload.reasonCode).toBe("administrative_transfer");

    expect(() => {
      parseTransferBadgeTemplateOwnershipRequest({
        toOrgUnitId: "tenant_123:org:department-math",
        reasonCode: "initial_assignment",
      });
    }).toThrow(/./);
  });
});
