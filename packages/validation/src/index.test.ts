import { describe, expect, it } from "vitest";

import {
  parseCreateDedicatedDbProvisioningRequest,
  parseCreateTenantApiKeyRequest,
  parseRevokeTenantApiKeyRequest,
  parseTenantAuthProviderPathParams,
  parseResolveDedicatedDbProvisioningRequest,
  parseTenantApiKeyListQuery,
  parseTenantAssertionListQuery,
  parseTenantAssertionLedgerExportQuery,
  parseTenantApiKeyPathParams,
  parseUpsertTenantAuthPolicyRequest,
  parseUpsertTenantAuthProviderRequest,
  parseTenantDedicatedDbProvisioningRequestPathParams,
  parseUpsertTenantSsoSamlConfigurationRequest,
  parseUpsertTenantCanvasGradebookIntegrationRequest,
  parseAdminCanvasOAuthAuthorizeUrlRequest,
  parseAdminLearnerRecordReviewQuery,
  parseAdminCanvasOAuthExchangeRequest,
  parseTenantCanvasGradebookSnapshotQuery,
  parseTenantLmsConnectionCoursePathParams,
  parseTenantLmsConnectionCourseSearchQuery,
  parseTenantLmsConnectionGradebookItemPathParams,
  parseTenantLmsConnectionPathParams,
  parseUpsertTenantLmsConnectionRequest,
  parseCreateBadgeIssuanceRuleRequest,
  parseUpdateBadgeIssuanceRuleDraftRequest,
  parseCreateBadgeIssuanceRuleValueListRequest,
  parseCreateBadgeIssuanceRuleVersionRequest,
  parseBadgeIssuanceRuleReviewQueueQuery,
  parseDecideBadgeIssuanceRuleVersionRequest,
  parseEvaluateBadgeIssuanceRuleRequest,
  parsePreviewEvaluateBadgeIssuanceRuleRequest,
  parsePreviewSimulateBadgeIssuanceRuleRequest,
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleAuditLogQuery,
  parseBadgeIssuanceRuleVersionDiffQuery,
  parseBadgeIssuanceRuleVersionPathParams,
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseCreateTenantMemberRequest,
  parseBadgeTemplateListQuery,
  parseTenantOrgUnitListQuery,
  parseBadgeTemplateImageGenerationPathParams,
  parseBadgeTemplateImageRevisionPathParams,
  parseBadgeTemplatePathParams,
  parseCredentialPathParams,
  parseCreateBadgeTemplateRequest,
  parseGenerateBadgeTemplateImageRequest,
  parseTrustEdCredentialMetadata,
  parseLearnerRecordImportBatchDefaults,
  parseLearnerRecordImportBatchPathParams,
  parseLearnerRecordImportProgressQuery,
  parseLearnerRecordImportRetryRequest,
  parseLearnerRecordImportRow,
  parseLearnerRecordImportUploadQuery,
  parseCreateLearnerRecordEntryRequest,
  parseCreateTenantOrgUnitRequest,
  parseLearnerRecordExportPathParams,
  parseLearnerRecordExportQuery,
  parseLearnerRecordEntryListQuery,
  parseLearnerRecordEntryPathParams,
  parseLearnerRecordStandardsMappingQuery,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
  parseIssueBadgeRequest,
  parseManualIssueBadgeRequest,
  parseProgrammaticIssueBadgeRequest,
  parseProgrammaticRevokeBadgeRequest,
  parseLearnerIdentityLinkRequest,
  parseLearnerIdentityLinkVerifyRequest,
  parseLearnerDidSettingsRequest,
  parsePresentationCreateRequest,
  parsePresentationVerifyRequest,
  parseAssertionLifecycleTransitionRequest,
  parseAssertionPathParams,
  isValidationParseError,
  parseMagicLinkRequest,
  parseMagicLinkVerifyRequest,
  parseMigrationBatchPathParams,
  parseMigrationBatchRetryRequest,
  parseMigrationProgressQuery,
  parseMigrationBatchUploadQuery,
  parseOb2ImportConversionRequest,
  parseProcessQueueRequest,
  parseQueueJob,
  parseRevokeBadgeRequest,
  parseSignCredentialRequest,
  parseTenantUserPathParams,
  parseTenantMemberPathParams,
  parseTenantUserOrgUnitPathParams,
  parseTenantUserDelegatedGrantPathParams,
  parseUpdateTenantMemberRoleRequest,
  parseDelegatedIssuingAuthorityGrantListQuery,
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseTenantSigningRegistry,
  parseUpdateBadgeTemplateRequest,
  parseTransferBadgeTemplateOwnershipRequest,
  parseTenantReportingComparisonQuery,
  parseTenantExecutiveDashboardQuery,
  parsePatchLearnerRecordEntryRequest,
  parseTenantReportingHierarchyQuery,
  parseTenantReportingTrendQuery,
} from "./index";
import { completeTrustEdCredentialMetadataInput } from "./testing";

describe("parseQueueJob", () => {
  it("accepts a valid issue_badge queue payload", () => {
    const job = parseQueueJob({
      jobType: "issue_badge",
      tenantId: "tenant_123",
      payload: {
        assertionId: "assertion_456",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        requestedAt: "2026-02-10T15:00:00.000Z",
      },
      idempotencyKey: "idem_abc",
    });

    expect(job.jobType).toBe("issue_badge");
  });

  it("accepts issue_badge queue payload with recipient identifiers", () => {
    const job = parseQueueJob({
      jobType: "issue_badge",
      tenantId: "tenant_123",
      payload: {
        assertionId: "assertion_456",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        recipientIdentifiers: [
          {
            identifierType: "emailAddress",
            identifier: "learner@example.edu",
          },
          {
            identifierType: "studentId",
            identifier: "student-123",
          },
        ],
        recipientDisplayName: "Learner Example",
        issuerImageUri: "https://issuer.example.edu/logo.svg",
        requestedAt: "2026-02-10T15:00:00.000Z",
      },
      idempotencyKey: "idem_abc",
    });

    expect(job.jobType).toBe("issue_badge");

    if (job.jobType !== "issue_badge") {
      throw new Error("Expected issue_badge queue payload");
    }

    expect(job.payload.recipientIdentifiers).toHaveLength(2);
    expect(job.payload.recipientDisplayName).toBe("Learner Example");
    expect(job.payload.issuerImageUri).toBe("https://issuer.example.edu/logo.svg");
  });

  it("accepts a valid revoke_badge queue payload", () => {
    const job = parseQueueJob({
      jobType: "revoke_badge",
      tenantId: "tenant_123",
      payload: {
        revocationId: "revocation_456",
        assertionId: "assertion_456",
        reason: "Issued in error",
        requestedAt: "2026-02-10T15:00:00.000Z",
      },
      idempotencyKey: "idem_def",
    });

    expect(job.jobType).toBe("revoke_badge");
  });

  it("accepts a valid generate_badge_template_image queue payload", () => {
    const job = parseQueueJob({
      jobType: "generate_badge_template_image",
      tenantId: "tenant_123",
      payload: {
        generationId: "btig_123",
        badgeTemplateId: "badge_template_001",
        promptText: "Create a square badge image.",
        stylePreset: "institutional",
        requestedAt: "2026-02-10T15:00:00.000Z",
        requestedByUserId: "usr_admin",
      },
      idempotencyKey: "btig_123",
    });

    expect(job.jobType).toBe("generate_badge_template_image");
  });

  it("rejects malformed queue jobs", () => {
    expect(() => {
      parseQueueJob({
        tenantId: "tenant_123",
      });
    }).toThrowError();
  });
});

describe("issue/revoke request parsers", () => {
  it("accepts a valid issue request", () => {
    const request = parseIssueBadgeRequest({
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
    });

    expect(request.tenantId).toBe("tenant_123");
  });

  it("accepts a valid issue request with recipient identifiers", () => {
    const request = parseIssueBadgeRequest({
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      recipientIdentifiers: [
        {
          identifierType: "emailAddress",
          identifier: "learner@example.edu",
        },
        {
          identifierType: "sourcedId",
          identifier: "canvas-user-44",
        },
      ],
      recipientDisplayName: "Learner Example",
      issuerImageUri: "https://issuer.example.edu/logo.svg",
    });

    expect(request.recipientIdentifiers).toHaveLength(2);
    expect(request.recipientDisplayName).toBe("Learner Example");
    expect(request.issuerImageUri).toBe("https://issuer.example.edu/logo.svg");
  });

  it("rejects invalid recipient identifier entries", () => {
    expect(() => {
      parseIssueBadgeRequest({
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        recipientIdentifiers: [
          {
            identifierType: "emailAddress",
            identifier: "",
          },
        ],
      });
    }).toThrowError();
  });

  it("accepts a valid revoke request", () => {
    const request = parseRevokeBadgeRequest({
      tenantId: "tenant_123",
      assertionId: "assertion_456",
      reason: "Revoked by issuer",
    });

    expect(request.assertionId).toBe("assertion_456");
  });

  it("rejects revoke requests without a reason", () => {
    expect(() => {
      parseRevokeBadgeRequest({
        tenantId: "tenant_123",
        assertionId: "assertion_456",
        reason: "",
      });
    }).toThrowError();
  });

  it("accepts a valid manual issue request", () => {
    const request = parseManualIssueBadgeRequest({
      badgeTemplateId: "badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
    });

    expect(request.badgeTemplateId).toBe("badge_template_001");
  });

  it("requires idempotencyKey for programmatic issue requests", () => {
    expect(() => {
      parseProgrammaticIssueBadgeRequest({
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
      });
    }).toThrowError();
  });

  it("accepts a valid programmatic issue request with idempotencyKey", () => {
    const request = parseProgrammaticIssueBadgeRequest({
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      idempotencyKey: "idem_issue_123",
    });

    expect(request.idempotencyKey).toBe("idem_issue_123");
  });

  it("requires idempotencyKey for programmatic revoke requests", () => {
    expect(() => {
      parseProgrammaticRevokeBadgeRequest({
        tenantId: "tenant_123",
        assertionId: "assertion_456",
        reason: "Revoked by issuer",
      });
    }).toThrowError();
  });

  it("accepts a valid programmatic revoke request with idempotencyKey", () => {
    const request = parseProgrammaticRevokeBadgeRequest({
      tenantId: "tenant_123",
      assertionId: "assertion_456",
      reason: "Revoked by issuer",
      idempotencyKey: "idem_revoke_123",
    });

    expect(request.idempotencyKey).toBe("idem_revoke_123");
  });
});

describe("process queue request parser", () => {
  it("accepts an empty payload", () => {
    const request = parseProcessQueueRequest({});
    expect(request.limit).toBeUndefined();
  });

  it("accepts bounded queue processor settings", () => {
    const request = parseProcessQueueRequest({
      limit: 25,
      leaseSeconds: 30,
      retryDelaySeconds: 120,
    });

    expect(request.limit).toBe(25);
    expect(request.leaseSeconds).toBe(30);
    expect(request.retryDelaySeconds).toBe(120);
  });

  it("rejects invalid queue processor settings", () => {
    expect(() => {
      parseProcessQueueRequest({
        limit: 0,
      });
    }).toThrowError();
  });
});

describe("OB2 import conversion parser", () => {
  it("accepts OB2 assertion JSON payload", () => {
    const request = parseOb2ImportConversionRequest({
      ob2Assertion: {
        "@context": "https://w3id.org/openbadges/v2",
        type: "Assertion",
        recipient: {
          type: "email",
          identity: "learner@example.edu",
        },
        badge: {
          type: "BadgeClass",
          name: "Intro Badge",
        },
      },
    });

    expect(request.ob2Assertion?.type).toBe("Assertion");
  });

  it("accepts bakedBadgeImage payloads without assertion JSON", () => {
    const request = parseOb2ImportConversionRequest({
      bakedBadgeImage: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
    });

    expect(request.bakedBadgeImage).toContain("iVBOR");
  });

  it("rejects payloads without an assertion source", () => {
    expect(() => {
      parseOb2ImportConversionRequest({});
    }).toThrowError();
  });
});

describe("migration batch upload query parser", () => {
  it("defaults dryRun to true", () => {
    const query = parseMigrationBatchUploadQuery({});
    expect(query.dryRun).toBe(true);
  });

  it("parses explicit dryRun false", () => {
    const query = parseMigrationBatchUploadQuery({
      dryRun: "false",
    });
    expect(query.dryRun).toBe(false);
  });

  it("rejects invalid dryRun values", () => {
    expect(() => {
      parseMigrationBatchUploadQuery({
        dryRun: "nope",
      });
    }).toThrowError();
  });
});

describe("learner-record import parsers", () => {
  it("accepts a minimal learner-record import row with bounded batch defaults", () => {
    const row = parseLearnerRecordImportRow({
      learnerEmail: "learner@example.edu",
      title: "Clinical Placement Seminar",
      recordType: "course",
      issuedAt: "2026-03-26T12:00:00.000Z",
    });
    const defaults = parseLearnerRecordImportBatchDefaults({});

    expect(row.learnerEmail).toBe("learner@example.edu");
    expect(defaults.defaultTrustLevel).toBe("issuer_verified");
  });

  it("rejects supplemental artifacts that try to override trust to issuer verified", () => {
    expect(() => {
      parseLearnerRecordImportRow({
        learnerEmail: "learner@example.edu",
        title: "Portfolio Reflection",
        recordType: "supplemental_artifact",
        trustLevel: "issuer_verified",
        issuedAt: "2026-03-26T12:00:00.000Z",
      });
    }).toThrowError();
  });

  it("parses learner-record import upload, progress, retry, and batch path inputs", () => {
    const upload = parseLearnerRecordImportUploadQuery({
      dryRun: "false",
    });
    const progress = parseLearnerRecordImportProgressQuery({
      limit: "10",
    });
    const retry = parseLearnerRecordImportRetryRequest({
      rowNumbers: [2, 4, 6],
    });
    const pathParams = parseLearnerRecordImportBatchPathParams({
      tenantId: "tenant_123",
      batchId: "batch_123",
    });

    expect(upload.dryRun).toBe(false);
    expect(progress.limit).toBe(10);
    expect(retry.rowNumbers).toEqual([2, 4, 6]);
    expect(pathParams.batchId).toBe("batch_123");
  });

  it("accepts learner-record import queue jobs", () => {
    const job = parseQueueJob({
      jobType: "import_learner_record_batch",
      tenantId: "tenant_123",
      payload: {
        batchId: "batch_123",
        rowNumber: 1,
        fileName: "learner-records.csv",
        format: "csv",
        requestedAt: "2026-03-26T12:00:00.000Z",
        row: {
          learnerEmail: "learner@example.edu",
          learnerDisplayName: null,
          title: "Clinical Placement Seminar",
          recordType: "course",
          issuedAt: "2026-03-26T12:00:00.000Z",
          description: null,
          sourceRecordId: null,
          evidenceLinks: [],
          effectiveTrustLevel: "issuer_verified",
          effectiveIssuerName: "CredTrail University",
          smartContext: {
            orgUnitId: "tenant_123:org:department-health",
            badgeTemplateId: null,
            pathwayLabel: "Clinical readiness",
            inferredFrom: ["row", "org_unit"],
          },
        },
      },
      idempotencyKey: "idem_import_123",
    });

    expect(job.jobType).toBe("import_learner_record_batch");
  });
});

describe("migration progress parser", () => {
  it("defaults progress query values", () => {
    const query = parseMigrationProgressQuery({});
    expect(query.source).toBe("all");
    expect(query.limit).toBe(50);
  });

  it("parses source and limit filters", () => {
    const query = parseMigrationProgressQuery({
      source: "credly_export",
      limit: "25",
    });
    expect(query.source).toBe("credly_export");
    expect(query.limit).toBe(25);
  });

  it("parses parchment export source filters", () => {
    const query = parseMigrationProgressQuery({
      source: "parchment_export",
      limit: "10",
    });

    expect(query.source).toBe("parchment_export");
    expect(query.limit).toBe(10);
  });

  it("rejects invalid source filters", () => {
    expect(() => {
      parseMigrationProgressQuery({
        source: "legacy_csv",
      });
    }).toThrowError();
  });

  it("parses migration batch path params", () => {
    const params = parseMigrationBatchPathParams({
      tenantId: "tenant_123",
      batchId: "cc8f1dc6-ff06-4f4f-b915-c0de703ff5e0",
    });

    expect(params.batchId).toContain("cc8f");
  });

  it("parses retry payload row filters", () => {
    const request = parseMigrationBatchRetryRequest({
      source: "parchment_export",
      rowNumbers: [1, 2, 3],
    });

    expect(request.source).toBe("parchment_export");
    expect(request.rowNumbers).toEqual([1, 2, 3]);
  });
});

describe("magic link request parsers", () => {
  it("accepts a valid magic link request", () => {
    const request = parseMagicLinkRequest({
      tenantId: "tenant_123",
      email: "learner@example.edu",
      nextPath: "/auth/resolve",
    });

    expect(request.tenantId).toBe("tenant_123");
    expect(request.email).toBe("learner@example.edu");
    expect(request.nextPath).toBe("/auth/resolve");
  });

  it("accepts browser date-time preferences for magic link email formatting", () => {
    const request = parseMagicLinkRequest({
      tenantId: "tenant_123",
      email: "learner@example.edu",
      preferredLocale: "en-US",
      preferredTimeZone: "America/New_York",
    });

    expect(request.preferredLocale).toBe("en-US");
    expect(request.preferredTimeZone).toBe("America/New_York");
  });

  it("accepts email-only magic link requests for tenant discovery", () => {
    const request = parseMagicLinkRequest({
      email: "learner@example.edu",
    });

    expect(request.tenantId).toBeUndefined();
    expect(request.email).toBe("learner@example.edu");
  });

  it("rejects invalid email values", () => {
    expect(() => {
      parseMagicLinkRequest({
        tenantId: "tenant_123",
        email: "not-an-email",
      });
    }).toThrowError();
  });

  it("accepts a valid magic link verify payload", () => {
    const verify = parseMagicLinkVerifyRequest({
      token: "0123456789012345678901234567890123456789",
    });

    expect(verify.token.length).toBeGreaterThan(20);
  });
});

describe("learner identity link parsers", () => {
  it("accepts a valid learner identity link request", () => {
    const request = parseLearnerIdentityLinkRequest({
      email: "learner@gmail.com",
    });

    expect(request.email).toBe("learner@gmail.com");
  });

  it("accepts a valid learner identity link verify payload", () => {
    const request = parseLearnerIdentityLinkVerifyRequest({
      token: "0123456789012345678901234567890123456789",
    });

    expect(request.token.length).toBeGreaterThan(20);
  });

  it("rejects invalid learner identity link email values", () => {
    expect(() => {
      parseLearnerIdentityLinkRequest({
        email: "invalid",
      });
    }).toThrowError();
  });
});

describe("learner DID settings parser", () => {
  it("accepts supported DID methods and empty clear value", () => {
    const keyDid = parseLearnerDidSettingsRequest({
      did: "did:key:z6MkhY1pD8x7Jk9hN8YvKQxN5f3qU8d9sF4A2B3C4D5E6F7",
    });
    const webDid = parseLearnerDidSettingsRequest({ did: "did:web:wallet.example.edu:alice" });
    const ionDid = parseLearnerDidSettingsRequest({ did: "did:ion:EiAxyz123" });
    const clearDid = parseLearnerDidSettingsRequest({ did: "" });

    expect(keyDid.did).toContain("did:key:");
    expect(webDid.did).toContain("did:web:");
    expect(ionDid.did).toContain("did:ion:");
    expect(clearDid.did).toBe("");
  });

  it("rejects unsupported DID methods", () => {
    expect(() => {
      parseLearnerDidSettingsRequest({
        did: "did:example:123",
      });
    }).toThrowError();
  });
});

describe("presentation parser", () => {
  it("accepts a valid presentation create payload", () => {
    const request = parsePresentationCreateRequest({
      holderDid: "did:key:z6MknqT2qWnVYxR2s4cV8nH2uC6wYtQ5jT8kH7aX9mP2zR1",
      holderPrivateJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: "11qYAY7Y8A8kS0P3J-bwFTHlL8E8fQf6c3n2pP7Q9Q0",
        d: "nWGxne_9Wm7nP8aW8Q6BYfQhRj6iB-8Sn4Xc6D4J3vU",
      },
      credentialIds: ["tenant_123:assertion_456"],
    });

    expect(request.holderDid).toContain("did:key:");
    expect(request.credentialIds).toHaveLength(1);
  });

  it("rejects duplicate credential identifiers in create payload", () => {
    expect(() => {
      parsePresentationCreateRequest({
        holderDid: "did:key:z6MknqT2qWnVYxR2s4cV8nH2uC6wYtQ5jT8kH7aX9mP2zR1",
        holderPrivateJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: "11qYAY7Y8A8kS0P3J-bwFTHlL8E8fQf6c3n2pP7Q9Q0",
          d: "nWGxne_9Wm7nP8aW8Q6BYfQhRj6iB-8Sn4Xc6D4J3vU",
        },
        credentialIds: ["tenant_123:assertion_456", "tenant_123:assertion_456"],
      });
    }).toThrowError();
  });

  it("accepts a valid presentation verify payload", () => {
    const request = parsePresentationVerifyRequest({
      presentation: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiablePresentation"],
        holder: "did:key:z6MknqT2qWnVYxR2s4cV8nH2uC6wYtQ5jT8kH7aX9mP2zR1",
        verifiableCredential: [],
      },
    });

    expect(request.presentation.type).toEqual(["VerifiablePresentation"]);
  });
});

describe("assertion lifecycle parsers", () => {
  it("accepts valid assertion lifecycle transition payloads", () => {
    const payload = parseAssertionLifecycleTransitionRequest({
      toState: "suspended",
      reasonCode: "administrative_hold",
      reason: "Pending registrar review",
      transitionSource: "manual",
      transitionedAt: "2026-02-12T23:00:00.000Z",
    });

    expect(payload.toState).toBe("suspended");
    expect(payload.reasonCode).toBe("administrative_hold");
    expect(payload.transitionSource).toBe("manual");
  });

  it("defaults transitionSource to manual when omitted", () => {
    const payload = parseAssertionLifecycleTransitionRequest({
      toState: "expired",
      reasonCode: "credential_expired",
    });

    expect(payload.transitionSource).toBe("manual");
  });

  it("rejects invalid assertion lifecycle state values", () => {
    expect(() => {
      parseAssertionLifecycleTransitionRequest({
        toState: "paused",
        reasonCode: "other",
      });
    }).toThrowError();
  });

  it("parses assertion path params", () => {
    const pathParams = parseAssertionPathParams({
      tenantId: "tenant_123",
      assertionId: "tenant_123:assertion_456",
    });

    expect(pathParams.tenantId).toBe("tenant_123");
    expect(pathParams.assertionId).toBe("tenant_123:assertion_456");
  });
});

describe("learner-record parsers", () => {
  it("accepts a valid issuer-verified learner-record entry payload", () => {
    const payload = parseCreateLearnerRecordEntryRequest({
      learnerProfileId: "lpr_123",
      trustLevel: "issuer_verified",
      recordType: "course",
      title: "Intro to Cybersecurity",
      description: "Completed with distinction.",
      status: "active",
      provenance: {
        issuerName: "CredTrail University",
        sourceSystem: "credtrail_admin",
        issuedAt: "2026-03-24T15:00:00.000Z",
        evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
      },
      details: {
        grade: "A",
      },
    });

    expect(payload.trustLevel).toBe("issuer_verified");
    expect(payload.recordType).toBe("course");
    expect(payload.provenance.evidenceLinks).toHaveLength(1);
  });

  it("rejects ambiguous supplemental trust and revoked-state payloads without provenance", () => {
    expect(() => {
      parseCreateLearnerRecordEntryRequest({
        learnerProfileId: "lpr_123",
        trustLevel: "issuer_verified",
        recordType: "supplemental_artifact",
        title: "Supplemental portfolio",
        provenance: {
          issuerName: "Learner upload",
          sourceSystem: "learner_self_reported",
          issuedAt: "2026-03-24T15:00:00.000Z",
          evidenceLinks: ["https://portfolio.example.edu/work"],
        },
      });
    }).toThrowError();

    expect(() => {
      parseCreateLearnerRecordEntryRequest({
        learnerProfileId: "lpr_123",
        trustLevel: "learner_supplemental",
        recordType: "experience",
        title: "Community leadership",
        status: "revoked",
        provenance: {
          issuerName: "Learner self report",
          sourceSystem: "learner_self_reported",
          issuedAt: "2026-03-24T15:00:00.000Z",
          evidenceLinks: [],
        },
      });
    }).toThrowError();
  });

  it("parses learner-record path params, filters, and patch payloads", () => {
    expect(
      parseLearnerRecordEntryPathParams({
        tenantId: "tenant_123",
        entryId: "lre_123",
      }),
    ).toEqual({
      tenantId: "tenant_123",
      entryId: "lre_123",
    });

    expect(
      parseLearnerRecordEntryListQuery({
        learnerProfileId: "lpr_123",
        trustLevel: "issuer_verified",
        status: "active",
      }),
    ).toEqual({
      learnerProfileId: "lpr_123",
      trustLevel: "issuer_verified",
      status: "active",
    });

    expect(
      parsePatchLearnerRecordEntryRequest({
        description: "Completed with distinction and capstone presentation.",
        status: "revoked",
        provenance: {
          issuerName: "CredTrail University",
          sourceSystem: "credtrail_admin",
          issuedAt: "2026-03-24T15:00:00.000Z",
          revokedAt: "2026-03-25T15:00:00.000Z",
          evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
        },
      }),
    ).toEqual({
      description: "Completed with distinction and capstone presentation.",
      status: "revoked",
      provenance: {
        issuerName: "CredTrail University",
        sourceSystem: "credtrail_admin",
        issuedAt: "2026-03-24T15:00:00.000Z",
        revokedAt: "2026-03-25T15:00:00.000Z",
        evidenceLinks: ["https://credtrail.example.edu/evidence/intro-cybersecurity/project"],
      },
    });
  });

  it("parses learner-record export path params and export profiles", () => {
    expect(
      parseLearnerRecordExportPathParams({
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
      }),
    ).toEqual({
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
    });

    expect(
      parseLearnerRecordExportQuery({
        profile: "clr_alignment_json",
      }),
    ).toEqual({
      profile: "clr_alignment_json",
    });

    expect(parseLearnerRecordStandardsMappingQuery({})).toEqual({
      profile: "clr_alignment_json",
    });
  });

  it("rejects invalid learner-record export profile values", () => {
    expect(() => {
      parseLearnerRecordExportQuery({
        profile: "full_clr_conformance",
      });
    }).toThrowError();

    expect(() => {
      parseLearnerRecordStandardsMappingQuery({
        profile: "opaque_vendor_dump",
      });
    }).toThrowError();
  });

  it("parses bounded admin learner-record review queries", () => {
    expect(
      parseAdminLearnerRecordReviewQuery({
        learnerProfileId: "lpr_123",
      }),
    ).toEqual({
      learnerProfileId: "lpr_123",
    });

    expect(
      parseAdminLearnerRecordReviewQuery({
        email: "learner@example.edu",
      }),
    ).toEqual({
      email: "learner@example.edu",
    });

    expect(parseAdminLearnerRecordReviewQuery({})).toEqual({});
  });

  it("rejects ambiguous admin learner-record review queries", () => {
    expect(() => {
      parseAdminLearnerRecordReviewQuery({
        learnerProfileId: "lpr_123",
        email: "learner@example.edu",
      });
    }).toThrowError();

    expect(() => {
      parseAdminLearnerRecordReviewQuery({
        email: "not-an-email",
      });
    }).toThrowError();
  });
});

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
    }).toThrowError();
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
    }).toThrowError();
  });
});

describe("badge issuance rule parsers", () => {
  it("accepts valid create/version/evaluate payloads", () => {
    const createRequest = parseCreateBadgeIssuanceRuleRequest({
      name: "CS101 Excellence Rule",
      description: "Award badge for high performers",
      badgeTemplateId: "badge_template_cs101",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          all: [
            {
              type: "course_completion",
              courseId: "course_101",
              requireCompleted: true,
            },
            {
              type: "grade_threshold",
              courseId: "course_101",
              scoreField: "final_score",
              minScore: 80,
            },
            {
              any: [
                {
                  type: "assignment_submission",
                  courseId: "course_101",
                  assignmentId: "assignment_1",
                  minScore: 75,
                },
                {
                  type: "prerequisite_badge",
                  badgeTemplateId: "badge_template_foundations",
                },
              ],
            },
            {
              type: "survey_completion",
              source: "qualtrics",
              surveyId: "exit_survey",
            },
            {
              type: "custom_field",
              fieldName: "programStanding",
              operator: "equals",
              expectedValue: "eligible",
            },
          ],
        },
      },
      approvalChain: [
        {
          requiredRole: "issuer",
          label: "Department approval",
        },
        {
          requiredRole: "admin",
          label: "Registrar approval",
        },
      ],
      changeSummary: "Initial draft",
    });
    const versionRequest = parseCreateBadgeIssuanceRuleVersionRequest({
      definition: {
        conditions: {
          type: "time_window",
          notBefore: "2026-01-01T00:00:00.000Z",
        },
      },
      approvalChain: [
        {
          requiredRole: "admin",
        },
      ],
      changeSummary: "Limit issuance to spring term",
    });
    const updateDraftRequest = parseUpdateBadgeIssuanceRuleDraftRequest({
      name: "CS101 Excellence Rule Revised",
      description: "",
      badgeTemplateId: "badge_template_cs101",
      lmsConnectionId: "lms_123",
      definition: createRequest.definition,
      approvalChain: [
        {
          requiredRole: "admin",
          label: "Registrar approval",
        },
      ],
      changeSummary: "Tighten course completion rule",
    });
    const decisionRequest = parseDecideBadgeIssuanceRuleVersionRequest({
      decision: "approved",
      comment: "Meets institutional governance requirements",
    });
    const evaluateRequest = parseEvaluateBadgeIssuanceRuleRequest({
      learnerId: "learner_123",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      dryRun: true,
      facts: {
        nowIso: "2026-02-17T00:00:00.000Z",
        grades: [
          {
            courseId: "course_101",
            learnerId: "learner_123",
            finalScore: 92,
          },
        ],
        surveyCompletions: [
          {
            surveyId: "exit_survey",
            learnerId: "learner_123",
            source: "qualtrics",
            completed: true,
          },
        ],
        customFields: [
          {
            learnerId: "learner_123",
            fieldName: "programStanding",
            value: "eligible",
          },
        ],
      },
    });
    const previewEvaluateRequest = parsePreviewEvaluateBadgeIssuanceRuleRequest({
      definition: {
        conditions: {
          all: [
            {
              type: "course_completion",
              courseId: "course_101",
            },
            {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          ],
        },
      },
      lmsConnectionId: "lms_123",
      learnerId: "learner_123",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      facts: {
        completions: [
          {
            courseId: "course_101",
            learnerId: "learner_123",
            completed: true,
          },
        ],
        grades: [
          {
            courseId: "course_101",
            learnerId: "learner_123",
            finalScore: 88,
          },
        ],
      },
    });

    expect(createRequest.lmsProviderKind).toBe("canvas");
    expect(createRequest.approvalChain?.[0]?.requiredRole).toBe("issuer");
    expect(JSON.stringify(createRequest.definition.conditions)).toContain("survey_completion");
    expect(JSON.stringify(createRequest.definition.conditions)).toContain("custom_field");
    expect(updateDraftRequest.name).toBe("CS101 Excellence Rule Revised");
    expect(updateDraftRequest.description).toBe("");
    expect(versionRequest.changeSummary).toContain("spring");
    expect(versionRequest.approvalChain).toHaveLength(1);
    expect(decisionRequest.decision).toBe("approved");
    expect(decisionRequest.comment).toContain("governance");
    expect(evaluateRequest.dryRun).toBe(true);
    expect(previewEvaluateRequest.definition.conditions).toHaveProperty("all");
    expect(JSON.stringify(createRequest.definition.conditions)).toContain(
      '"minCompletionPercent":100',
    );
    expect(JSON.stringify(createRequest.definition.conditions)).not.toContain("requireCompleted");
  });

  it("normalizes legacy course completion booleans to completion percentages", () => {
    const requireCompleteDefinition = parseCreateBadgeIssuanceRuleRequest({
      name: "Legacy complete rule",
      badgeTemplateId: "badge_template_cs101",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          type: "course_completion",
          courseId: "course_101",
          requireCompleted: true,
        },
      },
    }).definition;
    const requireStartedDefinition = parseCreateBadgeIssuanceRuleRequest({
      name: "Legacy started rule",
      badgeTemplateId: "badge_template_cs101",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          type: "course_completion",
          courseId: "course_101",
          requireCompleted: false,
        },
      },
    }).definition;

    expect(requireCompleteDefinition.conditions).toEqual({
      type: "course_completion",
      courseId: "course_101",
      minCompletionPercent: 100,
    });
    expect(requireStartedDefinition.conditions).toEqual({
      type: "course_completion",
      courseId: "course_101",
      minCompletionPercent: 0,
    });
  });

  it("rejects preview evaluation payloads without an LMS connection", () => {
    expect(() => {
      parsePreviewEvaluateBadgeIssuanceRuleRequest({
        definition: {
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
            minScore: 80,
          },
        },
        learnerId: "learner_123",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
      });
    }).toThrowError();
  });

  it("parses rule and rule-version path params", () => {
    const rulePathParams = parseBadgeIssuanceRulePathParams({
      tenantId: "tenant_123",
      ruleId: "brl_123",
    });
    const versionPathParams = parseBadgeIssuanceRuleVersionPathParams({
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
    });

    expect(rulePathParams.ruleId).toBe("brl_123");
    expect(versionPathParams.versionId).toBe("brv_123");
  });

  it("parses badge rule diff and audit-log query parameters", () => {
    const diffQuery = parseBadgeIssuanceRuleVersionDiffQuery({
      baseVersionId: "brv_122",
    });
    const auditLogQuery = parseBadgeIssuanceRuleAuditLogQuery({
      limit: "150",
    });
    const reviewQueueQuery = parseBadgeIssuanceRuleReviewQueueQuery({
      status: "resolved",
      limit: "25",
    });

    expect(diffQuery.baseVersionId).toBe("brv_122");
    expect(auditLogQuery.limit).toBe(150);
    expect(reviewQueueQuery.status).toBe("resolved");
    expect(reviewQueueQuery.limit).toBe(25);
  });

  it("accepts reusable-list rule conditions and simulation payloads", () => {
    const createRequest = parseCreateBadgeIssuanceRuleRequest({
      name: "Program path rule",
      badgeTemplateId: "badge_template_program",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          all: [
            {
              type: "program_completion",
              courseListId: "brvl_courses",
              minimumCompleted: 3,
            },
            {
              type: "prerequisite_badge",
              badgeTemplateListId: "brvl_badges",
            },
          ],
        },
        options: {
          reviewOnMissingFacts: true,
        },
      },
    });
    const valueListRequest = parseCreateBadgeIssuanceRuleValueListRequest({
      label: "Core CS sequence",
      kind: "course_ids",
      values: ["course_101", "course_102", "course_103"],
    });
    const simulationRequest = parsePreviewSimulateBadgeIssuanceRuleRequest({
      badgeTemplateId: "badge_template_program",
      sampleLimit: 20,
      definition: createRequest.definition,
    });
    const resolveReviewRequest = parseResolveBadgeIssuanceRuleReviewRequest({
      decision: "issue",
      comment: "Registrar review approved issuance.",
    });

    expect(createRequest.definition.options?.reviewOnMissingFacts).toBe(true);
    expect(valueListRequest.kind).toBe("course_ids");
    expect(simulationRequest.sampleLimit).toBe(20);
    expect(resolveReviewRequest.decision).toBe("issue");
  });

  it("rejects grade threshold conditions without a score boundary", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleRequest({
        name: "Invalid",
        badgeTemplateId: "badge_template_cs101",
        lmsConnectionId: "lms_123",
        lmsProviderKind: "canvas",
        definition: {
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
          },
        },
      });
    }).toThrowError();
  });

  it("rejects invalid time window condition payloads", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleVersionRequest({
        definition: {
          conditions: {
            type: "time_window",
          },
        },
      });
    }).toThrowError();
  });

  it("rejects rule conditions that provide both direct IDs and reusable list IDs", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleRequest({
        name: "Invalid list combination",
        badgeTemplateId: "badge_template_cs101",
        lmsConnectionId: "lms_123",
        lmsProviderKind: "canvas",
        definition: {
          conditions: {
            type: "course_completion",
            courseId: "course_101",
            courseListId: "brvl_courses",
          },
        },
      });
    }).toThrowError();
  });
});

describe("parseSignCredentialRequest", () => {
  it("accepts a valid did:web signing request", () => {
    const payload = parseSignCredentialRequest({
      did: "did:web:issuers.credtrail.org:tenant-a",
      credential: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
      },
    });

    expect(payload.did).toBe("did:web:issuers.credtrail.org:tenant-a");
  });

  it("accepts DataIntegrity signing requests with the eddsa-rdfc-2022 cryptosuite", () => {
    const payload = parseSignCredentialRequest({
      did: "did:web:issuers.credtrail.org:tenant-a",
      credential: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
      },
      proofType: "DataIntegrityProof",
      cryptosuite: "eddsa-rdfc-2022",
    });

    expect(payload.proofType).toBe("DataIntegrityProof");
    expect(payload.cryptosuite).toBe("eddsa-rdfc-2022");
  });

  it("rejects non did:web identifiers", () => {
    let thrownError: unknown = null;

    try {
      parseSignCredentialRequest({
        did: "did:key:z6Mk...",
        credential: {
          id: "urn:vc:1",
        },
      });
    } catch (error) {
      thrownError = error;
    }

    expect(isValidationParseError(thrownError)).toBe(true);
  });

  it("accepts DataIntegrity signing requests without an explicit cryptosuite", () => {
    const payload = parseSignCredentialRequest({
      did: "did:web:issuers.credtrail.org:tenant-a",
      credential: {
        id: "urn:vc:1",
      },
      proofType: "DataIntegrityProof",
    });

    expect(payload.proofType).toBe("DataIntegrityProof");
    expect(payload.cryptosuite).toBeUndefined();
  });

  it("rejects legacy proof types", () => {
    expect(() => {
      parseSignCredentialRequest({
        did: "did:web:issuers.credtrail.org:tenant-a",
        credential: {
          id: "urn:vc:1",
        },
        proofType: "Ed25519Signature2020",
      });
    }).toThrowError();
  });

  it("rejects cryptosuite when proofType is not DataIntegrityProof", () => {
    expect(() => {
      parseSignCredentialRequest({
        did: "did:web:issuers.credtrail.org:tenant-a",
        credential: {
          id: "urn:vc:1",
        },
        cryptosuite: "eddsa-rdfc-2022",
      });
    }).toThrowError();
  });
});

describe("parseTenantSigningRegistry", () => {
  it("accepts tenant registry entries", () => {
    const registry = parseTenantSigningRegistry({
      "did:web:issuers.credtrail.org:tenant-a": {
        tenantId: "tenant_a",
        keyId: "key-1",
        publicJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: "11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE",
        },
        privateJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: "11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE",
          d: "nWGxne_9WmZ8QfQwJdK2fNn_Ef3FQk7xU4mS1sM3x2U",
        },
      },
    });

    expect(Object.keys(registry)).toHaveLength(1);
  });

  it("accepts P-256 tenant registry entries", () => {
    const registry = parseTenantSigningRegistry({
      "did:web:issuers.credtrail.org:tenant-b": {
        tenantId: "tenant_b",
        keyId: "key-p256",
        publicJwk: {
          kty: "EC",
          crv: "P-256",
          x: "X".repeat(43),
          y: "Y".repeat(43),
        },
        privateJwk: {
          kty: "EC",
          crv: "P-256",
          x: "X".repeat(43),
          y: "Y".repeat(43),
          d: "D".repeat(43),
        },
      },
    });

    expect(Object.keys(registry)).toHaveLength(1);
  });

  it("rejects tenant registry entries with mismatched key types", () => {
    expect(() => {
      parseTenantSigningRegistry({
        "did:web:issuers.credtrail.org:tenant-c": {
          tenantId: "tenant_c",
          keyId: "key-mismatch",
          publicJwk: {
            kty: "OKP",
            crv: "Ed25519",
            x: "11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE",
          },
          privateJwk: {
            kty: "EC",
            crv: "P-256",
            x: "X".repeat(43),
            y: "Y".repeat(43),
            d: "D".repeat(43),
          },
        },
      });
    }).toThrowError();
  });
});

describe("badge template parsers", () => {
  it("accepts a valid create request", () => {
    const payload = parseCreateBadgeTemplateRequest({
      slug: "intro-to-ts",
      title: "Intro to TypeScript",
      description: "Awarded for completing TypeScript basics.",
      criteriaUri: "https://example.edu/badges/intro-to-ts/criteria",
      imageUri: "https://cdn.example.edu/badges/intro-to-ts.png",
    });

    expect(payload.slug).toBe("intro-to-ts");
  });

  it("rejects invalid slugs", () => {
    expect(() => {
      parseCreateBadgeTemplateRequest({
        slug: "Intro To TS",
        title: "Intro to TypeScript",
      });
    }).toThrowError();
  });

  it("accepts update requests with nullable optional fields", () => {
    const payload = parseUpdateBadgeTemplateRequest({
      description: null,
      imageUri: null,
    });

    expect(payload.description).toBeNull();
  });

  it("rejects empty update payloads", () => {
    expect(() => {
      parseUpdateBadgeTemplateRequest({});
    }).toThrowError();
  });

  it("parses TrustEd credential metadata", () => {
    const payload = parseTrustEdCredentialMetadata(completeTrustEdCredentialMetadataInput);

    expect(payload.skills[0]?.name).toBe("Applied data analysis");
    expect(payload.results[0]?.resultDate).toBe("2026-05-18");
  });

  it("rejects invalid TrustEd credential metadata URLs and dates", () => {
    expect(() => {
      parseTrustEdCredentialMetadata({
        skills: [{ name: "Applied data analysis", identifierUri: "not a url", source: null }],
        frameworkAlignments: [],
        issuerAuthority: null,
        evidence: [],
        results: [],
        criteria: null,
        assessments: [],
        achievementType: "Project",
        rubrics: [],
        duration: null,
        credits: null,
        endorsements: [],
      });
    }).toThrowError();

    expect(() => {
      parseTrustEdCredentialMetadata({
        skills: [],
        frameworkAlignments: [],
        issuerAuthority: null,
        evidence: [],
        results: [{ value: "Pass", resultDate: "May 18, 2026" }],
        criteria: null,
        assessments: [],
        achievementType: "Project",
        rubrics: [],
        duration: null,
        credits: null,
        endorsements: [],
      });
    }).toThrowError();
  });

  it("parses path params for badge template routes", () => {
    const params = parseBadgeTemplatePathParams({
      tenantId: "tenant_123",
      badgeTemplateId: "tmpl_456",
    });

    expect(params.badgeTemplateId).toBe("tmpl_456");
  });

  it("parses badge template image generation requests and path params", () => {
    const request = parseGenerateBadgeTemplateImageRequest({
      stylePreset: "technical",
      promptNotes: "Use circuit lines.",
      accentColor: "blue",
    });
    const generationParams = parseBadgeTemplateImageGenerationPathParams({
      tenantId: "tenant_123",
      badgeTemplateId: "tmpl_456",
      generationId: "btig_789",
    });
    const revisionParams = parseBadgeTemplateImageRevisionPathParams({
      tenantId: "tenant_123",
      badgeTemplateId: "tmpl_456",
      revisionId: "btir_789",
    });

    expect(request.stylePreset).toBe("technical");
    expect(generationParams.generationId).toBe("btig_789");
    expect(revisionParams.revisionId).toBe("btir_789");
  });

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
    }).toThrowError();
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

  it("defaults includeArchived to false in list query", () => {
    const query = parseBadgeTemplateListQuery({});

    expect(query.includeArchived).toBe(false);
  });

  it("accepts create payloads that include owner org unit", () => {
    const payload = parseCreateBadgeTemplateRequest({
      slug: "intro-to-ts",
      title: "Intro to TypeScript",
      ownerOrgUnitId: "tenant_123:org:institution",
    });

    expect(payload.ownerOrgUnitId).toBe("tenant_123:org:institution");
  });

  it("parses tenant org unit list query defaults and booleans", () => {
    const defaultQuery = parseTenantOrgUnitListQuery({});
    const explicitQuery = parseTenantOrgUnitListQuery({ includeInactive: "true" });

    expect(defaultQuery.includeInactive).toBe(false);
    expect(explicitQuery.includeInactive).toBe(true);
  });

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
    }).toThrowError();
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
    }).toThrowError();

    expect(() => {
      parseCreateTenantMemberRequest({
        email: "colleague@example.edu",
        role: "superadmin",
      });
    }).toThrowError();

    expect(() => {
      parseUpdateTenantMemberRoleRequest({
        role: "superadmin",
      });
    }).toThrowError();
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

  it("parses delegated authority grant list query defaults and booleans", () => {
    const defaultQuery = parseDelegatedIssuingAuthorityGrantListQuery({});
    const explicitQuery = parseDelegatedIssuingAuthorityGrantListQuery({
      includeRevoked: "true",
      includeExpired: "true",
    });

    expect(defaultQuery.includeRevoked).toBe(false);
    expect(defaultQuery.includeExpired).toBe(false);
    expect(explicitQuery.includeRevoked).toBe(true);
    expect(explicitQuery.includeExpired).toBe(true);
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
    }).toThrowError();

    expect(() => {
      parseCreateDelegatedIssuingAuthorityGrantRequest({
        orgUnitId: "tenant_123:org:department-math",
        allowedActions: ["issue_badge"],
        startsAt: "2026-03-13T12:00:00.000Z",
        endsAt: "2026-02-13T12:00:00.000Z",
      });
    }).toThrowError();
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
    }).toThrowError();
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
    }).toThrowError();

    expect(() => {
      parseTenantAssertionListQuery({
        limit: "0",
      });
    }).toThrowError();
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
    }).toThrowError();

    expect(() => {
      parseTenantAssertionLedgerExportQuery({
        state: "pending_review",
      });
    }).toThrowError();
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
    }).toThrowError();
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
    }).toThrowError();
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
    }).toThrowError();

    expect(() => {
      parseUpsertTenantAuthProviderRequest({
        protocol: "saml",
        label: "Campus SAML",
        configJson: '["array-not-object"]',
      });
    }).toThrowError();
  });

  it("parses tenant SAML SSO configuration payload", () => {
    const payload = parseUpsertTenantSsoSamlConfigurationRequest({
      idpEntityId: "https://idp.example.edu/entity",
      ssoLoginUrl: "https://idp.example.edu/sso/login",
      idpCertificatePem: "-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----",
      idpMetadataUrl: "https://idp.example.edu/metadata",
      spEntityId: "https://credtrail.example.edu/saml/sp",
      assertionConsumerServiceUrl: "https://credtrail.example.edu/saml/acs",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      enforced: true,
    });

    expect(payload.enforced).toBe(true);
    expect(payload.spEntityId).toContain("/saml/sp");
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
